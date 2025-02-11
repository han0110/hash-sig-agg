use crate::{
    gadget::not,
    poseidon2::{
        F,
        chip::{
            BUS_CHAIN, BUS_DECOMPOSITION, BUS_LIMB_RANGE_CHECK,
            decomposition::{
                F_MS_LIMB, LIMB_BITS, NUM_LIMBS, NUM_MSG_HASH_LIMBS,
                column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
            },
        },
        hash_sig::{CHUNK_SIZE, MSG_HASH_FE_LEN},
    },
};
use core::{
    borrow::Borrow,
    iter::{self, repeat, zip},
};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};

#[derive(Clone, Copy)]
pub struct DecompositionAir;

impl BaseAir<F> for DecompositionAir {
    fn width(&self) -> usize {
        NUM_DECOMPOSITION_COLS
    }
}

impl PartitionedBaseAir<F> for DecompositionAir {}

impl BaseAirWithPublicValues<F> for DecompositionAir {}

impl<AB> Air<AB> for DecompositionAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &DecompositionCols<AB::Var> = (*local).borrow();
        let next: &DecompositionCols<AB::Var> = (*next).borrow();

        // When every row
        eval_every_row(builder, local);
        eval_decomposition_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(local.inds[0]);
            eval_acc_first_row(&mut builder, local);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_transition(&mut builder, local, next);
            eval_acc_transition(&mut builder, local, next);
            eval_acc_last_row(&mut builder, local, next);
            eval_decomposition_transition(&mut builder, local, next);
        }

        // Interaction
        send_chain(builder, local);
        send_limb_range_check(builder, local);
        receive_decomposition(builder, local);
    }
}

#[inline]
fn eval_every_row<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    cols.inds.eval_every_row(builder);

    const { assert!(F_MS_LIMB == 0b1111000) };
    cols.value_ms_limb_bits
        .iter()
        .for_each(|cell| builder.assert_bool(*cell));
    builder.assert_eq(
        cols.value_ms_limb_auxs[0],
        cols.value_ms_limb_bits[6] * cols.value_ms_limb_bits[5] * cols.value_ms_limb_bits[4],
    );
    builder.assert_eq(
        cols.value_ms_limb_auxs[1],
        cols.value_ms_limb_bits[3]
            * not(cols.value_ms_limb_bits[2].into())
            * not(cols.value_ms_limb_bits[1].into()),
    );
    builder.assert_eq(
        cols.value_ms_limb_auxs[2],
        cols.value_ms_limb_auxs[0]
            * cols.value_ms_limb_auxs[1]
            * not(cols.value_ms_limb_bits[0].into()),
    );
    cols.value_limb_0_is_zero
        .eval(builder, cols.value_ls_limbs[0]);
    cols.value_limb_1_is_zero
        .eval(builder, cols.value_ls_limbs[1]);
    // MSL <= F_MS_LIMB
    builder
        .when(cols.value_ms_limb_auxs[0].into() * cols.value_ms_limb_bits[3].into())
        .assert_zero(
            cols.value_ms_limb_bits[0..3]
                .iter()
                .copied()
                .map(Into::into)
                .sum::<AB::Expr>(),
        );
    // When MSL == 31, second most significant limb should be 0.
    builder
        .when(cols.value_ms_limb_auxs[2].into())
        .assert_one(cols.value_limb_1_is_zero.output);
    // When MSL == 31 and second most significant limb == 0, LSL should be 0.
    builder
        .when(cols.value_ms_limb_auxs[2].into() * cols.value_limb_1_is_zero.output.into())
        .assert_one(cols.value_limb_0_is_zero.output);

    (0..MSG_HASH_FE_LEN).for_each(|idx| {
        builder.when(cols.inds[idx]).assert_eq(
            cols.values[MSG_HASH_FE_LEN - 1 - idx],
            cols.value_ls_limbs
                .iter()
                .copied()
                .map(Into::into)
                .chain([cols.value_ms_limb::<AB>()])
                .enumerate()
                .map(|(idx, limb)| limb * F::from_canonical_u32(1 << (idx * LIMB_BITS)))
                .sum::<AB::Expr>(),
        );
    });
}

#[inline]
fn eval_transition<AB>(
    builder: &mut AB,
    local: &DecompositionCols<AB::Var>,
    next: &DecompositionCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    local.inds.eval_transition(builder, &next.inds);
    builder
        .when(local.inds.is_transition::<AB>())
        .assert_eq(next.sig_idx, local.sig_idx);
    builder
        .when(local.inds.is_last_row_to_active::<AB>(&next.inds))
        .assert_eq(next.sig_idx, local.sig_idx + AB::Expr::ONE);
}

#[inline]
fn eval_acc_first_row<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    zip(
        cols.acc_limbs,
        cols.value_ls_limbs
            .iter()
            .copied()
            .map(Into::into)
            .chain([cols.value_ms_limb::<AB>()])
            .chain(repeat(AB::Expr::ZERO)),
    )
    .for_each(|(a, b)| builder.assert_eq(a, b))
}

#[inline]
fn eval_acc_transition<AB>(
    builder: &mut AB,
    local: &DecompositionCols<AB::Var>,
    next: &DecompositionCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_acc_transition::<AB>());

    let f_ms_limb = F::from_canonical_u32(F_MS_LIMB);
    let base = F::from_canonical_u32(1 << LIMB_BITS);
    (0..NUM_MSG_HASH_LIMBS).for_each(|i| {
        if i == 0 {
            builder.assert_eq(
                next.carries[0] * base + next.acc_limbs[0],
                local.acc_limbs[0] + next.value_ls_limbs[0],
            );
        } else if i < NUM_LIMBS - 1 {
            builder.assert_eq(
                next.carries[i] * base + next.acc_limbs[i],
                local.acc_limbs[i] + next.value_ls_limbs[i] + next.carries[i - 1],
            );
        } else if i < NUM_LIMBS {
            builder.assert_eq(
                next.carries[i] * base + next.acc_limbs[i],
                local.acc_limbs[i - (NUM_LIMBS - 1)].into() * f_ms_limb
                    + local.acc_limbs[i]
                    + next.value_ms_limb::<AB>()
                    + next.carries[i - 1],
            );
        } else if i < NUM_MSG_HASH_LIMBS - 1 {
            builder.assert_eq(
                next.carries[i] * base + next.acc_limbs[i],
                local.acc_limbs[i - (NUM_LIMBS - 1)].into() * f_ms_limb
                    + local.acc_limbs[i]
                    + next.carries[i - 1],
            );
        } else {
            builder.assert_eq(
                next.acc_limbs[i],
                local.acc_limbs[i - (NUM_LIMBS - 1)].into() * f_ms_limb
                    + local.acc_limbs[i]
                    + next.carries[i - 1],
            );
        }
    });
}

#[inline]
fn eval_acc_last_row<AB>(
    builder: &mut AB,
    local: &DecompositionCols<AB::Var>,
    next: &DecompositionCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_acc_last_row::<AB>());

    zip(next.acc_limbs, local.acc_limbs).for_each(|(a, b)| builder.assert_eq(a, b));
    eval_acc_first_row(&mut builder.when(next.is_acc_first_row::<AB>()), next);
}

#[inline]
fn eval_decomposition_every_row<AB>(builder: &mut AB, local: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_decomposition::<AB>());

    builder.assert_eq(
        zip(local.acc_limbs, local.decomposition_inds())
            .map(|(limb, ind)| limb * *ind)
            .sum::<AB::Expr>(),
        local
            .decomposition_bits
            .into_iter()
            .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + bit),
    );
}

#[inline]
fn eval_decomposition_transition<AB>(
    builder: &mut AB,
    local: &DecompositionCols<AB::Var>,
    next: &DecompositionCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_decomposition_transition::<AB>());

    zip(next.acc_limbs, local.acc_limbs).for_each(|(a, b)| builder.assert_eq(a, b));
}

#[inline]
fn send_limb_range_check<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    for limb in cols
        .value_ls_limbs
        .iter()
        .chain(&cols.acc_limbs)
        .chain(&cols.carries)
    {
        builder.push_send(BUS_LIMB_RANGE_CHECK, [*limb], cols.is_acc::<AB>());
    }
}

fn send_chain<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    let i_offset = cols
        .decomposition_inds()
        .iter()
        .enumerate()
        .map(|(idx, ind)| (*ind).into() * F::from_canonical_usize(6 * idx))
        .sum::<AB::Expr>();
    cols.decomposition_bits
        .chunks(CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let is_mid_of_chain = not(chunk.iter().copied().map(Into::into).product::<AB::Expr>());
            builder.push_send(
                BUS_CHAIN,
                [
                    cols.sig_idx.into(),
                    i_offset.clone() + AB::Expr::from_canonical_usize(chunk_idx),
                    chunk
                        .iter()
                        .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit),
                ],
                cols.is_decomposition::<AB>() * is_mid_of_chain,
            );
        });
}

#[inline]
fn receive_decomposition<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        BUS_DECOMPOSITION,
        iter::empty().chain([cols.sig_idx]).chain(cols.values),
        cols.is_acc_last_row::<AB>(),
    );
}
