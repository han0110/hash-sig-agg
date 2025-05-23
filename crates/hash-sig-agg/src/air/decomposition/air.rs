use crate::{
    air::{
        Bus,
        decomposition::{
            F_MS_LIMB, F_MS_LIMB_LEADING_ONES, F_MS_LIMB_TRAILING_ZEROS, LIMB_BITS, NUM_LIMBS,
            NUM_MSG_HASH_LIMBS,
            column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
        },
    },
    gadget::not,
    hash_sig::{F, MSG_HASH_FE_LEN, TARGET_SUM},
    util::zip,
};
use core::{borrow::Borrow, iter};
use hash_sig_verifier::instantiation::poseidon2::CHUNK_SIZE;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_air_ext::InteractionBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

#[derive(Clone, Copy, Debug, Default)]
pub struct DecompositionAir;

impl BaseAir<F> for DecompositionAir {
    fn width(&self) -> usize {
        NUM_DECOMPOSITION_COLS
    }
}

impl BaseAirWithPublicValues<F> for DecompositionAir {}

impl<AB> Air<AB> for DecompositionAir
where
    AB: InteractionBuilder<F = F>,
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        let local: &DecompositionCols<AB::Var> = (*local).borrow();
        let next: &DecompositionCols<AB::Var> = (*next).borrow();

        if !AB::ONLY_INTERACTION {
            eval_constriants(builder, local, next);
        }

        // Interaction
        send_chain(builder, local);
        send_range_check(builder, local);
        receive_decomposition(builder, local);
    }
}

#[inline]
fn eval_constriants<AB>(
    builder: &mut AB,
    local: &DecompositionCols<AB::Var>,
    next: &DecompositionCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    // When every row
    eval_every_row(builder, local);
    eval_decomposition_first_row(builder, local);
    eval_decomposition_every_row(builder, local);
    eval_decomposition_last_row(builder, local);

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
}

#[inline]
fn eval_every_row<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    cols.inds.eval_every_row(builder);

    cols.value_ms_limb_bits
        .iter()
        .for_each(|cell| builder.assert_bool(*cell));
    cols.is_ms_limb_max.eval(
        builder,
        cols.value_ms_limb_bits[F_MS_LIMB_TRAILING_ZEROS as usize..]
            .iter()
            .copied()
            .map_into()
            .sum::<AB::Expr>(),
        AB::F::from_u32(F_MS_LIMB_LEADING_ONES),
    );
    cols.value_limb_0_is_zero
        .eval(builder, cols.value_ls_limbs[0]);
    cols.value_limb_1_is_zero
        .eval(builder, cols.value_ls_limbs[1]);

    // MSL <= F_MS_LIMB
    if F_MS_LIMB_TRAILING_ZEROS != 0 {
        builder.when(cols.is_ms_limb_max.output.into()).assert_zero(
            cols.value_ms_limb_bits[..F_MS_LIMB_TRAILING_ZEROS as usize]
                .iter()
                .copied()
                .map_into()
                .sum::<AB::Expr>(),
        );
    }
    // When MSL == F_MS_LIMB, least significant limbs should be 0.
    for v in [
        cols.value_limb_0_is_zero.output,
        cols.value_limb_1_is_zero.output,
    ] {
        builder.when(cols.is_ms_limb_max.output).assert_one(v);
    }

    let value_composed = cols
        .value_ls_limbs
        .iter()
        .copied()
        .map_into()
        .chain([cols.value_ms_limb::<AB>()])
        .enumerate()
        .map(|(idx, limb)| limb * AB::F::from_u32(1 << (idx * LIMB_BITS)))
        .sum::<AB::Expr>();
    (0..MSG_HASH_FE_LEN).for_each(|idx| {
        builder.when(cols.inds[idx]).assert_eq(
            cols.values[MSG_HASH_FE_LEN - 1 - idx],
            value_composed.clone(),
        );
    });

    zip!(
        cols.decomposition_bits.chunks(CHUNK_SIZE),
        cols.is_send_chain
    )
    .for_each(|(chunk, is_send_chain)| {
        let is_chain_mid = not(chunk.iter().copied().map_into().product::<AB::Expr>());
        builder.assert_eq(is_send_chain, cols.is_decomposition::<AB>() * is_chain_mid);
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
    zip!(
        cols.acc_limbs.into_iter(),
        cols.value_ls_limbs
            .iter()
            .copied()
            .map_into()
            .chain([cols.value_ms_limb::<AB>()])
            .chain([AB::Expr::ZERO; NUM_MSG_HASH_LIMBS - NUM_LIMBS]),
    )
    .for_each(|(a, b)| builder.assert_eq(a, b));
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

    let f_ms_limb = AB::F::from_u32(F_MS_LIMB);
    let base = AB::F::from_u32(1 << LIMB_BITS);
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

    zip!(next.acc_limbs, local.acc_limbs).for_each(|(a, b)| builder.assert_eq(a, b));
    eval_acc_first_row(&mut builder.when(next.is_acc_first_row::<AB>()), next);
}

#[inline]
fn eval_decomposition_every_row<AB>(builder: &mut AB, local: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_decomposition::<AB>());

    builder.assert_eq(
        zip!(local.acc_limbs, local.decomposition_inds())
            .map(|(limb, ind)| limb * *ind)
            .sum::<AB::Expr>(),
        local
            .decomposition_bits
            .into_iter()
            .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + bit),
    );
}

#[inline]
fn eval_decomposition_first_row<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(cols.is_first_decomposition_row::<AB>());

    builder.assert_eq(
        cols.sum,
        cols.decomposed_chunks::<AB>().into_iter().sum::<AB::Expr>(),
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

    zip!(next.acc_limbs, local.acc_limbs).for_each(|(a, b)| builder.assert_eq(a, b));
    builder.assert_eq(
        next.sum,
        local.sum + next.decomposed_chunks::<AB>().into_iter().sum::<AB::Expr>(),
    );
}

#[inline]
fn eval_decomposition_last_row<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(cols.is_last_decomposition_row::<AB>());

    builder.assert_eq(cols.sum, AB::Expr::from(AB::F::from_u16(TARGET_SUM)));
}

fn send_chain<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    let i_offset = cols
        .decomposition_inds()
        .iter()
        .enumerate()
        .map(|(idx, ind)| (*ind).into() * AB::F::from_usize((LIMB_BITS / CHUNK_SIZE) * idx))
        .sum::<AB::Expr>();
    zip!(
        cols.decomposition_bits.chunks(CHUNK_SIZE),
        cols.is_send_chain
    )
    .enumerate()
    .for_each(|(chunk_idx, (chunk, is_send_chain))| {
        let chunk = chunk.iter().rev().copied().map_into();
        builder.push_send(
            Bus::Chain as usize,
            [
                cols.sig_idx.into(),
                i_offset.clone() + F::from_usize(chunk_idx),
                chunk.reduce(|acc, bit| acc.double() + bit).unwrap(),
            ],
            is_send_chain,
        );
    });
}

#[inline]
fn send_range_check<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    for limb in cols
        .value_ls_limbs
        .iter()
        .chain(&cols.acc_limbs)
        .chain(&cols.carries)
    {
        builder.push_send(Bus::RangeCheck as usize, [*limb], cols.is_acc::<AB>());
    }
}

#[inline]
fn receive_decomposition<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::Decomposition as usize,
        iter::once(cols.sig_idx).chain(cols.values),
        cols.is_acc_last_row::<AB>(),
    );
}
