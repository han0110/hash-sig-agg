use crate::{
    gadget::{not, select},
    poseidon2::{
        F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::{
            Bus,
            chain::{
                column::{ChainCols, NUM_CHAIN_COLS},
                poseidon2::{PARTIAL_ROUNDS, WIDTH},
            },
        },
        hash_sig::{CHUNK_SIZE, NUM_CHUNKS, TARGET_SUM},
    },
};
use core::{
    borrow::Borrow,
    iter::{self, zip},
};
use openvm_stark_backend::{
    air_builders::sub::SubAirBuilder,
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_poseidon2_air::{Poseidon2Air, num_cols};
use p3_poseidon2_util::horizon::baby_bear::constant::RC16;

pub struct ChainAir(
    Poseidon2Air<
        F,
        GenericPoseidon2LinearLayersHorizon<WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
);

impl Default for ChainAir {
    fn default() -> Self {
        Self(Poseidon2Air::new(RC16.into()))
    }
}

impl BaseAir<F> for ChainAir {
    fn width(&self) -> usize {
        NUM_CHAIN_COLS
    }
}

impl PartitionedBaseAir<F> for ChainAir {}

impl BaseAirWithPublicValues<F> for ChainAir {}

impl<AB> Air<AB> for ChainAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
    AB::Expr: FieldAlgebra<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        self.0.eval(&mut SubAirBuilder::<
            _,
            Poseidon2Air<
                F,
                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
            _,
        >::new(
            builder,
            0..num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(),
        ));

        // TODO:
        // 1. Make sure `encoded_tweak_chain` is correct.

        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &ChainCols<AB::Var> = (*local).borrow();
        let next: &ChainCols<AB::Var> = (*next).borrow();

        // When every rows
        eval_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(*local.is_active);
            builder.assert_zero(local.sig_idx);
            eval_sig_first_row(&mut builder, local);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_transition(&mut builder, local, next);
            eval_sig_transition(&mut builder, local, next);
            eval_sig_last_row(&mut builder, local, next);
            eval_chain_transition(&mut builder, local, next);
            eval_chain_last_row(&mut builder, local, next);
        }

        // Interaction
        receive_parameter(builder, local);
        receive_chain(builder, local);
        send_merkle_tree(builder, local);
    }
}

#[inline]
fn eval_every_row<AB>(builder: &mut AB, cols: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    cols.is_active.eval_every_row(builder);
    cols.is_last_sig_row.eval(
        builder,
        cols.sig_step,
        F::from_canonical_u16(TARGET_SUM - 1),
    );
    cols.chain_idx_is_zero.eval(builder, cols.chain_idx);
    cols.chain_idx_diff_bits.map(|bit| builder.assert_bool(bit));
    cols.chain_step_bits.map(|bit| builder.assert_bool(bit));
    builder.assert_bool(cols.is_receiving_chain);
    builder
        .when(*cols.is_active)
        .assert_one(cols.chain_idx_diff_inv * cols.chain_idx_diff::<AB>());
}

#[inline]
fn eval_transition<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    local.is_active.eval_transition(builder, &next.is_active);

    builder.assert_eq(
        next.sig_idx,
        select(
            local.is_last_sig_row.output.into(),
            local.sig_idx.into(),
            select(
                (*next.is_active).into(),
                AB::Expr::ZERO,
                local.sig_idx + AB::Expr::ONE,
            ),
        ),
    );
}

#[inline]
fn eval_sig_first_row<AB>(builder: &mut AB, cols: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    builder.assert_zero(cols.sig_step);
    builder.assert_eq(
        cols.sum,
        cols.chain_idx * F::from_canonical_usize((1 << CHUNK_SIZE) - 1) + cols.chain_step::<AB>(),
    );
}

#[inline]
fn eval_sig_transition<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_sig_transition::<AB>());

    builder.assert_eq(next.sig_step, local.sig_step.into() + AB::Expr::ONE);
    zip(next.parameter(), local.parameter()).for_each(|(a, b)| builder.assert_eq(a, b));
}

#[inline]
fn eval_sig_last_row<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_last_sig_row.output);

    builder.assert_eq(local.sum, F::from_canonical_u16(TARGET_SUM));
    eval_sig_first_row(&mut builder, next);
}

#[inline]
fn eval_chain_transition<AB>(
    builder: &mut AB,
    local: &ChainCols<AB::Var>,
    next: &ChainCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder =
        builder.when(local.is_sig_transition::<AB>() * not(local.is_last_chain_step::<AB>()));

    builder.assert_eq(next.sum, local.sum);
    builder.assert_eq(next.chain_idx, local.chain_idx);
    builder.assert_eq(
        next.chain_step::<AB>(),
        local.chain_step::<AB>() + AB::Expr::ONE,
    );
    zip(next.chain_input(), local.compression_output::<AB>())
        .for_each(|(a, b)| builder.assert_eq(a, b));
}

#[inline]
fn eval_chain_last_row<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    builder.when(local.is_last_chain_step::<AB>()).assert_eq(
        select(
            local.is_last_sig_row.output.into(),
            next.chain_idx.into(),
            AB::Expr::from_canonical_usize(NUM_CHUNKS),
        ),
        local.chain_idx + local.chain_idx_diff::<AB>(),
    );
    builder
        .when(local.is_last_chain_step::<AB>() - local.is_last_sig_row.output.into())
        .assert_eq(
            next.sum,
            local.sum
                + (local.chain_idx_diff::<AB>() - AB::Expr::ONE)
                    * F::from_canonical_usize((1 << CHUNK_SIZE) - 1)
                + next.chain_step::<AB>(),
        );
}

#[inline]
fn receive_parameter<AB>(builder: &mut AB, local: &ChainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::Parameter as usize,
        iter::empty()
            .chain([local.sig_idx])
            .chain(local.parameter()),
        (*local.is_active).into() * local.is_last_sig_row.output.into(),
    );
}

#[inline]
fn receive_chain<AB>(builder: &mut AB, local: &ChainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::Chain as usize,
        [
            local.sig_idx.into(),
            local.chain_idx.into(),
            local.chain_step::<AB>(),
        ],
        (*local.is_active).into() * local.is_receiving_chain.into(),
    );
}

#[inline]
fn send_merkle_tree<AB>(builder: &mut AB, local: &ChainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        Bus::MerkleLeaf as usize,
        iter::empty()
            .chain([local.sig_idx.into(), local.chain_idx.into() + AB::Expr::ONE])
            .chain(local.compression_output::<AB>()),
        *local.is_active * local.is_last_chain_step::<AB>(),
    );
}
