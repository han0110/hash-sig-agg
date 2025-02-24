use crate::{
    gadget::{not, select},
    poseidon2::{
        chip::{
            chain::{
                column::{ChainCols, NUM_CHAIN_COLS},
                poseidon2::{PARTIAL_ROUNDS, WIDTH},
            },
            Bus,
        },
        Poseidon2LinearLayers, F, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE, SBOX_REGISTERS,
    },
    util::zip,
};
use core::{borrow::Borrow, iter};
use itertools::Itertools;
use openvm_stark_backend::{
    air_builders::sub::SubAirBuilder,
    interaction::InteractionBuilder,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use p3_poseidon2_air::{num_cols, Poseidon2Air};

/// Alias for `Poseidon2Air` specialized with chain-related parameters.
type Poseidon2AirChain = Poseidon2Air<
    F,
    Poseidon2LinearLayers<WIDTH>,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

#[derive(Debug)]
pub struct ChainAir(Poseidon2AirChain);

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

impl BaseAirWithPublicValues<F> for ChainAir {
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB> Air<AB> for ChainAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
    AB::Expr: FieldAlgebra<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        self.0
            .eval(&mut SubAirBuilder::<_, Poseidon2AirChain, _>::new(
                builder,
                0
                    ..num_cols::<
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >(),
            ));

        let encoded_tweak_chain_first = builder.public_values()[0].into();

        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &ChainCols<AB::Var> = (*local).borrow();
        let next: &ChainCols<AB::Var> = (*next).borrow();

        // When every rows
        eval_every_row(builder, encoded_tweak_chain_first, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(*local.is_active);
            builder.assert_zero(local.sig_idx);
            local.sig_step.eval_first_row(&mut builder);
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
fn eval_every_row<AB>(
    builder: &mut AB,
    encoded_tweak_chain_first: AB::Expr,
    cols: &ChainCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    cols.is_active.eval_every_row(builder);
    cols.sig_step.eval_every_row(builder);
    cols.chain_step_bits.map(|bit| builder.assert_bool(bit));
    builder.assert_zero(
        cols.chain_step_bits
            .iter()
            .copied()
            .map_into()
            .product::<AB::Expr>(),
    );
    cols.chain_idx.eval_every_row(builder);
    builder.assert_bool(cols.is_x_i);
    cols.padding().map(|v| builder.assert_zero(v));
    zip!(
        cols.encoded_tweak_chain(),
        [
            encoded_tweak_chain_first,
            *cols.chain_idx * AB::Expr::from_wrapped_u32(1 << 16)
                + cols.chain_step::<AB>()
                + F::ONE
        ]
    )
    .for_each(|(a, b)| builder.when(*cols.is_active).assert_eq(a, b));
}

#[inline]
fn eval_transition<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    local.is_active.eval_transition(builder, &next.is_active);
    local
        .sig_step
        .eval_transition(&mut builder.when(*local.is_active), &next.sig_step);
    builder.assert_eq(
        next.sig_idx,
        select(
            local.is_last_sig_row::<AB>(),
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
    builder.assert_one(cols.is_x_i);
}

#[inline]
fn eval_sig_transition<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_sig_transition::<AB>());

    zip!(next.parameter(), local.parameter()).for_each(|(a, b)| builder.assert_eq(a, b));
}

#[inline]
fn eval_sig_last_row<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_last_sig_row::<AB>());

    eval_sig_first_row(&mut builder.when(*next.is_active), next);
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

    builder.assert_zero(next.is_x_i);
    builder.assert_eq(*next.chain_idx, *local.chain_idx);
    builder.assert_eq(
        next.chain_step::<AB>(),
        local.chain_step::<AB>() + AB::Expr::ONE,
    );
    zip!(next.chain_input(), local.compression_output::<AB>())
        .for_each(|(a, b)| builder.assert_eq(a, b));
}

#[inline]
fn eval_chain_last_row<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder =
        builder.when(local.is_last_chain_step::<AB>() - local.is_last_sig_row::<AB>());

    local
        .chain_idx
        .eval_transition(&mut builder, &next.chain_idx);
    builder.assert_one(next.is_x_i);
}

#[inline]
fn receive_parameter<AB>(builder: &mut AB, local: &ChainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::Parameter as usize,
        iter::once(local.sig_idx).chain(local.parameter()),
        (*local.is_active).into() * local.is_last_sig_row::<AB>(),
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
            (*local.chain_idx).into(),
            local.chain_step::<AB>(),
        ],
        (*local.is_active).into() * local.is_x_i.into(),
    );
}

#[inline]
fn send_merkle_tree<AB>(builder: &mut AB, local: &ChainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        Bus::MerkleLeaf as usize,
        [
            local.sig_idx.into(),
            (*local.chain_idx).into() + AB::Expr::ONE,
        ]
        .into_iter()
        .chain(local.compression_output::<AB>()),
        *local.is_active * local.is_last_chain_step::<AB>(),
    );
}
