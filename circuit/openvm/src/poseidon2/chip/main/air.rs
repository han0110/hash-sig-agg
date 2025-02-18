use crate::poseidon2::{
    chip::{
        main::column::{MainCols, NUM_MAIN_COLS},
        Bus,
    },
    F,
};
use core::{borrow::Borrow, iter};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_matrix::Matrix;

#[derive(Clone, Copy, Debug)]
pub struct MainAir;

impl BaseAir<F> for MainAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }
}

impl PartitionedBaseAir<F> for MainAir {}

impl BaseAirWithPublicValues<F> for MainAir {}

impl<AB> Air<AB> for MainAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &MainCols<AB::Var> = (*local).borrow();
        let next: &MainCols<AB::Var> = (*next).borrow();

        // When every rows
        local.is_active.eval_every_row(builder);

        // When first row
        builder.when_first_row().assert_one(*local.is_active);

        // When transition
        local
            .is_active
            .eval_transition(&mut builder.when_transition(), &next.is_active);

        // Interaction
        send_parameter(builder, local);
        send_msg_hash(builder, local);
        send_decomposition(builder, local);
    }
}

#[inline]
fn send_parameter<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        Bus::Parameter as usize,
        iter::once(cols.sig_idx).chain(cols.parameter),
        *cols.is_active,
    );
}

#[inline]
fn send_msg_hash<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        Bus::MerkleRootAndMsgHash as usize,
        iter::once(cols.sig_idx)
            .chain(cols.parameter)
            .chain(cols.merkle_root)
            .chain(cols.msg_hash),
        *cols.is_active,
    );
}

#[inline]
fn send_decomposition<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        Bus::Decomposition as usize,
        iter::once(cols.sig_idx).chain(cols.msg_hash.into_iter().rev()),
        *cols.is_active,
    );
}
