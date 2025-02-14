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
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};

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
        eval_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(*local.is_active);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_transition(&mut builder, local, next);
        }

        // Interaction
        send_parameter(builder, local);
        send_msg_hash(builder, local);
        send_decomposition(builder, local);
    }
}

#[inline]
fn eval_every_row<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    cols.is_active.eval_every_row(builder);
}

#[inline]
fn eval_transition<AB>(builder: &mut AB, local: &MainCols<AB::Var>, next: &MainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    local.is_active.eval_transition(builder, &next.is_active);
}

#[inline]
fn send_parameter<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        Bus::Parameter as usize,
        iter::empty().chain([cols.sig_idx]).chain(cols.parameter),
        *cols.is_active,
    );
}

#[inline]
fn send_msg_hash<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        Bus::MsgHash as usize,
        iter::empty()
            .chain([cols.sig_idx])
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
        iter::empty()
            .chain([cols.sig_idx])
            .chain(cols.msg_hash.into_iter().rev()),
        *cols.is_active,
    );
}
