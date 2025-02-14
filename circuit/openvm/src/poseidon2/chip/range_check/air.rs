use crate::poseidon2::{
    chip::{
        range_check::column::{RangeCheckCols, NUM_RANGE_CHECK_COLS},
        Bus,
    },
    F,
};
use core::borrow::Borrow;
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};

#[derive(Clone, Copy, Debug)]
pub struct RangeCheckAir;

impl BaseAir<F> for RangeCheckAir {
    fn width(&self) -> usize {
        NUM_RANGE_CHECK_COLS
    }
}

impl PartitionedBaseAir<F> for RangeCheckAir {}

impl BaseAirWithPublicValues<F> for RangeCheckAir {}

impl<AB> Air<AB> for RangeCheckAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &RangeCheckCols<AB::Var> = (*local).borrow();
        let next: &RangeCheckCols<AB::Var> = (*next).borrow();

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_zero(local.value);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_range_check_transition(&mut builder, local, next);
        }

        // Interaction
        receive_range_check(builder, local);
    }
}

#[inline]
fn eval_range_check_transition<AB>(
    builder: &mut AB,
    local: &RangeCheckCols<AB::Var>,
    next: &RangeCheckCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    builder.assert_eq(next.value, local.value + AB::Expr::ONE);
}

#[inline]
fn receive_range_check<AB>(builder: &mut AB, cols: &RangeCheckCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(Bus::RangeCheck as usize, [cols.value], cols.mult);
}
