use crate::{
    air::{
        Bus,
        range_check::column::{NUM_RANGE_CHECK_COLS, RangeCheckCols},
    },
    hash_sig::F,
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_air_ext::InteractionBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

#[derive(Clone, Copy, Debug, Default)]
pub struct RangeCheckAir;

impl BaseAir<F> for RangeCheckAir {
    fn width(&self) -> usize {
        NUM_RANGE_CHECK_COLS
    }
}

impl BaseAirWithPublicValues<F> for RangeCheckAir {}

impl<AB> Air<AB> for RangeCheckAir
where
    AB: InteractionBuilder<F = F>,
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        let local: &RangeCheckCols<AB::Var> = (*local).borrow();
        let next: &RangeCheckCols<AB::Var> = (*next).borrow();

        if !AB::ONLY_INTERACTION {
            eval_constriants(builder, local, next);
        }

        // Interaction
        receive_range_check(builder, local);
    }
}

#[inline]
fn eval_constriants<AB>(
    builder: &mut AB,
    local: &RangeCheckCols<AB::Var>,
    next: &RangeCheckCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
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
