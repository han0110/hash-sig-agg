use crate::{gadget::not, util::field::MaybeUninitField};
use core::{mem::MaybeUninit, ops::Deref};
use p3_air::AirBuilder;
use p3_field::PrimeField;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LowerRowsFilterCols<T> {
    pub is_active: T,
}

impl<T> Deref for LowerRowsFilterCols<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.is_active
    }
}

impl<T: PrimeField> LowerRowsFilterCols<MaybeUninit<T>> {
    #[inline]
    pub fn populate(&mut self, is_active: bool) {
        self.is_active.write_bool(is_active);
    }
}

impl<T: Copy> LowerRowsFilterCols<T> {
    #[inline]
    pub fn eval_every_row<AB: AirBuilder>(&self, builder: &mut AB)
    where
        T: Into<AB::Expr>,
    {
        builder.assert_bool(self.is_active);
    }

    #[inline]
    pub fn eval_transition<AB: AirBuilder>(&self, builder: &mut AB, next: &Self)
    where
        T: Into<AB::Expr>,
    {
        builder
            .when(not(self.is_active.into()))
            .assert_zero(next.is_active);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::test_utils::MockAirBuilder;
    use core::mem::MaybeUninit;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn test_lower_rows_filter_cols_populate_active() {
        let mut filter_cols: LowerRowsFilterCols<MaybeUninit<BabyBear>> = LowerRowsFilterCols {
            is_active: MaybeUninit::uninit(),
        };

        filter_cols.populate(true);

        let expected = BabyBear::ONE;
        let actual = unsafe { filter_cols.is_active.assume_init() };

        assert_eq!(
            actual, expected,
            "is_active should be 1 when populated with true"
        );
    }

    #[test]
    fn test_lower_rows_filter_cols_populate_inactive() {
        let mut filter_cols: LowerRowsFilterCols<MaybeUninit<BabyBear>> = LowerRowsFilterCols {
            is_active: MaybeUninit::uninit(),
        };

        filter_cols.populate(false);

        let expected = BabyBear::ZERO;
        let actual = unsafe { filter_cols.is_active.assume_init() };

        assert_eq!(
            actual, expected,
            "is_active should be 0 when populated with false"
        );
    }

    #[test]
    fn test_lower_rows_filter_cols_eval_every_row_active() {
        let mut builder = MockAirBuilder::new();
        let filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ONE,
        };

        filter_cols.eval_every_row(&mut builder);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should generate one constraint for active row"
        );
    }

    #[test]
    fn test_lower_rows_filter_cols_eval_every_row_inactive() {
        let mut builder = MockAirBuilder::new();
        let filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ZERO,
        };

        filter_cols.eval_every_row(&mut builder);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should generate one constraint for inactive row"
        );
    }

    #[test]
    fn test_lower_rows_filter_cols_eval_transition_active_to_active() {
        let mut builder = MockAirBuilder::new();
        let filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ONE,
        };
        let next_filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ONE,
        };

        filter_cols.eval_transition(&mut builder, &next_filter_cols);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should allow active -> active transition"
        );
    }

    #[test]
    fn test_lower_rows_filter_cols_eval_transition_active_to_inactive() {
        let mut builder = MockAirBuilder::new();
        let filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ONE,
        };
        let next_filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ZERO,
        };

        filter_cols.eval_transition(&mut builder, &next_filter_cols);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should allow active -> inactive transition"
        );
    }

    #[test]
    fn test_lower_rows_filter_cols_eval_transition_inactive_to_inactive() {
        let mut builder = MockAirBuilder::new();
        let filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ZERO,
        };
        let next_filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ZERO,
        };

        filter_cols.eval_transition(&mut builder, &next_filter_cols);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should allow inactive -> inactive transition"
        );
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_lower_rows_filter_cols_eval_transition_inactive_to_active_invalid() {
        let mut builder = MockAirBuilder::new();
        let filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ZERO,
        };
        let next_filter_cols = LowerRowsFilterCols {
            is_active: BabyBear::ONE,
        };

        filter_cols.eval_transition(&mut builder, &next_filter_cols);
    }
}
