use crate::{
    gadget::{is_equal::IsEqualCols, not},
    util::field::MaybeUninitField,
};
use core::{mem::MaybeUninit, ops::Deref};
use p3_air::AirBuilder;
use p3_field::{PrimeCharacteristicRing, PrimeField};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CycleInt<T, const N: usize> {
    pub step: T,
    pub is_last_step: IsEqualCols<T>,
}

impl<T, const N: usize> Deref for CycleInt<T, N> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.step
    }
}

impl<T: PrimeField, const N: usize> CycleInt<MaybeUninit<T>, N> {
    #[inline]
    pub fn populate(&mut self, step: usize) {
        self.step.write_usize(step);
        self.is_last_step
            .populate(T::from_usize(step), T::from_usize(N - 1));
    }
}

impl<T: Copy, const N: usize> CycleInt<T, N> {
    #[inline]
    pub fn eval_first_row<AB: AirBuilder>(&self, builder: &mut AB)
    where
        T: Into<AB::Expr>,
    {
        builder.assert_zero(self.step);
    }

    #[inline]
    pub fn eval_every_row<AB: AirBuilder>(&self, builder: &mut AB)
    where
        T: Into<AB::Expr>,
    {
        self.is_last_step
            .eval(builder, self.step, AB::F::from_usize(N - 1));
    }

    #[inline]
    pub fn eval_transition<AB: AirBuilder>(&self, builder: &mut AB, next: &Self)
    where
        T: Into<AB::Expr>,
    {
        builder.assert_eq(
            next.step,
            self.step.into() + AB::Expr::ONE
                - self.is_last_step.output.into() * AB::F::from_usize(N),
        );
    }

    #[inline]
    pub fn is_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        not(self.is_last_step::<AB>())
    }

    #[inline]
    pub fn is_last_step<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.is_last_step.output.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::{is_zero::IsZeroCols, test_utils::MockAirBuilder};
    use core::mem::MaybeUninit;
    use p3_baby_bear::BabyBear;
    use p3_field::Field;

    // Example cycle size
    const N: usize = 4;

    #[test]
    fn test_cycle_int_populate_first_step() {
        let mut cycle_int: CycleInt<MaybeUninit<BabyBear>, N> = CycleInt {
            step: MaybeUninit::uninit(),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: MaybeUninit::uninit(),
                output: MaybeUninit::uninit(),
            }),
        };

        cycle_int.populate(0);

        let expected_step = BabyBear::ZERO;
        let expected_is_last_output = BabyBear::ZERO;

        let actual_step = unsafe { cycle_int.step.assume_init() };
        let actual_is_last_output = unsafe { cycle_int.is_last_step.output.assume_init() };

        assert_eq!(
            actual_step, expected_step,
            "Step should be initialized to 0"
        );
        assert_eq!(
            actual_is_last_output, expected_is_last_output,
            "is_last_step should be 0 at step 0"
        );
    }

    #[test]
    fn test_cycle_int_populate_last_step() {
        let mut cycle_int: CycleInt<MaybeUninit<BabyBear>, N> = CycleInt {
            step: MaybeUninit::uninit(),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: MaybeUninit::uninit(),
                output: MaybeUninit::uninit(),
            }),
        };

        cycle_int.populate(N - 1);

        let expected_step = BabyBear::from_usize(N - 1);
        let expected_is_last_output = BabyBear::ONE;

        let actual_step = unsafe { cycle_int.step.assume_init() };
        let actual_is_last_output = unsafe { cycle_int.is_last_step.output.assume_init() };

        assert_eq!(actual_step, expected_step, "Step should be N-1");
        assert_eq!(
            actual_is_last_output, expected_is_last_output,
            "is_last_step should be 1 at last step"
        );
    }

    #[test]
    fn test_cycle_int_eval_first_row() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::ZERO,
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        cycle_int.eval_first_row(&mut builder);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should generate one constraint"
        );
    }

    #[test]
    fn test_cycle_int_eval_every_row() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::new(2),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: (BabyBear::new(2) - BabyBear::from_usize(N - 1))
                    .try_inverse()
                    .unwrap(),
                output: BabyBear::ZERO,
            }),
        };

        cycle_int.eval_every_row(&mut builder);

        assert_eq!(
            builder.constraints().len(),
            2,
            "Should generate constraints for every row"
        );
    }

    #[test]
    fn test_cycle_int_eval_transition_normal() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::new(1),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };
        let next_cycle_int = CycleInt {
            step: BabyBear::new(2),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        cycle_int.eval_transition(&mut builder, &next_cycle_int);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should generate one constraint for transition"
        );
    }

    #[test]
    fn test_cycle_int_eval_transition_wrap_around() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::from_usize(N - 1),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ONE,
            }),
        };
        let next_cycle_int = CycleInt {
            step: BabyBear::ZERO,
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        cycle_int.eval_transition(&mut builder, &next_cycle_int);

        assert_eq!(
            builder.constraints().len(),
            1,
            "Should correctly enforce wrap-around transition"
        );
    }

    #[test]
    fn test_cycle_int_is_transition() {
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::new(2),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        let transition = cycle_int.is_transition::<MockAirBuilder>();

        assert_eq!(
            transition,
            BabyBear::ONE,
            "Should transition if not last step"
        );
    }

    #[test]
    fn test_cycle_int_is_not_transition_at_last_step() {
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::from_usize(N - 1),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ONE,
            }),
        };

        let transition = cycle_int.is_transition::<MockAirBuilder>();

        assert_eq!(
            transition,
            BabyBear::ZERO,
            "Should not transition if last step"
        );
    }

    #[test]
    fn test_cycle_int_is_last_step() {
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::from_usize(N - 1),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ONE,
            }),
        };

        let is_last = cycle_int.is_last_step::<MockAirBuilder>();

        assert_eq!(is_last, BabyBear::ONE, "Should return 1 when last step");
    }

    #[test]
    fn test_cycle_int_is_not_last_step() {
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::new(1),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        let is_last = cycle_int.is_last_step::<MockAirBuilder>();

        assert_eq!(
            is_last,
            BabyBear::ZERO,
            "Should return 0 when not last step"
        );
    }

    // ################################################################################

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_cycle_int_eval_first_row_invalid() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::new(1), // Incorrect: first row should have step = 0
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        cycle_int.eval_first_row(&mut builder);
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_cycle_int_eval_every_row_invalid() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::new(3),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::new(23), // Incorrect inverse
                output: BabyBear::ZERO, // Incorrect output
            }),
        };

        cycle_int.eval_every_row(&mut builder);
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_cycle_int_eval_transition_invalid_step_increment() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::new(1),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };
        let next_cycle_int = CycleInt {
            step: BabyBear::new(3), // Incorrect: should be step + 1
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        cycle_int.eval_transition(&mut builder, &next_cycle_int);
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_cycle_int_eval_transition_invalid_wrap_around() {
        let mut builder = MockAirBuilder::new();
        let cycle_int: CycleInt<BabyBear, N> = CycleInt {
            step: BabyBear::from_usize(N - 1),
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ONE,
            }),
        };
        let next_cycle_int = CycleInt {
            step: BabyBear::new(2), // Incorrect: should be 0 due to wrap-around
            is_last_step: IsEqualCols(IsZeroCols {
                inv: BabyBear::ZERO,
                output: BabyBear::ZERO,
            }),
        };

        cycle_int.eval_transition(&mut builder, &next_cycle_int);
    }
}
