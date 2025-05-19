use crate::gadget::is_zero::IsZeroCols;
use core::mem::MaybeUninit;
use core::ops::Deref;
use p3_air::AirBuilder;
use p3_field::Field;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IsEqualCols<T>(pub IsZeroCols<T>);

impl<T> Deref for IsEqualCols<T> {
    type Target = IsZeroCols<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Field> IsEqualCols<MaybeUninit<T>> {
    #[inline]
    pub fn populate(&mut self, a: T, b: T) {
        self.0.populate(a - b);
    }
}

impl<T: Copy> IsEqualCols<T> {
    #[inline]
    pub fn eval<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        a: impl Into<AB::Expr>,
        b: impl Into<AB::Expr>,
    ) where
        T: Into<AB::Expr>,
    {
        self.0.eval(builder, a.into() - b.into());
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
    fn test_is_equal_cols_populate_equal() {
        let mut is_equal_cols = IsEqualCols(IsZeroCols {
            inv: MaybeUninit::uninit(),
            output: MaybeUninit::uninit(),
        });

        let a = BabyBear::new(7);
        let b = BabyBear::new(7);
        is_equal_cols.populate(a, b);

        let expected_inv = BabyBear::ZERO;
        let expected_output = BabyBear::ONE;

        let actual_inv = unsafe { is_equal_cols.inv.assume_init() };
        let actual_output = unsafe { is_equal_cols.output.assume_init() };

        assert_eq!(
            actual_inv, expected_inv,
            "Inverse should be zero when a == b"
        );
        assert_eq!(
            actual_output, expected_output,
            "Output should be one when a == b"
        );
    }

    #[test]
    fn test_is_equal_cols_populate_not_equal() {
        let mut is_equal_cols = IsEqualCols(IsZeroCols {
            inv: MaybeUninit::uninit(),
            output: MaybeUninit::uninit(),
        });

        let a = BabyBear::new(10);
        let b = BabyBear::new(5);
        is_equal_cols.populate(a, b);

        let expected_inv = BabyBear::new(5).try_inverse().unwrap();
        let expected_output = BabyBear::ZERO;

        let actual_inv = unsafe { is_equal_cols.inv.assume_init() };
        let actual_output = unsafe { is_equal_cols.output.assume_init() };

        assert_eq!(
            actual_inv, expected_inv,
            "Inverse should be correct when a != b"
        );
        assert_eq!(
            actual_output, expected_output,
            "Output should be zero when a != b"
        );
    }

    #[test]
    fn test_is_equal_cols_eval_equal() {
        let mut builder = MockAirBuilder::new();
        let is_equal_cols = IsEqualCols(IsZeroCols {
            inv: BabyBear::ZERO,
            output: BabyBear::ONE,
        });

        let a = BabyBear::new(8);
        let b = BabyBear::new(8);

        is_equal_cols.eval(&mut builder, a, b);

        assert_eq!(
            builder.constraints().len(),
            2,
            "Should generate two constraints"
        );
    }

    #[test]
    fn test_is_equal_cols_eval_not_equal() {
        let mut builder = MockAirBuilder::new();
        let a = BabyBear::new(12);
        let b = BabyBear::new(3);
        let is_equal_cols = IsEqualCols(IsZeroCols {
            inv: (a - b).try_inverse().unwrap(),
            output: BabyBear::ZERO,
        });

        is_equal_cols.eval(&mut builder, a, b);

        assert_eq!(
            builder.constraints().len(),
            2,
            "Should generate two constraints"
        );
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_is_equal_cols_eval_invalid_output() {
        let mut builder = MockAirBuilder::new();
        let a = BabyBear::new(4);
        let b = BabyBear::new(9);
        let is_equal_cols = IsEqualCols(IsZeroCols {
            inv: (a - b).try_inverse().unwrap(), // Correct inverse
            output: BabyBear::ONE,               // Incorrect output
        });

        is_equal_cols.eval(&mut builder, a, b);
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_is_equal_cols_eval_invalid_inverse() {
        let mut builder = MockAirBuilder::new();
        let a = BabyBear::new(6);
        let b = BabyBear::new(2);
        let is_equal_cols = IsEqualCols(IsZeroCols {
            inv: BabyBear::new(3), // Incorrect inverse
            output: BabyBear::ZERO,
        });

        is_equal_cols.eval(&mut builder, a, b);
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_is_equal_cols_eval_invalid_both() {
        let mut builder = MockAirBuilder::new();
        let a = BabyBear::new(5);
        let b = BabyBear::new(1);
        let is_equal_cols = IsEqualCols(IsZeroCols {
            inv: BabyBear::new(3), // Incorrect inverse
            output: BabyBear::ONE, // Incorrect output
        });

        is_equal_cols.eval(&mut builder, a, b);
    }
}
