use core::mem::MaybeUninit;
use p3_air::AirBuilder;
use p3_field::Field;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IsZeroCols<T> {
    pub inv: T,
    pub output: T,
}

impl<T: Field> IsZeroCols<MaybeUninit<T>> {
    #[inline]
    pub fn populate(&mut self, input: T) {
        let is_zero = input.is_zero();
        self.output.write(T::from_bool(is_zero));
        if is_zero {
            self.inv.write(T::ZERO);
        } else {
            self.inv.write(input.try_inverse().unwrap());
        }
    }
}

impl<T: Copy> IsZeroCols<T> {
    #[inline]
    pub fn eval<AB: AirBuilder>(&self, builder: &mut AB, input: impl Into<AB::Expr>)
    where
        T: Into<AB::Expr>,
    {
        let input = input.into();
        builder.assert_zero(input.clone() * self.output.into());
        builder.assert_one(self.output.into() + input * self.inv.into());
    }
}

#[cfg(test)]
mod tests {
    use crate::gadget::test_utils::MockAirBuilder;

    use super::*;
    use core::mem::MaybeUninit;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn test_is_zero_cols_populate_zero() {
        let mut is_zero_cols = IsZeroCols {
            inv: MaybeUninit::uninit(),
            output: MaybeUninit::uninit(),
        };

        is_zero_cols.populate(BabyBear::ZERO);

        let expected_inv = BabyBear::ZERO;
        let expected_output = BabyBear::ONE;

        let actual_inv = unsafe { is_zero_cols.inv.assume_init() };
        let actual_output = unsafe { is_zero_cols.output.assume_init() };

        assert_eq!(
            actual_inv, expected_inv,
            "Inverse should be zero when input is zero"
        );
        assert_eq!(
            actual_output, expected_output,
            "Output should be one when input is zero"
        );
    }

    #[test]
    fn test_is_zero_cols_populate_nonzero() {
        let mut is_zero_cols = IsZeroCols {
            inv: MaybeUninit::uninit(),
            output: MaybeUninit::uninit(),
        };

        let input = BabyBear::new(5);
        is_zero_cols.populate(input);

        let expected_inv = input.try_inverse().unwrap();
        let expected_output = BabyBear::ZERO;

        let actual_inv = unsafe { is_zero_cols.inv.assume_init() };
        let actual_output = unsafe { is_zero_cols.output.assume_init() };

        assert_eq!(
            actual_inv, expected_inv,
            "Inverse should be correct when input is nonzero"
        );
        assert_eq!(
            actual_output, expected_output,
            "Output should be zero when input is nonzero"
        );
    }

    #[test]
    fn test_is_zero_cols_eval_zero_input() {
        let mut builder = MockAirBuilder::new();
        let is_zero_cols = IsZeroCols {
            inv: BabyBear::ZERO,
            output: BabyBear::ONE,
        };
        let input = BabyBear::ZERO;

        is_zero_cols.eval(&mut builder, input);

        assert_eq!(
            builder.constraints(),
            [BabyBear::ZERO; 2],
            "Should generate two constraints"
        );
    }

    #[test]
    fn test_is_zero_cols_eval_nonzero_input() {
        let mut builder = MockAirBuilder::new();
        let input = BabyBear::new(5);
        let is_zero_cols = IsZeroCols {
            inv: input.try_inverse().unwrap(),
            output: BabyBear::ZERO,
        };

        is_zero_cols.eval(&mut builder, input);

        assert_eq!(
            builder.constraints(),
            [BabyBear::ZERO; 2],
            "Should generate two constraints"
        );
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_is_zero_cols_eval_invalid_output() {
        let mut builder = MockAirBuilder::new();
        let input = BabyBear::new(5);
        let is_zero_cols = IsZeroCols {
            inv: input.try_inverse().unwrap(), // Correct inverse
            output: BabyBear::ONE,             // Incorrect output
        };

        is_zero_cols.eval(&mut builder, input);
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_is_zero_cols_eval_invalid_inverse() {
        let mut builder = MockAirBuilder::new();
        let input = BabyBear::new(5);
        let is_zero_cols = IsZeroCols {
            inv: BabyBear::new(3), // Incorrect inverse
            output: BabyBear::ZERO,
        };

        is_zero_cols.eval(&mut builder, input);
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_is_zero_cols_eval_invalid_both() {
        let mut builder = MockAirBuilder::new();
        let input = BabyBear::new(5);
        let is_zero_cols = IsZeroCols {
            inv: BabyBear::new(3), // Incorrect inverse
            output: BabyBear::ONE, // Incorrect output
        };

        is_zero_cols.eval(&mut builder, input);
    }
}
