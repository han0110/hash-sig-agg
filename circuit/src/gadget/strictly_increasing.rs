use crate::util::field::{MaybeUninitField, MaybeUninitFieldSlice};
use core::{mem::MaybeUninit, ops::Deref};
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{PrimeCharacteristicRing, PrimeField};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct StrictlyIncreasingCols<T, const MAX_DIFF_BITS: usize> {
    pub value: T,
    pub diff_bits: [T; MAX_DIFF_BITS],
    pub diff_inv: T,
}

impl<T, const MAX_DIFF_BITS: usize> Deref for StrictlyIncreasingCols<T, MAX_DIFF_BITS> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: PrimeField, const MAX_DIFF_BITS: usize>
    StrictlyIncreasingCols<MaybeUninit<T>, MAX_DIFF_BITS>
{
    #[inline]
    pub fn populate(&mut self, value: u32, value_next: u32) {
        let diff = value_next - value;
        self.value.write_u32(value);
        self.diff_bits
            .fill_from_iter((0..MAX_DIFF_BITS).map(|i| T::from_bool(((diff >> i) & 1) == 1)));
        self.diff_inv.write_f(match diff {
            0 => T::ZERO,
            1 => T::ONE,
            2 => T::ONE.halve(),
            _ => T::from_u32(diff).inverse(),
        });
    }

    #[inline]
    pub fn populate_padding(&mut self) {
        self.value.write_zero();
        self.diff_bits.fill_zero();
        self.diff_inv.write_zero();
    }
}

impl<T: Copy, const MAX_DIFF_BITS: usize> StrictlyIncreasingCols<T, MAX_DIFF_BITS> {
    #[inline]
    pub fn diff<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.diff_bits
            .into_iter()
            .rev()
            .map_into()
            .reduce(|acc, bit| acc.double() + bit)
            .unwrap()
    }

    #[inline]
    pub fn eval_every_row<AB: AirBuilder>(&self, builder: &mut AB)
    where
        T: Into<AB::Expr>,
    {
        self.diff_bits.map(|bit| builder.assert_bool(bit));
    }

    #[inline]
    pub fn eval_transition<AB: AirBuilder>(&self, builder: &mut AB, next: &Self)
    where
        T: Into<AB::Expr>,
    {
        builder.assert_one(self.diff_inv.into() * self.diff::<AB>());
        builder.assert_eq(next.value.into(), self.value.into() + self.diff::<AB>());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::test_utils::MockAirBuilder;
    use core::mem::MaybeUninit;
    use p3_baby_bear::BabyBear;
    use p3_field::Field;

    // Example bit size for testing
    const MAX_DIFF_BITS: usize = 5;

    #[test]
    fn test_strictly_increasing_cols_populate_increment_1() {
        let mut cols: StrictlyIncreasingCols<MaybeUninit<BabyBear>, MAX_DIFF_BITS> =
            StrictlyIncreasingCols {
                value: MaybeUninit::uninit(),
                diff_bits: [MaybeUninit::uninit(); MAX_DIFF_BITS],
                diff_inv: MaybeUninit::uninit(),
            };

        cols.populate(3, 4);

        let expected_value = BabyBear::new(3);
        let expected_diff_bits = [
            BabyBear::ONE,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
        ];
        let expected_diff_inv = BabyBear::ONE;

        let actual_value = unsafe { cols.value.assume_init() };
        let actual_diff_bits: [BabyBear; MAX_DIFF_BITS] =
            cols.diff_bits.map(|x| unsafe { x.assume_init() });
        let actual_diff_inv = unsafe { cols.diff_inv.assume_init() };

        assert_eq!(
            actual_value, expected_value,
            "Value should be initialized correctly"
        );
        assert_eq!(
            actual_diff_bits, expected_diff_bits,
            "Diff bits should represent 1"
        );
        assert_eq!(
            actual_diff_inv, expected_diff_inv,
            "Diff inv should be 1 for increment of 1"
        );
    }

    #[test]
    fn test_strictly_increasing_cols_populate_increment_2() {
        let mut cols: StrictlyIncreasingCols<MaybeUninit<BabyBear>, MAX_DIFF_BITS> =
            StrictlyIncreasingCols {
                value: MaybeUninit::uninit(),
                diff_bits: [MaybeUninit::uninit(); MAX_DIFF_BITS],
                diff_inv: MaybeUninit::uninit(),
            };

        cols.populate(3, 5);

        let expected_value = BabyBear::new(3);
        let expected_diff_bits = [
            BabyBear::ZERO,
            BabyBear::ONE,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
        ];
        let expected_diff_inv = BabyBear::ONE.halve();

        let actual_value = unsafe { cols.value.assume_init() };
        let actual_diff_bits: [BabyBear; MAX_DIFF_BITS] =
            cols.diff_bits.map(|x| unsafe { x.assume_init() });
        let actual_diff_inv = unsafe { cols.diff_inv.assume_init() };

        assert_eq!(
            actual_value, expected_value,
            "Value should be initialized correctly"
        );
        assert_eq!(
            actual_diff_bits, expected_diff_bits,
            "Diff bits should represent 2"
        );
        assert_eq!(
            actual_diff_inv, expected_diff_inv,
            "Diff inv should be 1/2 for increment of 2"
        );
    }

    #[test]
    fn test_strictly_increasing_cols_populate_no_change() {
        let mut cols: StrictlyIncreasingCols<MaybeUninit<BabyBear>, MAX_DIFF_BITS> =
            StrictlyIncreasingCols {
                value: MaybeUninit::uninit(),
                diff_bits: [MaybeUninit::uninit(); MAX_DIFF_BITS],
                diff_inv: MaybeUninit::uninit(),
            };

        cols.populate(5, 5);

        let expected_value = BabyBear::new(5);
        let expected_diff_bits = [BabyBear::ZERO; MAX_DIFF_BITS];
        let expected_diff_inv = BabyBear::ZERO;

        let actual_value = unsafe { cols.value.assume_init() };
        let actual_diff_bits: [BabyBear; MAX_DIFF_BITS] =
            cols.diff_bits.map(|x| unsafe { x.assume_init() });
        let actual_diff_inv = unsafe { cols.diff_inv.assume_init() };

        assert_eq!(
            actual_value, expected_value,
            "Value should be initialized correctly"
        );
        assert_eq!(
            actual_diff_bits, expected_diff_bits,
            "Diff bits should be all zero for no change"
        );
        assert_eq!(
            actual_diff_inv, expected_diff_inv,
            "Diff inv should be zero for no change"
        );
    }

    #[test]
    fn test_strictly_increasing_cols_populate_padding() {
        let mut cols: StrictlyIncreasingCols<MaybeUninit<BabyBear>, MAX_DIFF_BITS> =
            StrictlyIncreasingCols {
                value: MaybeUninit::uninit(),
                diff_bits: [MaybeUninit::uninit(); MAX_DIFF_BITS],
                diff_inv: MaybeUninit::uninit(),
            };

        cols.populate_padding();

        let expected_value = BabyBear::ZERO;
        let expected_diff_bits = [BabyBear::ZERO; MAX_DIFF_BITS];
        let expected_diff_inv = BabyBear::ZERO;

        let actual_value = unsafe { cols.value.assume_init() };
        let actual_diff_bits: [BabyBear; MAX_DIFF_BITS] =
            cols.diff_bits.map(|x| unsafe { x.assume_init() });
        let actual_diff_inv = unsafe { cols.diff_inv.assume_init() };

        assert_eq!(
            actual_value, expected_value,
            "Padding should set value to zero"
        );
        assert_eq!(
            actual_diff_bits, expected_diff_bits,
            "Padding should set diff_bits to zero"
        );
        assert_eq!(
            actual_diff_inv, expected_diff_inv,
            "Padding should set diff_inv to zero"
        );
    }

    #[test]
    fn test_strictly_increasing_cols_eval_transition() {
        let mut builder = MockAirBuilder::new();
        let cols: StrictlyIncreasingCols<BabyBear, MAX_DIFF_BITS> = StrictlyIncreasingCols {
            value: BabyBear::new(3),
            diff_bits: [
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
            diff_inv: BabyBear::ONE,
        };
        let next_cols = StrictlyIncreasingCols {
            value: BabyBear::new(4),
            diff_bits: [BabyBear::ZERO; MAX_DIFF_BITS],
            diff_inv: BabyBear::ZERO,
        };

        cols.eval_transition(&mut builder, &next_cols);

        assert_eq!(
            builder.constraints().len(),
            2,
            "Should generate two constraints for transition"
        );
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_strictly_increasing_cols_eval_transition_invalid() {
        let mut builder = MockAirBuilder::new();
        let cols: StrictlyIncreasingCols<BabyBear, MAX_DIFF_BITS> = StrictlyIncreasingCols {
            value: BabyBear::new(3),
            diff_bits: [
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
            diff_inv: BabyBear::ONE,
        };
        let next_cols = StrictlyIncreasingCols {
            value: BabyBear::new(5), // Incorrect: should be value + diff
            diff_bits: [BabyBear::ZERO; MAX_DIFF_BITS],
            diff_inv: BabyBear::ZERO,
        };

        cols.eval_transition(&mut builder, &next_cols);
    }
}
