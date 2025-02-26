use crate::{gadget::not, util::field::MaybeUninitFieldSlice};
use core::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CycleBits<T, const N: usize> {
    pub bits: [T; N],
}

impl<T, const N: usize> Deref for CycleBits<T, N> {
    type Target = [T; N];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.bits
    }
}

impl<T, const N: usize> DerefMut for CycleBits<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bits
    }
}

impl<T: Field, const N: usize> CycleBits<MaybeUninit<T>, N> {
    #[inline]
    pub fn populate(&mut self, idx: Option<usize>) {
        if let Some(i) = idx {
            self.fill_from_iter((0..N).map(|j| T::from_bool(i == j)));
        } else {
            self.fill_zero();
        }
    }
}

impl<T: Copy, const N: usize> CycleBits<T, N> {
    #[inline]
    pub fn eval_every_row<AB: AirBuilder>(&self, builder: &mut AB)
    where
        T: Into<AB::Expr>,
    {
        self.map(|bit| builder.assert_bool(bit));
        builder.assert_bool(self.is_active::<AB>());
    }

    #[inline]
    pub fn eval_transition<AB: AirBuilder>(&self, builder: &mut AB, next: &Self)
    where
        T: Into<AB::Expr>,
    {
        builder.when(self.is_transition::<AB>()).assert_eq(
            next.active_idx::<AB>(),
            self.active_idx::<AB>() + AB::Expr::ONE,
        );
        builder
            .when(self[N - 1])
            .assert_zero(next[1..].iter().copied().map_into().sum::<AB::Expr>());
        builder
            .when(not(self.is_active::<AB>()))
            .assert_zero(next.is_active::<AB>());
    }

    #[inline]
    fn active_idx<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.into_iter()
            .enumerate()
            .map(|(idx, bit)| bit.into() * AB::Expr::from_canonical_usize(idx))
            .sum()
    }

    #[inline]
    pub fn is_active<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.into_iter().map_into().sum()
    }

    #[inline]
    pub fn is_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.into_iter().take(N - 1).map_into().sum()
    }

    #[inline]
    pub fn is_last_row_to_active<AB: AirBuilder>(&self, next: &Self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self[N - 1].into() * next[0].into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::test_utils::MockAirBuilder;
    use core::mem::MaybeUninit;
    use p3_baby_bear::BabyBear;

    #[test]
    fn test_cycle_bits_deref() {
        let cycle_bits = CycleBits { bits: [1, 0, 1, 0] };
        assert_eq!(cycle_bits.bits, [1, 0, 1, 0]);
    }

    #[test]
    fn test_cycle_bits_deref_mut() {
        let mut cycle_bits = CycleBits { bits: [1, 0, 1, 0] };
        cycle_bits.bits[1] = 1;
        assert_eq!(cycle_bits.bits, [1, 1, 1, 0]);
    }

    #[test]
    fn test_cycle_bits_populate_some() {
        let mut cycle_bits = CycleBits {
            bits: [MaybeUninit::uninit(); 4],
        };
        cycle_bits.populate(Some(2));

        let expected = [
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ONE,
            BabyBear::ZERO,
        ];

        let actual: [BabyBear; 4] = cycle_bits.bits.map(|x| unsafe { x.assume_init() });

        assert_eq!(
            actual, expected,
            "Populate should set the correct active bit"
        );
    }

    #[test]
    fn test_cycle_bits_populate_none() {
        let mut cycle_bits = CycleBits {
            bits: [MaybeUninit::uninit(); 4],
        };
        cycle_bits.populate(None);

        let expected = [BabyBear::ZERO; 4];
        let actual: [BabyBear; 4] = cycle_bits.bits.map(|x| unsafe { x.assume_init() });

        assert_eq!(
            actual, expected,
            "Populate with None should set all bits to zero"
        );
    }

    #[test]
    fn test_cycle_bits_eval_every_row() {
        let mut builder = MockAirBuilder::new();
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
        };

        cycle_bits.eval_every_row(&mut builder);

        assert_eq!(
            builder.constraints().len(),
            5,
            "Should have 5 boolean assertions (4 + 1 for is_active)"
        );
    }

    #[test]
    #[should_panic(expected = "Assertion failed: x should be zero")]
    fn test_cycle_bits_eval_every_row_invalid() {
        let mut builder = MockAirBuilder::new();
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ONE,
                BabyBear::ONE, // Invalid: more than one active bit
                BabyBear::ONE,
                BabyBear::ZERO,
            ],
        };

        cycle_bits.eval_every_row(&mut builder);
    }

    #[test]
    fn test_cycle_bits_eval_transition() {
        let mut builder = MockAirBuilder::new();
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
        };
        let next_cycle_bits = CycleBits {
            bits: [
                BabyBear::ZERO,
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
        };

        cycle_bits.eval_transition(&mut builder, &next_cycle_bits);

        // Should generate three constraints for transition rules:
        // - When transition
        // - When last row is active
        // - When not active
        assert_eq!(builder.constraints().len(), 3);
    }

    #[test]
    fn test_cycle_bits_active_idx() {
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ZERO,
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
        };
        let idx = cycle_bits.active_idx::<MockAirBuilder>();

        assert_eq!(
            idx,
            BabyBear::new(1),
            "Active index should be 1 when second bit is set"
        );
    }

    #[test]
    fn test_cycle_bits_is_active() {
        // One active bit -> is active
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
        };
        let active = cycle_bits.is_active::<MockAirBuilder>();

        assert_eq!(
            active,
            BabyBear::ONE,
            "is_active should sum the active bits"
        );

        // No active bits -> not active
        let cycle_bits = CycleBits {
            bits: [BabyBear::ZERO, BabyBear::ZERO],
        };
        let active = cycle_bits.is_active::<MockAirBuilder>();

        assert_eq!(active, BabyBear::ZERO);
    }

    #[test]
    fn test_cycle_bits_is_transition() {
        // ONE in range [0, N-1] -> transition
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
        };
        let transition = cycle_bits.is_transition::<MockAirBuilder>();

        assert_eq!(transition, BabyBear::ONE);

        // ONE at index N-1 -> no transition
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ONE,
            ],
        };
        let transition = cycle_bits.is_transition::<MockAirBuilder>();

        assert_eq!(transition, BabyBear::ZERO);
    }

    #[test]
    fn test_cycle_bits_is_last_row_to_active() {
        let cycle_bits = CycleBits {
            bits: [
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ONE,
            ],
        };
        let next_cycle_bits = CycleBits {
            bits: [
                BabyBear::ONE,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
        };

        let result = cycle_bits.is_last_row_to_active::<MockAirBuilder>(&next_cycle_bits);

        // Should be active in the last row and transition to first bit in next cycle
        assert_eq!(result, BabyBear::ONE);
    }
}
