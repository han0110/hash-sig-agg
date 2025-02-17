use crate::util::{MaybeUninitField, MaybeUninitFieldSlice};
use core::{mem::MaybeUninit, ops::Deref};
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

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

impl<T: Field, const MAX_DIFF_BITS: usize> StrictlyIncreasingCols<MaybeUninit<T>, MAX_DIFF_BITS> {
    #[inline]
    pub fn populate(&mut self, value: u32, value_next: u32) {
        let diff = value_next - value;
        self.value.write_u32(value);
        self.diff_bits
            .fill_from_iter((0..MAX_DIFF_BITS).map(|i| T::from_bool((diff >> i & 1) == 1)));
        self.diff_inv.write_f(match diff {
            0 => T::ZERO,
            1 => T::ONE,
            2 => T::ONE.halve(),
            _ => T::from_canonical_u32(diff).inverse(),
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
