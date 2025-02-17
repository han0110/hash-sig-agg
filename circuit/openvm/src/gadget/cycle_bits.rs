use crate::{gadget::not, util::MaybeUninitFieldSlice};
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
    pub fn active_idx<AB: AirBuilder>(&self) -> AB::Expr
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
