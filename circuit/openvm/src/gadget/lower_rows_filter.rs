use crate::{gadget::not, util::field::MaybeUninitField};
use core::{mem::MaybeUninit, ops::Deref};
use p3_air::AirBuilder;
use p3_field::Field;

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

impl<T: Field> LowerRowsFilterCols<MaybeUninit<T>> {
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
