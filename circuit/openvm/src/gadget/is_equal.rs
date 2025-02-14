use crate::gadget::is_zero::IsZeroCols;
use core::mem::MaybeUninit;
use core::ops::Deref;
use p3_air::AirBuilder;
use p3_field::Field;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct IsEqualCols<T>(IsZeroCols<T>);

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
