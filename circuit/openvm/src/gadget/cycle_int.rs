use crate::{
    gadget::{is_equal::IsEqualCols, not},
    util::field::MaybeUninitField,
};
use core::mem::MaybeUninit;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CycleInt<T, const N: usize> {
    pub step: T,
    pub is_last_step: IsEqualCols<T>,
}

impl<T: Field, const N: usize> CycleInt<MaybeUninit<T>, N> {
    #[inline]
    pub fn populate(&mut self, step: usize) {
        self.step.write_usize(step);
        self.is_last_step.populate(
            T::from_canonical_usize(step),
            T::from_canonical_usize(N - 1),
        );
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
            .eval(builder, self.step, AB::Expr::from_canonical_usize(N - 1));
    }

    #[inline]
    pub fn eval_transition<AB: AirBuilder>(&self, builder: &mut AB, next: &Self)
    where
        T: Into<AB::Expr>,
    {
        builder.assert_eq(
            next.step,
            self.step.into() + AB::Expr::ONE
                - self.is_last_step.output.into() * AB::Expr::from_canonical_usize(N),
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
