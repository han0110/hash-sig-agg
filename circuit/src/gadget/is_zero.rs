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
