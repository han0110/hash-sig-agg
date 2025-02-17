use core::{
    borrow::{Borrow, BorrowMut},
    mem::MaybeUninit,
};
use p3_field::Field;

pub use hash_sig_verifier::concat_array;

pub trait MaybeUninitField<F: Field>: BorrowMut<MaybeUninit<F>> {
    #[inline]
    fn write_f(&mut self, value: F) {
        self.borrow_mut().write(value);
    }

    #[inline]
    fn write_zero(&mut self) {
        self.write_f(F::ZERO);
    }

    #[inline]
    fn write_one(&mut self) {
        self.write_f(F::ONE);
    }

    #[inline]
    fn write_bool(&mut self, value: bool) {
        self.write_f(F::from_bool(value));
    }

    #[inline]
    fn write_u8(&mut self, value: u8) {
        self.write_f(F::from_canonical_u8(value));
    }

    #[inline]
    fn write_u16(&mut self, value: u16) {
        self.write_f(F::from_canonical_u16(value));
    }

    #[inline]
    fn write_u32(&mut self, value: u32) {
        self.write_f(F::from_canonical_u32(value));
    }

    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.write_f(F::from_canonical_usize(value));
    }
}

impl<F: Field, T: BorrowMut<MaybeUninit<F>>> MaybeUninitField<F> for T {}

pub trait MaybeUninitFieldSlice<F: Field>: AsMut<[MaybeUninit<F>]> {
    #[inline]
    fn fill_from_slice(&mut self, values: &[F]) {
        zip!(self.as_mut(), values).for_each(|(cell, value)| cell.write_f(*value));
    }

    #[inline]
    fn fill_from_iter(&mut self, values: impl IntoIterator<Item: Borrow<F>>) {
        zip!(self.as_mut(), values).for_each(|(cell, value)| cell.write_f(*value.borrow()));
    }

    #[inline]
    fn fill_zero(&mut self) {
        self.as_mut()
            .iter_mut()
            .for_each(MaybeUninitField::write_zero);
    }

    #[inline]
    fn fill_one(&mut self) {
        self.as_mut()
            .iter_mut()
            .for_each(MaybeUninitField::write_one);
    }
}

impl<F: Field, T: ?Sized + AsMut<[MaybeUninit<F>]>> MaybeUninitFieldSlice<F> for T {}

macro_rules! zip {
    (@closure $p:pat => $tup:expr) => {
        |$p| $tup
    };
    (@closure $p:pat => ($($tup:tt)*) , $_iter:expr $(, $tail:expr)*) => {
        $crate::util::zip!(@closure ($p, b) => ($($tup)*, b) $(, $tail)*)
    };
    ($first:expr $(,)*) => {
        ::core::iter::IntoIterator::into_iter($first)
    };
    ($first:expr, $second:expr $(,)*) => {{
        #[cfg(debug_assertions)]
        { ::itertools::Itertools::zip_eq($crate::util::zip!($first), $second) }
        #[cfg(not(debug_assertions))]
        { ::core::iter::Iterator::zip($crate::util::zip!($first), $second) }
    }};
    ($first:expr $(, $rest:expr)* $(,)*) => {{
        let t = $crate::util::zip!($first);
        $(let t = $crate::util::zip!(t, $rest);)*
        t.map($crate::util::zip!(@closure a => (a) $(, $rest)*))
    }};
}

macro_rules! par_zip {
    ($first:expr $(, $rest:expr)* $(,)*) => {{
        use p3_maybe_rayon::prelude::*;
        (($first $(, $rest)*)).into_par_iter()
    }};
}

pub(crate) use {par_zip, zip};
