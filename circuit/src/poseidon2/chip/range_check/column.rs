use crate::util::AlignBorrow;
use core::borrow::{Borrow, BorrowMut};

pub const NUM_RANGE_CHECK_COLS: usize = size_of::<RangeCheckCols<u8>>();

#[repr(C)]
pub struct RangeCheckCols<T> {
    pub value: T,
    pub mult: T,
}

impl<T> AlignBorrow<T> for RangeCheckCols<T> {
    const SIZE: usize = NUM_RANGE_CHECK_COLS;
}

impl<T> Borrow<RangeCheckCols<T>> for [T] {
    #[inline]
    fn borrow(&self) -> &RangeCheckCols<T> {
        RangeCheckCols::align_borrow(self)
    }
}

impl<T> BorrowMut<RangeCheckCols<T>> for [T] {
    #[inline]
    fn borrow_mut(&mut self) -> &mut RangeCheckCols<T> {
        RangeCheckCols::align_borrow_mut(self)
    }
}
