use crate::{
    gadget::lower_rows_filter::LowerRowsFilterCols,
    poseidon2::hash_sig::{HASH_FE_LEN, MSG_HASH_FE_LEN, PARAM_FE_LEN},
    util::AlignBorrow,
};
use core::borrow::{Borrow, BorrowMut};

pub const NUM_MAIN_COLS: usize = size_of::<MainCols<u8>>();

#[repr(C)]
pub struct MainCols<T> {
    pub is_active: LowerRowsFilterCols<T>,
    pub sig_idx: T,
    pub parameter: [T; PARAM_FE_LEN],
    pub merkle_root: [T; HASH_FE_LEN],
    pub msg_hash: [T; MSG_HASH_FE_LEN],
}

impl<T> AlignBorrow<T> for MainCols<T> {
    const SIZE: usize = NUM_MAIN_COLS;
}

impl<T> Borrow<MainCols<T>> for [T] {
    #[inline]
    fn borrow(&self) -> &MainCols<T> {
        MainCols::align_borrow(self)
    }
}

impl<T> BorrowMut<MainCols<T>> for [T] {
    #[inline]
    fn borrow_mut(&mut self) -> &mut MainCols<T> {
        MainCols::align_borrow_mut(self)
    }
}
