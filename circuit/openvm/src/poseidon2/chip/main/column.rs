use crate::{
    gadget::lower_rows_filter::LowerRowsFilterCols,
    poseidon2::hash_sig::{HASH_FE_LEN, MSG_HASH_FE_LEN, PARAM_FE_LEN},
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

impl<T> Borrow<MainCols<T>> for [T] {
    fn borrow(&self) -> &MainCols<T> {
        debug_assert_eq!(self.len(), NUM_MAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MainCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MainCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MainCols<T> {
        debug_assert_eq!(self.len(), NUM_MAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MainCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
