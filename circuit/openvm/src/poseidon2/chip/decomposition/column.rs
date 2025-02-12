use crate::{
    gadget::{cycle_bits::CycleBits, is_zero::IsZeroCols},
    poseidon2::{
        chip::decomposition::{F_MS_LIMB_BITS, LIMB_BITS, NUM_LIMBS, NUM_MSG_HASH_LIMBS},
        hash_sig::MSG_HASH_FE_LEN,
    },
};
use core::{
    borrow::{Borrow, BorrowMut},
    slice,
};
use openvm_stark_backend::{p3_air::AirBuilder, p3_field::FieldAlgebra};

pub const NUM_DECOMPOSITION_COLS: usize = size_of::<DecompositionCols<u8>>();

#[repr(C)]
pub struct DecompositionCols<T> {
    /// Signature index.
    pub sig_idx: T,
    /// One-hot vector indicating current accumulation step.
    pub inds: CycleBits<T, { MSG_HASH_FE_LEN + NUM_MSG_HASH_LIMBS }>,
    /// Scalars in little-endian order.
    pub values: [T; MSG_HASH_FE_LEN],
    /// Least significant limbs of `value[step]`.
    pub value_ls_limbs: [T; NUM_LIMBS - 1],
    /// Most significant limb bits of `value[step]`.
    pub value_ms_limb_bits: [T; F_MS_LIMB_BITS],
    /// Whether `value_ls_limbs[0] == 0`.
    pub value_limb_0_is_zero: IsZeroCols<T>,
    /// Whether `value_ls_limbs[1] == 0`.
    pub value_limb_1_is_zero: IsZeroCols<T>,
    /// Equals to `[value_ms_limb_bits[4] & value_ms_limb_bits[3] & value_ms_limb_bits[2], value_ms_limb_bits[1] & !value_ms_limb_bits[0]]`.
    pub value_ms_limb_auxs: [T; 3],
    /// Limbs of accumulation value.
    pub acc_limbs: [T; NUM_MSG_HASH_LIMBS],
    /// Bit decomposition of `acc_limbs[decomposition_step]` in little-endian.
    pub decomposition_bits: [T; LIMB_BITS],
    pub carries: [T; NUM_MSG_HASH_LIMBS - 1],
}

impl<T> DecompositionCols<T> {
    pub fn as_slice(&self) -> &[T] {
        unsafe { slice::from_raw_parts(self as *const _ as *const T, NUM_DECOMPOSITION_COLS) }
    }

    pub fn as_slice_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self as *mut _ as *mut T, NUM_DECOMPOSITION_COLS) }
    }
}

impl<T: Copy> DecompositionCols<T> {
    pub fn acc_inds(&self) -> &[T] {
        &self.inds[..MSG_HASH_FE_LEN]
    }

    pub fn is_acc<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds()
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>()
    }

    pub fn is_acc_first_row<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds()[0].into()
    }

    pub fn is_acc_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds()
            .iter()
            .take(MSG_HASH_FE_LEN - 1)
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>()
    }

    pub fn is_acc_last_row<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds()[MSG_HASH_FE_LEN - 1].into()
    }

    pub fn decomposition_inds(&self) -> &[T] {
        &self.inds[MSG_HASH_FE_LEN..]
    }

    pub fn is_decomposition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.decomposition_inds()
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>()
    }

    pub fn is_decomposition_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.decomposition_inds()
            .iter()
            .take(NUM_MSG_HASH_LIMBS - 1)
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>()
    }

    pub fn value_ms_limb<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.value_ms_limb_bits
            .iter()
            .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + (*bit).into())
    }
}

impl<T> Borrow<DecompositionCols<T>> for [T] {
    fn borrow(&self) -> &DecompositionCols<T> {
        debug_assert_eq!(self.len(), NUM_DECOMPOSITION_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<DecompositionCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<DecompositionCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut DecompositionCols<T> {
        debug_assert_eq!(self.len(), NUM_DECOMPOSITION_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<DecompositionCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
