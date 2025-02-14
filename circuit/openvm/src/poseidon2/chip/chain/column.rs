use crate::{
    gadget::{cycle_int::CycleInt, is_zero::IsZeroCols, lower_rows_filter::LowerRowsFilterCols},
    poseidon2::{
        chip::chain::{
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
            MAX_CHAIN_STEP_DIFF_BITS,
        },
        hash_sig::{CHUNK_SIZE, HASH_FE_LEN, PARAM_FE_LEN, TARGET_SUM, TWEAK_FE_LEN},
        HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
    slice,
};
use p3_air::AirBuilder;
use p3_field::FieldAlgebra;
use p3_poseidon2_util::air::{outputs, Poseidon2Cols};

pub const NUM_CHAIN_COLS: usize = size_of::<ChainCols<u8>>();

#[repr(C)]
pub struct ChainCols<T> {
    pub perm:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// Whether this sig is active or not.
    pub is_active: LowerRowsFilterCols<T>,
    /// Signature index.
    pub sig_idx: T,
    /// Signature step.
    pub sig_step: CycleInt<T, { TARGET_SUM as usize }>,
    /// Chain index.
    pub chain_idx: T,
    /// Whether `chain_idx == 0`.
    pub chain_idx_is_zero: IsZeroCols<T>,
    /// Chain index diff range check.
    pub chain_idx_diff_bits: [T; MAX_CHAIN_STEP_DIFF_BITS],
    /// Chain index diff inverse.
    pub chain_idx_diff_inv: T,
    /// Chain step in little-endian bits, in range `0..(1 << CHUNK_SIZE)`.
    pub chain_step_bits: [T; CHUNK_SIZE],
    /// Whether `chain_step` is equal to `x_i` or not.
    pub is_x_i: T,
    /// Sum of `x_i`.
    pub sum: T,
}

impl<T> ChainCols<T> {
    #[inline]
    pub const fn as_slice(&self) -> &[T] {
        unsafe { slice::from_raw_parts(core::ptr::from_ref(self).cast::<T>(), NUM_CHAIN_COLS) }
    }

    #[inline]
    pub const fn as_slice_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(core::ptr::from_mut(self).cast::<T>(), NUM_CHAIN_COLS) }
    }
}

impl<T: Copy> ChainCols<T> {
    #[inline]
    pub fn is_sig_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        (*self.is_active).into() - self.is_last_sig_row::<AB>()
    }

    #[inline]
    pub fn is_last_sig_row<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.sig_step.is_last_step::<AB>()
    }

    #[inline]
    pub fn chain_idx_diff<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.chain_idx_diff_bits
            .iter()
            .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + (*bit).into())
    }

    #[inline]
    pub fn chain_step<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        const { assert!(CHUNK_SIZE == 2) }
        self.chain_step_bits[0].into() + self.chain_step_bits[1].into().double()
    }

    /// Returns bool indicating `chain_step == (1 << CHUNKS_SIZE) - 2`
    #[inline]
    pub fn is_last_chain_step<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        const { assert!(CHUNK_SIZE == 2) }
        self.chain_step_bits[1].into()
    }

    #[inline]
    pub fn parameter(&self) -> [T; PARAM_FE_LEN] {
        from_fn(|i| self.perm.inputs[i])
    }

    #[inline]
    pub fn encoded_tweak_chain(&self) -> [T; TWEAK_FE_LEN] {
        from_fn(|i| self.perm.inputs[PARAM_FE_LEN + i])
    }

    #[inline]
    pub fn chain_input(&self) -> [T; HASH_FE_LEN] {
        from_fn(|i| self.perm.inputs[PARAM_FE_LEN + TWEAK_FE_LEN + i])
    }

    #[inline]
    pub fn compression_output<AB: AirBuilder>(&self) -> [AB::Expr; HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| self.perm.inputs[i].into() + outputs(&self.perm)[i].into())
    }
}

impl<T> Borrow<ChainCols<T>> for [T] {
    fn borrow(&self) -> &ChainCols<T> {
        debug_assert_eq!(self.len(), NUM_CHAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ChainCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<ChainCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ChainCols<T> {
        debug_assert_eq!(self.len(), NUM_CHAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<ChainCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
