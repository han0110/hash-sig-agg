use crate::{
    gadget::{cycle_bits::CycleBits, is_equal::IsEqualCols, is_zero::IsZeroCols},
    poseidon2::{
        chip::{
            decomposition::{F_MS_LIMB_BITS, LIMB_BITS, NUM_LIMBS, NUM_MSG_HASH_LIMBS},
            AlignBorrow,
        },
        hash_sig::{CHUNK_SIZE, MSG_HASH_FE_LEN},
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
    slice,
};
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::FieldAlgebra;

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
    /// Whether `sum(value_ms_limb_bits[F_MS_LIMB_TRAILING_ZEROS..]) == F_MS_LIMB_LEADING_ONES`
    pub is_ms_limb_max: IsEqualCols<T>,
    /// Limbs of accumulation value.
    pub acc_limbs: [T; NUM_MSG_HASH_LIMBS],
    /// Carries of limbs addition.
    pub carries: [T; NUM_MSG_HASH_LIMBS - 1],
    /// Bit decomposition of `acc_limbs[decomposition_step]` in little-endian.
    pub decomposition_bits: [T; LIMB_BITS],
    /// Sum of decomposed chunks.
    pub sum: T,
}

impl<T> DecompositionCols<T> {
    #[inline]
    pub const fn as_slice(&self) -> &[T] {
        unsafe {
            slice::from_raw_parts(
                core::ptr::from_ref(self).cast::<T>(),
                NUM_DECOMPOSITION_COLS,
            )
        }
    }

    #[inline]
    pub const fn as_slice_mut(&mut self) -> &mut [T] {
        unsafe {
            slice::from_raw_parts_mut(
                core::ptr::from_mut(self).cast::<T>(),
                NUM_DECOMPOSITION_COLS,
            )
        }
    }
}

impl<T: Copy> DecompositionCols<T> {
    #[inline]
    pub fn acc_inds(&self) -> &[T] {
        &self.inds[..MSG_HASH_FE_LEN]
    }

    #[inline]
    pub fn is_acc<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds().iter().copied().map_into().sum()
    }

    #[inline]
    pub fn is_acc_first_row<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds()[0].into()
    }

    #[inline]
    pub fn is_acc_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds()
            .iter()
            .take(MSG_HASH_FE_LEN - 1)
            .copied()
            .map_into()
            .sum()
    }

    #[inline]
    pub fn is_acc_last_row<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.acc_inds()[MSG_HASH_FE_LEN - 1].into()
    }

    #[inline]
    pub fn decomposition_inds(&self) -> &[T] {
        &self.inds[MSG_HASH_FE_LEN..]
    }

    #[inline]
    pub fn is_decomposition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.decomposition_inds().iter().copied().map_into().sum()
    }

    #[inline]
    pub fn is_decomposition_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.decomposition_inds()
            .iter()
            .take(NUM_MSG_HASH_LIMBS - 1)
            .copied()
            .map_into()
            .sum()
    }

    #[inline]
    pub fn is_first_decomposition_row<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.decomposition_inds().first().copied().unwrap().into()
    }

    #[inline]
    pub fn is_last_decomposition_row<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.decomposition_inds().last().copied().unwrap().into()
    }

    #[inline]
    pub fn value_ms_limb<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.value_ms_limb_bits
            .iter()
            .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + (*bit).into())
    }

    #[inline]
    pub fn decomposed_chunks<AB: AirBuilder>(&self) -> [AB::Expr; LIMB_BITS / CHUNK_SIZE]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| {
            self.decomposition_bits[CHUNK_SIZE * i..][..CHUNK_SIZE]
                .iter()
                .rev()
                .copied()
                .map_into()
                .reduce(|acc, bit| acc.double() + bit)
                .unwrap()
        })
    }
}

impl<T> AlignBorrow<T> for DecompositionCols<T> {
    const NUM_COLS: usize = NUM_DECOMPOSITION_COLS;
}

impl<T> Borrow<DecompositionCols<T>> for [T] {
    #[inline]
    fn borrow(&self) -> &DecompositionCols<T> {
        DecompositionCols::align_borrow(self)
    }
}

impl<T> BorrowMut<DecompositionCols<T>> for [T] {
    #[inline]
    fn borrow_mut(&mut self) -> &mut DecompositionCols<T> {
        DecompositionCols::align_borrow_mut(self)
    }
}
