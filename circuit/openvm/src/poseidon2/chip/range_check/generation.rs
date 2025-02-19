use crate::{
    poseidon2::{
        chip::{
            decomposition::LIMB_BITS,
            range_check::column::{RangeCheckCols, NUM_RANGE_CHECK_COLS},
        },
        F,
    },
    util::{field::MaybeUninitField, par_zip},
};
use core::mem::MaybeUninit;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_maybe_rayon::prelude::*;

pub const fn trace_height() -> usize {
    1 << LIMB_BITS
}

pub fn generate_trace_rows(extra_capacity_bits: usize, mult: Vec<u32>) -> RowMajorMatrix<F> {
    let height = 1 << LIMB_BITS;
    let size = height * NUM_RANGE_CHECK_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_RANGE_CHECK_COLS);

    let (prefix, rows, suffix) = unsafe {
        trace
            .values
            .align_to_mut::<RangeCheckCols<MaybeUninit<F>>>()
    };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    par_zip!(rows, mult)
        .enumerate()
        .for_each(|(idx, (row, mult))| {
            row.value.write_usize(idx);
            row.mult.write_u32(mult);
        });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_RANGE_CHECK_COLS)
}
