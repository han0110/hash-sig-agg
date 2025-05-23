use crate::{
    air::{
        decomposition::LIMB_BITS,
        range_check::{
            RangeCheckInteraction,
            column::{NUM_RANGE_CHECK_COLS, RangeCheckCols},
        },
    },
    hash_sig::F,
    util::{field::MaybeUninitField, par_zip},
};
use core::{mem::MaybeUninit, sync::atomic::Ordering};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_maybe_rayon::prelude::*;

pub const fn trace_height() -> usize {
    1 << LIMB_BITS
}

pub fn generate_trace(
    extra_capacity_bits: usize,
    mult: &RangeCheckInteraction,
) -> RowMajorMatrix<F> {
    let height = trace_height();
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

    par_zip!(rows, &mult.0)
        .enumerate()
        .for_each(|(idx, (row, mult))| {
            row.value.write_usize(idx);
            row.mult.write_u32(mult.load(Ordering::Relaxed));
        });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_RANGE_CHECK_COLS)
}
