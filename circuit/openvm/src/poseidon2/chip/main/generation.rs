use crate::{
    poseidon2::{
        chip::main::column::{MainCols, NUM_MAIN_COLS},
        hash_sig::VerificationTrace,
        F,
    },
    util::{MaybeUninitField, MaybeUninitFieldSlice},
};
use core::mem::MaybeUninit;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_maybe_rayon::prelude::*;

pub const fn trace_height(traces: &[VerificationTrace]) -> usize {
    traces.len().next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_MAIN_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_MAIN_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<MainCols<MaybeUninit<_>>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    rows.par_iter_mut().enumerate().for_each(|(sig_idx, row)| {
        if let Some(trace) = traces.get(sig_idx) {
            row.is_active.populate(true);
            row.sig_idx.write_usize(sig_idx);
            row.parameter.fill_from_slice(&trace.pk.parameter);
            row.merkle_root.fill_from_slice(&trace.pk.merkle_root);
            row.msg_hash.fill_from_slice(&trace.msg_hash);
        } else {
            row.is_active.populate(false);
            row.sig_idx.write_zero();
            row.parameter.fill_zero();
            row.merkle_root.fill_zero();
            row.msg_hash.fill_zero();
        }
    });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_MAIN_COLS)
}
