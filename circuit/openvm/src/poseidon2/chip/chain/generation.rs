use crate::{
    poseidon2::{
        chip::chain::{
            column::{ChainCols, NUM_CHAIN_COLS},
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
        },
        hash_sig::{VerificationTrace, CHUNK_SIZE, NUM_CHUNKS, TARGET_SUM},
        Poseidon2LinearLayers, F, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE, SBOX_REGISTERS,
    },
    util::{
        field::{MaybeUninitField, MaybeUninitFieldSlice},
        par_zip, zip,
    },
};
use core::mem::MaybeUninit;
use itertools::Itertools;
use p3_field::FieldAlgebra;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_maybe_rayon::prelude::*;
use p3_poseidon2_util::air::generate_trace_rows_for_perm;

const MAX_X_I: u32 = (1 << CHUNK_SIZE) - 1;

pub const fn trace_height(traces: &[VerificationTrace]) -> usize {
    (traces.len() * TARGET_SUM as usize).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_CHAIN_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_CHAIN_COLS);

    let (prefix, rows, suffix) =
        unsafe { trace.values.align_to_mut::<ChainCols<MaybeUninit<F>>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (rows, padding_rows) = rows.split_at_mut(traces.len() * TARGET_SUM as usize);

    join(
        || {
            par_zip!(rows.par_chunks_mut(TARGET_SUM as _), traces)
                .enumerate()
                .for_each(|(sig_idx, (rows, trace))| generate_trace_rows_sig(rows, sig_idx, trace));
        },
        || generate_trace_rows_padding(padding_rows),
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_CHAIN_COLS)
}

#[inline]
pub fn generate_trace_rows_sig(
    rows: &mut [ChainCols<MaybeUninit<F>>],
    sig_idx: usize,
    trace: &VerificationTrace,
) {
    par_zip!(&mut *rows, trace.chain_inputs)
        .enumerate()
        .for_each(|(sig_step, (row, input))| {
            row.is_active.populate(true);
            row.sig_idx.write_usize(sig_idx);
            row.sig_step.populate(sig_step);
            generate_trace_rows_for_perm::<
                F,
                Poseidon2LinearLayers<WIDTH>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(&mut row.perm, input, &RC16);
        });
    let mut rows = rows.iter_mut();
    let chain_mid_indices = zip!(0..NUM_CHUNKS as u32, trace.x)
        .filter_map(|(i, x_i)| (x_i != MAX_X_I as u16).then_some(i));
    chain_mid_indices
        .chain([NUM_CHUNKS as _])
        .tuple_windows()
        .for_each(|(i, i_next)| {
            let x_i = u32::from(trace.x[i as usize]);
            zip!(x_i..MAX_X_I, rows.by_ref().take((MAX_X_I - x_i) as usize)).for_each(
                |(chain_step, row)| {
                    row.chain_idx.populate(i, i_next);
                    row.chain_step_bits.fill_from_iter(
                        (0..CHUNK_SIZE).map(|idx| F::from_bool((chain_step >> idx) & 1 == 1)),
                    );
                    row.is_x_i.write_bool(chain_step == x_i);
                },
            );
        });
    debug_assert!(rows.next().is_none());
}

#[inline]
pub fn generate_trace_rows_padding(rows: &mut [ChainCols<MaybeUninit<F>>]) {
    if let Some((template, rows)) = rows.split_first_mut() {
        generate_trace_row_padding(template);
        let template = template.as_slice();
        rows.par_iter_mut()
            .for_each(|row| row.as_slice_mut().copy_from_slice(template));
    }
}

#[inline]
pub fn generate_trace_row_padding(row: &mut ChainCols<MaybeUninit<F>>) {
    row.is_active.populate(false);
    row.sig_idx.write_zero();
    row.sig_step.populate(0);
    row.chain_idx.populate_padding();
    row.chain_step_bits.fill_zero();
    row.is_x_i.write_zero();
    generate_trace_rows_for_perm::<
        F,
        Poseidon2LinearLayers<WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(&mut row.perm, Default::default(), &RC16);
}
