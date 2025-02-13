use crate::{
    poseidon2::{
        chip::chain::{
            column::{ChainCols, NUM_CHAIN_COLS},
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
            MAX_CHAIN_STEP_DIFF_BITS,
        },
        hash_sig::{VerificationTrace, CHUNK_SIZE, NUM_CHUNKS, TARGET_SUM},
        GenericPoseidon2LinearLayersHorizon, F, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE,
        SBOX_REGISTERS,
    },
    util::{MaybeUninitField, MaybeUninitFieldSlice},
};
use core::{iter::zip, mem::MaybeUninit};
use itertools::Itertools;
use openvm_stark_backend::{
    p3_field::{Field, FieldAlgebra},
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};
use p3_poseidon2_util::air::generate_trace_rows_for_perm;

const MAX_X_I: u32 = (1 << CHUNK_SIZE) - 1;

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
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
            rows.par_chunks_mut(TARGET_SUM as usize)
                .zip(traces)
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
    rows.par_iter_mut()
        .zip(trace.chain_inputs)
        .enumerate()
        .for_each(|(sig_step, (row, input))| {
            row.is_active.populate(true);
            row.sig_idx.write_usize(sig_idx);
            row.sig_step.populate(sig_step);
            generate_trace_rows_for_perm::<
                F,
                GenericPoseidon2LinearLayersHorizon<F, WIDTH>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(&mut row.perm, input, &RC16);
        });
    let mut rows = rows.iter_mut();
    let chain_mid_indices = zip(0.., trace.x)
        .filter_map(|(i, x_i)| (x_i != MAX_X_I as u16).then_some(i))
        .chain([NUM_CHUNKS as u32])
        .collect_vec();
    chain_mid_indices.iter().tuple_windows().fold(
        chain_mid_indices[0] * MAX_X_I,
        |mut sum, (&i, &next_i)| {
            let x_i = trace.x[i as usize] as u32;
            let i_diff = next_i - i;
            sum += x_i;
            zip(x_i..MAX_X_I, rows.by_ref()).for_each(|(chain_step, row)| {
                row.chain_idx.write_u32(i);
                row.chain_idx_is_zero.populate(F::from_canonical_u32(i));
                row.chain_idx_diff_bits.fill_from_iter(
                    (0..MAX_CHAIN_STEP_DIFF_BITS).map(|idx| F::from_bool((i_diff >> idx) & 1 == 1)),
                );
                row.chain_idx_diff_inv.write_f(match i_diff {
                    1 => F::ONE,
                    2 => F::ONE.halve(),
                    _ => F::from_canonical_u32(i_diff).inverse(),
                });
                row.chain_step_bits.fill_from_iter(
                    (0..CHUNK_SIZE).map(|idx| F::from_bool((chain_step >> idx) & 1 == 1)),
                );
                row.is_x_i.write_bool(chain_step == x_i);
                row.sum.write_u32(sum);
            });
            sum + (next_i - i - 1) * MAX_X_I
        },
    );
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
    row.chain_idx.write_zero();
    row.chain_idx_is_zero.populate(F::ZERO);
    row.chain_idx_diff_bits.fill_zero();
    row.chain_idx_diff_inv.write_zero();
    row.chain_step_bits.fill_zero();
    row.is_x_i.write_zero();
    row.sum.write_zero();
    generate_trace_rows_for_perm::<
        F,
        GenericPoseidon2LinearLayersHorizon<F, WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(&mut row.perm, Default::default(), &RC16);
}
