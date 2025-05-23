use crate::{
    air::{
        decomposition::{
            F_MS_LIMB, F_MS_LIMB_BITS, F_MS_LIMB_LEADING_ONES, F_MS_LIMB_TRAILING_ZEROS, LIMB_BITS,
            LIMB_MASK, NUM_LIMBS, NUM_MSG_HASH_LIMBS,
            column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
        },
        range_check::RangeCheckInteraction,
    },
    hash_sig::{CHUNK_SIZE, F, MSG_HASH_FE_LEN, VerificationTrace},
    util::{
        field::{MaybeUninitField, MaybeUninitFieldSlice},
        par_zip,
    },
};
use core::{array::from_fn, mem::MaybeUninit};
use itertools::Itertools;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_maybe_rayon::prelude::*;

const MAX_X_I: u32 = (1 << CHUNK_SIZE) - 1;

const NUM_ROWS_PER_SIG: usize = MSG_HASH_FE_LEN + NUM_MSG_HASH_LIMBS;

pub const fn trace_height(traces: &[VerificationTrace]) -> usize {
    (NUM_ROWS_PER_SIG * traces.len()).next_power_of_two()
}

pub fn generate_trace(
    extra_capacity_bits: usize,
    traces: &[VerificationTrace],
    range_check_mult: &RangeCheckInteraction,
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_DECOMPOSITION_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_DECOMPOSITION_COLS);

    let (prefix, rows, suffix) = unsafe {
        trace
            .values
            .align_to_mut::<DecompositionCols<MaybeUninit<_>>>()
    };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (msg_hash_rows, padding_rows) = rows.split_at_mut(NUM_ROWS_PER_SIG * traces.len());

    join(
        || {
            par_zip!(msg_hash_rows.par_chunks_mut(NUM_ROWS_PER_SIG), traces)
                .enumerate()
                .for_each(|(sig_idx, (rows, trace))| {
                    let values = from_fn(|i| trace.msg_hash[MSG_HASH_FE_LEN - 1 - i]); // FIXME: Use little-endian when #9 is resolved.
                    let mut acc_limbs = Default::default();
                    let (acc_rows, decomposition_rows) = rows.split_at_mut(MSG_HASH_FE_LEN);
                    acc_rows.iter_mut().enumerate().for_each(|(step, row)| {
                        generate_acc_row(
                            row,
                            sig_idx,
                            &mut acc_limbs,
                            values,
                            step,
                            range_check_mult,
                        );
                    });
                    let sums = trace
                        .x
                        .chunks(LIMB_BITS / CHUNK_SIZE)
                        .scan(0u32, |sum, x| {
                            *sum += u32::from(x.iter().copied().sum::<u16>());
                            Some(*sum)
                        })
                        .collect_vec();
                    par_zip!(decomposition_rows, sums).enumerate().for_each(
                        |(step, (row, sum))| {
                            generate_decomposition_row(row, sig_idx, &acc_limbs, sum, step);
                        },
                    );
                });
        },
        || generate_padding_rows(padding_rows),
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_DECOMPOSITION_COLS)
}

#[inline]
fn generate_acc_row(
    row: &mut DecompositionCols<MaybeUninit<F>>,
    sig_idx: usize,
    acc_limbs: &mut [u32; NUM_MSG_HASH_LIMBS],
    values: [F; MSG_HASH_FE_LEN],
    step: usize,
    range_check_mult: &RangeCheckInteraction,
) {
    let value = values[MSG_HASH_FE_LEN - 1 - step].as_canonical_u32();
    let value_limbs: [_; NUM_LIMBS] = from_fn(|i| (value >> (i * LIMB_BITS)) & LIMB_MASK);
    let value_ms_limb = value_limbs[NUM_LIMBS - 1];
    let value_ms_limb_bits: [_; F_MS_LIMB_BITS] = from_fn(|i| (value_ms_limb >> i) & 1 == 1);
    let mut carries = [0; NUM_MSG_HASH_LIMBS - 1];
    *acc_limbs = from_fn(|i| {
        let sum = if i == 0 {
            acc_limbs[i] + value_limbs[i]
        } else if i < NUM_LIMBS - 1 {
            acc_limbs[i] + value_limbs[i] + carries[i - 1]
        } else if i < NUM_LIMBS {
            acc_limbs[i - (NUM_LIMBS - 1)] * F_MS_LIMB
                + acc_limbs[i]
                + value_limbs[i]
                + carries[i - 1]
        } else {
            acc_limbs[i - (NUM_LIMBS - 1)] * F_MS_LIMB + acc_limbs[i] + carries[i - 1]
        };
        if i < NUM_MSG_HASH_LIMBS - 1 {
            carries[i] = sum >> LIMB_BITS;
        }
        sum & LIMB_MASK
    });
    value_limbs
        .into_iter()
        .take(NUM_LIMBS - 1)
        .chain(*acc_limbs)
        .chain(carries)
        .for_each(|value| range_check_mult.send(value as usize));
    let value_ls_limbs: [_; NUM_LIMBS - 1] = from_fn(|i| F::from_u32(value_limbs[i]));
    row.sig_idx.write_usize(sig_idx);
    row.inds.populate(Some(step));
    row.values.fill_from_slice(&values);
    row.value_ls_limbs.fill_from_slice(&value_ls_limbs);
    row.value_ms_limb_bits
        .fill_from_iter(value_ms_limb_bits.map(F::from_bool));
    row.value_limb_0_is_zero.populate(value_ls_limbs[0]);
    row.value_limb_1_is_zero.populate(value_ls_limbs[1]);
    row.is_ms_limb_max.populate(
        F::from_u32((value_ms_limb >> F_MS_LIMB_TRAILING_ZEROS).count_ones()),
        F::from_u32(F_MS_LIMB_LEADING_ONES),
    );
    row.acc_limbs.fill_from_iter(acc_limbs.map(F::from_u32));
    row.carries.fill_from_iter(carries.map(F::from_u32));

    row.decomposition_bits.fill_zero();
    row.is_send_chain.fill_zero();
    row.sum.write_zero();
}

#[inline]
fn generate_decomposition_row(
    row: &mut DecompositionCols<MaybeUninit<F>>,
    sig_idx: usize,
    acc_limbs: &[u32; NUM_MSG_HASH_LIMBS],
    sum: u32,
    step: usize,
) {
    row.sig_idx.write_usize(sig_idx);
    row.inds.populate(Some(MSG_HASH_FE_LEN + step));
    row.acc_limbs.fill_from_iter(acc_limbs.map(F::from_u32));
    row.decomposition_bits
        .fill_from_iter((0..LIMB_BITS).map(|i| F::from_bool((acc_limbs[step] >> i) & 1 == 1)));
    row.is_send_chain.fill_from_iter(
        (0..LIMB_BITS)
            .step_by(CHUNK_SIZE)
            .map(|i| F::from_bool((acc_limbs[step] >> i) & MAX_X_I != MAX_X_I)),
    );
    row.sum.write_u32(sum);

    row.values.fill_zero();
    row.value_ls_limbs.fill_zero();
    row.value_ms_limb_bits.fill_zero();
    row.value_limb_0_is_zero.populate(F::ZERO);
    row.value_limb_1_is_zero.populate(F::ZERO);
    row.is_ms_limb_max
        .populate(F::ZERO, F::from_u32(F_MS_LIMB_LEADING_ONES));
    row.carries.fill_zero();
}

#[inline]
fn generate_padding_rows(rows: &mut [DecompositionCols<MaybeUninit<F>>]) {
    if let Some((template, rows)) = rows.split_first_mut() {
        generate_padding_row(template);
        let template = template.as_slice();
        rows.par_iter_mut()
            .for_each(|row| row.as_slice_mut().copy_from_slice(template));
    }
}

#[inline]
fn generate_padding_row(row: &mut DecompositionCols<MaybeUninit<F>>) {
    row.sig_idx.write_zero();
    row.inds.populate(None);
    row.values.fill_zero();
    row.value_ls_limbs.fill_zero();
    row.value_ms_limb_bits.fill_zero();
    row.value_limb_0_is_zero.populate(F::ZERO);
    row.value_limb_1_is_zero.populate(F::ZERO);
    row.is_ms_limb_max
        .populate(F::ZERO, F::from_u32(F_MS_LIMB_LEADING_ONES));
    row.acc_limbs.fill_zero();
    row.carries.fill_zero();
    row.decomposition_bits.fill_zero();
    row.is_send_chain.fill_zero();
    row.sum.write_zero();
}
