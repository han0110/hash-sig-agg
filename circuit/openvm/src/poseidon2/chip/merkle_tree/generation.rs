use crate::{
    poseidon2::{
        chip::merkle_tree::{
            column::{MerkleTreeCols, NUM_MERKLE_TREE_COLS},
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
        },
        hash_sig::{
            encode_tweak_merkle_tree, VerificationTrace, CHUNK_SIZE, HASH_FE_LEN, LOG_LIFETIME,
            MSG_FE_LEN, SPONGE_CAPACITY_VALUES, SPONGE_PERM, SPONGE_RATE,
        },
        Poseidon2LinearLayers, F, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE, SBOX_REGISTERS,
    },
    util::{concat_array, par_zip, zip, MaybeUninitField, MaybeUninitFieldSlice},
};
use core::{array::from_fn, iter, mem::MaybeUninit};
use p3_field::FieldAlgebra;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_maybe_rayon::prelude::*;
use p3_poseidon2_util::air::{generate_trace_rows_for_perm, outputs};

const NUM_ROWS_PER_SIG: usize = 1 + SPONGE_PERM + LOG_LIFETIME;

pub const fn trace_height(traces: &[VerificationTrace]) -> usize {
    (traces.len() * NUM_ROWS_PER_SIG).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
    encoded_msg: [F; MSG_FE_LEN],
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_MERKLE_TREE_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_MERKLE_TREE_COLS);

    let (prefix, rows, suffix) = unsafe {
        trace
            .values
            .align_to_mut::<MerkleTreeCols<MaybeUninit<F>>>()
    };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (rows, padding_rows) = rows.split_at_mut(traces.len() * NUM_ROWS_PER_SIG);

    join(
        || {
            par_zip!(rows.par_chunks_mut(NUM_ROWS_PER_SIG), traces)
                .enumerate()
                .for_each(|(sig_idx, (rows, trace))| {
                    let (msg_row, rows) = rows.split_first_mut().unwrap();
                    let (leaf_rows, path_rows) = rows.split_at_mut(SPONGE_PERM);
                    generate_trace_row_msg(msg_row, epoch, encoded_msg, trace, sig_idx);
                    let leaf_hash = generate_trace_rows_leaf(leaf_rows, epoch, sig_idx, trace);
                    generate_trace_rows_path(path_rows, epoch, sig_idx, trace, leaf_hash);
                });
        },
        || generate_trace_rows_padding(padding_rows),
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_MERKLE_TREE_COLS)
}

#[inline]
fn generate_trace_row_msg(
    row: &mut MerkleTreeCols<MaybeUninit<F>>,
    epoch: u32,
    encoded_msg: [F; MSG_FE_LEN],
    trace: &VerificationTrace,
    sig_idx: usize,
) {
    row.sig_idx.write_usize(sig_idx);
    row.is_msg.write_one();
    row.is_merkle_leaf.write_zero();
    row.is_merkle_leaf_transition.write_zero();
    row.is_merkle_path.write_zero();
    row.is_merkle_path_transition.write_zero();
    row.is_recevie_merkle_tree.fill_zero();
    row.root.fill_from_slice(&trace.pk.merkle_root);
    row.sponge_step.populate(0);
    row.sponge_block.fill_zero();
    row.leaf_chunk_start_ind.fill_zero();
    row.leaf_chunk_idx.write_zero();
    row.level.populate(0);
    row.epoch_dec.write_zero();
    row.is_right.write_zero();
    let input = trace.msg_hash_preimage(epoch, encoded_msg);
    generate_trace_rows_for_perm::<
        F,
        Poseidon2LinearLayers<WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(&mut row.perm, input, &RC24);
}

#[inline]
fn generate_trace_rows_leaf(
    rows: &mut [MerkleTreeCols<MaybeUninit<F>>],
    epoch: u32,
    sig_idx: usize,
    trace: &VerificationTrace,
) -> [F; HASH_FE_LEN] {
    let input = from_fn(|i| {
        i.checked_sub(SPONGE_RATE)
            .map(|i| SPONGE_CAPACITY_VALUES[i])
            .unwrap_or_default()
    });
    let mut is_receive_merkle_tree = iter::empty()
        .chain([false])
        .chain(trace.x.iter().map(|x_i| *x_i != (1 << CHUNK_SIZE) - 1))
        .chain([false]);
    let output = zip!(rows, trace.merkle_tree_leaf(epoch).chunks(SPONGE_RATE))
        .enumerate()
        .fold(input, |mut input, (sponge_step, (row, sponge_block))| {
            zip!(&mut input[..sponge_block.len()], sponge_block)
                .for_each(|(input, block)| *input += *block);
            row.sig_idx.write_usize(sig_idx);
            row.is_msg.write_zero();
            row.is_merkle_leaf.write_one();
            row.is_merkle_leaf_transition
                .write_bool(sponge_step != SPONGE_PERM - 1);
            if (sponge_step * SPONGE_RATE) % HASH_FE_LEN == 0 {
                row.is_recevie_merkle_tree
                    .fill_from_iter(is_receive_merkle_tree.by_ref().take(3).map(F::from_bool));
            } else {
                row.is_recevie_merkle_tree[0].write_zero();
                row.is_recevie_merkle_tree[1..]
                    .fill_from_iter(is_receive_merkle_tree.by_ref().take(2).map(F::from_bool));
            }
            row.is_merkle_path.write_zero();
            row.is_merkle_path_transition.write_zero();
            row.root.fill_from_slice(&trace.pk.merkle_root);
            row.sponge_step.populate(sponge_step);
            row.sponge_block[..sponge_block.len()].fill_from_slice(sponge_block);
            row.sponge_block[sponge_block.len()..].fill_zero();
            row.leaf_chunk_start_ind.fill_from_iter(
                (0..SPONGE_RATE)
                    .map(|idx| F::from_bool((sponge_step * SPONGE_RATE + idx) % HASH_FE_LEN == 0)),
            );
            row.leaf_chunk_idx
                .write_usize((sponge_step * SPONGE_RATE).div_ceil(HASH_FE_LEN));
            row.level.populate(0);
            row.epoch_dec.write_zero();
            row.is_right.write_zero();
            generate_trace_rows_for_perm::<
                F,
                Poseidon2LinearLayers<WIDTH>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(&mut row.perm, input, &RC24);
            unsafe { from_fn(|i| outputs(&row.perm)[i].assume_init()) }
        });
    from_fn(|i| output[i])
}

#[inline]
fn generate_trace_rows_path(
    rows: &mut [MerkleTreeCols<MaybeUninit<F>>],
    epoch: u32,
    sig_idx: usize,
    trace: &VerificationTrace,
    merkle_leaf_hash: [F; HASH_FE_LEN],
) {
    let mut epoch_dec = epoch;
    zip!(rows, trace.sig.merkle_siblings).enumerate().fold(
        merkle_leaf_hash,
        |node, (level, (row, sibling))| {
            let is_right = epoch_dec & 1 == 1;
            row.sig_idx.write_usize(sig_idx);
            row.is_msg.write_zero();
            row.is_merkle_leaf.write_zero();
            row.is_merkle_leaf_transition.write_zero();
            row.is_merkle_path.write_one();
            row.is_merkle_path_transition
                .write_bool(level != LOG_LIFETIME - 1);
            row.is_recevie_merkle_tree.fill_zero();
            row.root.fill_from_slice(&trace.pk.merkle_root);
            row.sponge_step.populate(0);
            row.sponge_block.fill_zero();
            row.leaf_chunk_start_ind.fill_zero();
            row.leaf_chunk_idx.write_zero();
            row.level.populate(level);
            row.epoch_dec.write_u32(epoch_dec);
            row.is_right.write_bool(is_right);
            let mut left_right = [node, sibling];
            if is_right {
                left_right.swap(0, 1);
            }
            let input = concat_array![
                trace.pk.parameter,
                encode_tweak_merkle_tree(level as u32 + 1, epoch_dec >> 1),
                if is_right {
                    [sibling, node].into_iter().flatten()
                } else {
                    [node, sibling].into_iter().flatten()
                }
            ];
            generate_trace_rows_for_perm::<
                F,
                Poseidon2LinearLayers<WIDTH>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(&mut row.perm, input, &RC24);
            epoch_dec >>= 1;
            unsafe { from_fn(|i| input[i] + outputs(&row.perm)[i].assume_init()) }
        },
    );
}

#[inline]
pub fn generate_trace_rows_padding(rows: &mut [MerkleTreeCols<MaybeUninit<F>>]) {
    if let Some((template, rows)) = rows.split_first_mut() {
        generate_trace_row_padding(template);
        let template = template.as_slice();
        rows.par_iter_mut()
            .for_each(|row| row.as_slice_mut().copy_from_slice(template));
    }
}

#[inline]
pub fn generate_trace_row_padding(row: &mut MerkleTreeCols<MaybeUninit<F>>) {
    row.sig_idx.write_zero();
    row.is_msg.write_zero();
    row.is_merkle_leaf.write_zero();
    row.is_merkle_leaf_transition.write_zero();
    row.is_merkle_path.write_zero();
    row.is_merkle_path_transition.write_zero();
    row.is_recevie_merkle_tree.fill_zero();
    row.root.fill_zero();
    row.sponge_step.populate(0);
    row.sponge_block.fill_zero();
    row.leaf_chunk_start_ind.fill_zero();
    row.leaf_chunk_idx.write_zero();
    row.level.populate(0);
    row.epoch_dec.write_zero();
    row.is_right.write_zero();
    generate_trace_rows_for_perm::<
        F,
        Poseidon2LinearLayers<WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(&mut row.perm, Default::default(), &RC24);
}
