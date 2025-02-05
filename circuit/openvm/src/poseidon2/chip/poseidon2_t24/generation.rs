use crate::poseidon2::{
    F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE, SBOX_REGISTERS,
    chip::poseidon2_t24::{
        PARTIAL_ROUNDS, WIDTH,
        column::{NUM_POSEIDON2_T24_COLS, Poseidon2T24Cols},
    },
    concat_array,
    hash_sig::{
        LOG_LIFETIME, PublicKey, SPONGE_CAPACITY_VALUES, SPONGE_INPUT_SIZE, SPONGE_PERM,
        SPONGE_RATE, TH_HASH_FE_LEN, encode_tweak_merkle_tree,
    },
};
use core::{
    array::from_fn,
    iter::{repeat, zip},
};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};
use p3_poseidon2_util::air::generate_trace_rows_for_perm;
use std::mem::MaybeUninit;

const MERKLE_ROWS: usize = SPONGE_PERM + LOG_LIFETIME;

pub fn trace_height(
    msg_hash_inputs: &[[F; 22]],
    merkle_inputs: &[(
        PublicKey,
        [F; SPONGE_INPUT_SIZE],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )],
) -> usize {
    (merkle_inputs.len() * MERKLE_ROWS + msg_hash_inputs.len()).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
    msg_hash_inputs: Vec<[F; 22]>,
    merkle_inputs: Vec<(
        PublicKey,
        [F; SPONGE_INPUT_SIZE],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )>,
) -> RowMajorMatrix<F> {
    let height = trace_height(&msg_hash_inputs, &merkle_inputs);
    let size = height * NUM_POSEIDON2_T24_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_POSEIDON2_T24_COLS);

    let (prefix, rows, suffix) = unsafe {
        trace
            .values
            .align_to_mut::<Poseidon2T24Cols<MaybeUninit<F>>>()
    };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (merkle_rows, msg_hash_rows) = rows.split_at_mut(merkle_inputs.len() * MERKLE_ROWS);
    rayon::join(
        || {
            merkle_rows
                .par_chunks_mut(MERKLE_ROWS)
                .zip(merkle_inputs)
                .for_each(|(rows, (pk, leaf, siblings))| {
                    let mut input = from_fn(|i| {
                        i.checked_sub(SPONGE_RATE)
                            .map(|i| SPONGE_CAPACITY_VALUES[i])
                            .unwrap_or_default()
                    });
                    let (leaf_rows, path_rows) = rows.split_at_mut(SPONGE_PERM);
                    leaf_rows
                        .iter_mut()
                        .zip(leaf.chunks(SPONGE_RATE))
                        .enumerate()
                        .for_each(|(leaf_block_step, (row, leaf_block))| {
                            row.is_msg.write(F::ZERO);
                            row.is_merkle_leaf.write(F::ONE);
                            row.is_merkle_leaf_transition
                                .write(F::from_bool(leaf_block_step != SPONGE_PERM - 1));
                            row.is_merkle_path.write(F::ZERO);
                            row.is_merkle_path_transition.write(F::ZERO);
                            zip(&mut row.root, pk.merkle_root).for_each(|(cell, value)| {
                                cell.write(value);
                            });
                            row.leaf_block_step
                                .write(F::from_canonical_usize(leaf_block_step));
                            row.is_last_leaf_block_step.populate(
                                F::from_canonical_usize(leaf_block_step),
                                F::from_canonical_usize(SPONGE_PERM - 1),
                            );
                            zip(
                                &mut input,
                                zip(
                                    &mut row.leaf_block,
                                    leaf_block.iter().chain(repeat(&F::ZERO)),
                                ),
                            )
                            .for_each(|(state, (cell, value))| {
                                *state += *value;
                                cell.write(*value);
                            });
                            row.level.write(F::ZERO);
                            row.is_last_level
                                .populate(F::ZERO, F::from_canonical_usize(LOG_LIFETIME - 1));
                            row.epoch_dec.write(F::ZERO);
                            row.is_right.write(F::ZERO);
                            generate_trace_rows_for_perm::<
                                F,
                                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                                WIDTH,
                                SBOX_DEGREE,
                                SBOX_REGISTERS,
                                HALF_FULL_ROUNDS,
                                PARTIAL_ROUNDS,
                            >(&mut row.perm, input, &RC24);
                            input = from_fn(|i| unsafe {
                                row.perm.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i]
                                    .assume_init()
                            })
                        });
                    let leaf_hash = from_fn(|i| input[i]);
                    let mut epoch_dec = epoch;
                    zip(path_rows, siblings).enumerate().fold(
                        leaf_hash,
                        |node, (level, (row, sibling))| {
                            let encoded_tweak =
                                encode_tweak_merkle_tree(level as u32 + 1, epoch_dec >> 1);
                            let mut left_right = [node, sibling];
                            let is_right = epoch_dec & 1 == 1;
                            if is_right {
                                left_right.swap(0, 1);
                            }
                            row.is_msg.write(F::ZERO);
                            row.is_merkle_leaf.write(F::ZERO);
                            row.is_merkle_leaf_transition.write(F::ZERO);
                            row.is_merkle_path.write(F::ONE);
                            row.is_merkle_path_transition
                                .write(F::from_bool(level != LOG_LIFETIME - 1));
                            zip(&mut row.root, pk.merkle_root).for_each(|(cell, value)| {
                                cell.write(value);
                            });
                            row.leaf_block_step.write(F::ZERO);
                            row.is_last_leaf_block_step
                                .populate(F::ZERO, F::from_canonical_usize(SPONGE_PERM - 1));
                            row.leaf_block.iter_mut().for_each(|cell| {
                                cell.write(F::ZERO);
                            });
                            row.level.write(F::from_canonical_usize(level));
                            row.is_last_level.populate(
                                F::from_canonical_usize(level),
                                F::from_canonical_usize(LOG_LIFETIME - 1),
                            );
                            row.epoch_dec.write(F::from_canonical_u32(epoch_dec));
                            row.is_right.write(F::from_bool(is_right));
                            let input = concat_array![
                                pk.parameter,
                                encoded_tweak,
                                left_right[0],
                                left_right[1]
                            ];
                            generate_trace_rows_for_perm::<
                                F,
                                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                                WIDTH,
                                SBOX_DEGREE,
                                SBOX_REGISTERS,
                                HALF_FULL_ROUNDS,
                                PARTIAL_ROUNDS,
                            >(&mut row.perm, input, &RC24);
                            epoch_dec >>= 1;
                            from_fn(|i| unsafe {
                                row.perm.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i]
                                    .assume_init()
                                    + input[i]
                            })
                        },
                    );
                })
        },
        || {
            msg_hash_rows
                .par_iter_mut()
                .enumerate()
                .for_each(|(idx, row)| {
                    let input = msg_hash_inputs
                        .get(idx)
                        .map(|msg_hash_input| {
                            from_fn(|i| msg_hash_input.get(i).copied().unwrap_or_default())
                        })
                        .unwrap_or_default();
                    row.is_msg
                        .write(F::from_bool(msg_hash_inputs.get(idx).is_some()));
                    row.is_merkle_leaf.write(F::ZERO);
                    row.is_merkle_leaf_transition.write(F::ZERO);
                    row.is_merkle_path.write(F::ZERO);
                    row.is_merkle_path_transition.write(F::ZERO);
                    row.root.iter_mut().for_each(|cell| {
                        cell.write(F::ZERO);
                    });
                    row.leaf_block_step.write(F::ZERO);
                    row.is_last_leaf_block_step
                        .populate(F::ZERO, F::from_canonical_usize(SPONGE_PERM - 1));
                    row.leaf_block.iter_mut().for_each(|cell| {
                        cell.write(F::ZERO);
                    });
                    row.level.write(F::ZERO);
                    row.is_last_level
                        .populate(F::ZERO, F::from_canonical_usize(LOG_LIFETIME - 1));
                    row.epoch_dec.write(F::ZERO);
                    row.is_right.write(F::ZERO);
                    generate_trace_rows_for_perm::<
                        F,
                        GenericPoseidon2LinearLayersHorizon<WIDTH>,
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >(&mut row.perm, input, &RC24);
                })
        },
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_POSEIDON2_T24_COLS)
}
