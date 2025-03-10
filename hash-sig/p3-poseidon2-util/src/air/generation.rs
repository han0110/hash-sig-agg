//! Copied from https://github.com/Plonky3/Plonky3/blob/main/poseidon2-air/src/generation.rs
//! to expose `generate_trace_rows_for_perm`.

use crate::air::RoundConstants;
use core::mem::MaybeUninit;
use p3_field::PrimeField;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{FullRound, PartialRound, Poseidon2Cols, SBox};

pub fn generate_trace_rows_for_perm<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    perm: &mut Poseidon2Cols<
        MaybeUninit<F>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    mut state: [F; WIDTH],
    constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
) {
    perm.export.write(F::ONE);
    perm.inputs
        .iter_mut()
        .zip(state.iter())
        .for_each(|(input, &x)| {
            input.write(x);
        });

    LinearLayers::external_linear_layer(&mut state);

    for (full_round, constants) in perm
        .beginning_full_rounds
        .iter_mut()
        .zip(&constants.beginning_full_round_constants)
    {
        generate_full_round::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state, full_round, constants,
        );
    }

    for (partial_round, constant) in perm
        .partial_rounds
        .iter_mut()
        .zip(&constants.partial_round_constants)
    {
        generate_partial_round::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            partial_round,
            *constant,
        );
    }

    for (full_round, constants) in perm
        .ending_full_rounds
        .iter_mut()
        .zip(&constants.ending_full_round_constants)
    {
        generate_full_round::<F, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state, full_round, constants,
        );
    }
}

#[inline]
fn generate_full_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [F; WIDTH],
    full_round: &mut FullRound<MaybeUninit<F>, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constants: &[F; WIDTH],
) {
    for (state_i, const_i) in state.iter_mut().zip(round_constants) {
        *state_i += *const_i;
    }
    for (state_i, sbox_i) in state.iter_mut().zip(full_round.sbox.iter_mut()) {
        generate_sbox(sbox_i, state_i);
    }
    LinearLayers::external_linear_layer(state);
    full_round
        .post
        .iter_mut()
        .zip(*state)
        .for_each(|(post, x)| {
            post.write(x);
        });
}

#[inline]
fn generate_partial_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [F; WIDTH],
    partial_round: &mut PartialRound<MaybeUninit<F>, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constant: F,
) {
    state[0] += round_constant;
    generate_sbox(&mut partial_round.sbox, &mut state[0]);
    partial_round.post_sbox.write(state[0]);
    LinearLayers::internal_linear_layer(state);
}

#[inline]
fn generate_sbox<F: PrimeField, const DEGREE: u64, const REGISTERS: usize>(
    sbox: &mut SBox<MaybeUninit<F>, DEGREE, REGISTERS>,
    x: &mut F,
) {
    *x = match (DEGREE, REGISTERS) {
        (3, 0) => x.cube(),
        (5, 0) => x.exp_const_u64::<5>(),
        (7, 0) => x.exp_const_u64::<7>(),
        (5, 1) => {
            let x2 = x.square();
            let x3 = x2 * *x;
            sbox.0[0].write(x3);
            x3 * x2
        }
        (7, 1) => {
            let x3 = x.cube();
            sbox.0[0].write(x3);
            x3 * x3 * *x
        }
        (11, 2) => {
            let x2 = x.square();
            let x3 = x2 * *x;
            let x9 = x3.cube();
            sbox.0[0].write(x3);
            sbox.0[1].write(x9);
            x9 * x2
        }
        _ => panic!("Unexpected (DEGREE, REGISTERS) of ({DEGREE}, {REGISTERS})"),
    }
}
