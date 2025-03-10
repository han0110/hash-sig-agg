use crate::RoundConstants;
use p3_field::Field;

mod generation;

pub use generation::generate_trace_rows_for_perm;
pub use p3_poseidon2_air::{num_cols, Poseidon2Air, Poseidon2Cols};

impl<F: Field, const WIDTH: usize, const HALF_FULL_ROUNDS: usize, const PARTIAL_ROUNDS: usize>
    From<RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>>
    for p3_poseidon2_air::RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>
{
    #[inline]
    fn from(value: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>) -> Self {
        Self::new(
            value.beginning_full_round_constants,
            value.partial_round_constants,
            value.ending_full_round_constants,
        )
    }
}

#[inline]
pub fn outputs<
    T,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    cols: &Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
) -> &[T; WIDTH] {
    &cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
}
