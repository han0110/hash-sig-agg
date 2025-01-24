use p3_field::Field;

mod generation;

pub use generation::generate_trace_rows_for_perm;
pub use p3_poseidon2_air::{num_cols, Poseidon2Air, Poseidon2Cols};

#[derive(Debug, Clone)]
pub struct RoundConstants<
    F,
    const WIDTH: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    pub beginning_full_round_constants: [[F; WIDTH]; HALF_FULL_ROUNDS],
    pub partial_round_constants: [F; PARTIAL_ROUNDS],
    pub ending_full_round_constants: [[F; WIDTH]; HALF_FULL_ROUNDS],
}

impl<F: Field, const WIDTH: usize, const HALF_FULL_ROUNDS: usize, const PARTIAL_ROUNDS: usize>
    From<RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>>
    for p3_poseidon2_air::RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>
{
    fn from(value: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>) -> Self {
        Self::new(
            value.beginning_full_round_constants,
            value.partial_round_constants,
            value.ending_full_round_constants,
        )
    }
}
