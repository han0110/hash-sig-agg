use crate::{
    poseidon2::{
        F,
        chip::HashSigAggAir,
        hash_sig::{NUM_CHUNKS, VerificationTrace},
    },
    util::chip::Chip,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

mod poseidon2 {
    pub const WIDTH: usize = 16;
    pub const PARTIAL_ROUNDS: usize = crate::poseidon2::partial_round::<WIDTH>();
}

const MAX_CHAIN_STEP_DIFF_BITS: usize = (NUM_CHUNKS / 2).next_power_of_two().ilog2() as usize;

pub use air::*;
pub use column::*;
pub use generation::*;

pub struct ChainChip<'a> {
    extra_capacity_bits: usize,
    epoch: u32,
    traces: &'a [VerificationTrace],
}

impl<'a> ChainChip<'a> {
    pub const fn new(
        extra_capacity_bits: usize,
        epoch: u32,
        traces: &'a [VerificationTrace],
    ) -> Self {
        Self {
            extra_capacity_bits,
            epoch,
            traces,
        }
    }
}

impl Chip<F> for ChainChip<'_> {
    type Air = HashSigAggAir;
    type Interaction = ();

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::Chain(Default::default())
    }

    fn public_values(&self) -> Vec<F> {
        vec![F::from_u32(self.epoch << 2)]
    }

    fn trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn generate_trace(&self, (): &Self::Interaction) -> RowMajorMatrix<F> {
        generate_trace(self.extra_capacity_bits, self.traces)
    }
}
