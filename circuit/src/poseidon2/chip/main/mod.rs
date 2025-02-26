use crate::{
    poseidon2::{F, chip::HashSigAggAir, hash_sig::VerificationTrace},
    util::chip::Chip,
};
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

pub use air::*;
pub use column::*;
pub use generation::*;

pub const fn main_public_values() -> Vec<F> {
    Vec::new()
}

pub struct MainChip<'a> {
    extra_capacity_bits: usize,
    traces: &'a [VerificationTrace],
}

impl<'a> MainChip<'a> {
    pub const fn new(extra_capacity_bits: usize, traces: &'a [VerificationTrace]) -> Self {
        Self {
            extra_capacity_bits,
            traces,
        }
    }
}

impl Chip<F> for MainChip<'_> {
    type Air = HashSigAggAir;
    type Interaction = ();

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::Main(Default::default())
    }

    fn trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn generate_trace(&self, (): &Self::Interaction) -> RowMajorMatrix<F> {
        generate_trace(self.extra_capacity_bits, self.traces)
    }
}
