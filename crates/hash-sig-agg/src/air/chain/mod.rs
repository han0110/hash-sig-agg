use crate::{
    air::{HashSigAggAir, HashSigAggInteraction, chain::generation::generate_trace},
    hash_sig::{F, NUM_CHUNKS, VerificationTrace},
    util::air_instance::AirInstance,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

mod poseidon2 {
    pub const WIDTH: usize = 16;
    pub const PARTIAL_ROUNDS: usize = crate::hash_sig::partial_round::<WIDTH>();
}

const MAX_CHAIN_STEP_DIFF_BITS: usize = (NUM_CHUNKS / 2).next_power_of_two().ilog2() as usize;

pub use air::*;
pub use column::*;

pub(super) struct ChainAirInstance<'a> {
    epoch: u32,
    traces: &'a [VerificationTrace],
}

impl<'a> ChainAirInstance<'a> {
    pub const fn new(epoch: u32, traces: &'a [VerificationTrace]) -> Self {
        Self { epoch, traces }
    }
}

impl AirInstance<F> for ChainAirInstance<'_> {
    type Air = HashSigAggAir;
    type Interaction = HashSigAggInteraction;

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::Chain(Default::default())
    }

    fn public_values(&self) -> Vec<F> {
        vec![F::from_u32(self.epoch << 2)]
    }

    fn generate_trace(
        &self,
        extra_capacity_bits: usize,
        _: &Self::Interaction,
    ) -> RowMajorMatrix<F> {
        generate_trace(extra_capacity_bits, self.traces)
    }
}
