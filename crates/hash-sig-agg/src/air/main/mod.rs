use crate::{
    air::{HashSigAggAir, HashSigAggInteraction, main::generation::generate_trace},
    hash_sig::{F, VerificationTrace},
    util::air_instance::AirInstance,
};
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

pub use air::*;
pub use column::*;

pub const fn main_public_values() -> Vec<F> {
    Vec::new()
}

pub(super) struct MainAirInstance<'a> {
    traces: &'a [VerificationTrace],
}

impl<'a> MainAirInstance<'a> {
    pub const fn new(traces: &'a [VerificationTrace]) -> Self {
        Self { traces }
    }
}

impl AirInstance<F> for MainAirInstance<'_> {
    type Air = HashSigAggAir;
    type Interaction = HashSigAggInteraction;

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::Main(Default::default())
    }

    fn generate_trace(
        &self,
        extra_capacity_bits: usize,
        _: &Self::Interaction,
    ) -> RowMajorMatrix<F> {
        generate_trace(extra_capacity_bits, self.traces)
    }
}
