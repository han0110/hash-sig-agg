use crate::{
    air::{
        HashSigAggAir, HashSigAggInteraction, decomposition::LIMB_BITS,
        range_check::generation::generate_trace,
    },
    hash_sig::F,
    util::air_instance::AirInstance,
};
use core::{
    iter::repeat_with,
    sync::atomic::{AtomicU32, Ordering},
};
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

pub use air::*;
pub use column::*;

#[derive(Default)]
pub(super) struct RangeCheckAirInstance;

impl RangeCheckAirInstance {
    pub const fn new() -> Self {
        Self
    }
}

impl AirInstance<F> for RangeCheckAirInstance {
    type Air = HashSigAggAir;
    type Interaction = HashSigAggInteraction;

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::RangeCheck(Default::default())
    }

    fn generate_trace(
        &self,
        extra_capacity_bits: usize,
        interaction: &Self::Interaction,
    ) -> RowMajorMatrix<F> {
        generate_trace(extra_capacity_bits, &interaction.range_check)
    }
}

pub struct RangeCheckInteraction(Vec<AtomicU32>);

impl Default for RangeCheckInteraction {
    fn default() -> Self {
        Self(repeat_with(Default::default).take(1 << LIMB_BITS).collect())
    }
}

impl RangeCheckInteraction {
    pub fn send(&self, value: usize) {
        self.0[value].fetch_add(1, Ordering::Relaxed);
    }
}
