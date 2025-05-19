use crate::{
    poseidon2::{
        F,
        chip::{HashSigAggAir, decomposition::LIMB_BITS},
    },
    util::chip::Chip,
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
pub use generation::*;

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

pub struct RangeCheckChip {
    extra_capacity_bits: usize,
}

impl RangeCheckChip {
    pub const fn new(extra_capacity_bits: usize) -> Self {
        Self {
            extra_capacity_bits,
        }
    }
}

impl Chip<F> for RangeCheckChip {
    type Air = HashSigAggAir;
    type Interaction = RangeCheckInteraction;

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::RangeCheck(Default::default())
    }

    fn trace_height(&self) -> usize {
        1 << LIMB_BITS
    }

    fn generate_trace(&self, interaction: &Self::Interaction) -> RowMajorMatrix<F> {
        generate_trace(self.extra_capacity_bits, interaction)
    }
}
