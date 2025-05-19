use crate::{
    poseidon2::{
        F,
        chip::{HashSigAggAir, range_check::RangeCheckInteraction},
        hash_sig::{MSG_HASH_FE_LEN, VerificationTrace},
    },
    util::chip::Chip,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

pub const LIMB_BITS: usize = 12;
pub const LIMB_MASK: u32 = (1 << LIMB_BITS) - 1;
pub const NUM_LIMBS: usize =
    (F::ORDER_U32.next_power_of_two().ilog2() as usize).div_ceil(LIMB_BITS);
pub const NUM_MSG_HASH_LIMBS: usize =
    (MSG_HASH_FE_LEN * F::ORDER_U32.next_power_of_two().ilog2() as usize).div_ceil(LIMB_BITS);
pub const F_MS_LIMB: u32 = {
    assert!(F::ORDER_U32 & LIMB_MASK == 1);
    assert!((F::ORDER_U32 >> LIMB_BITS) & LIMB_MASK == 0);
    F::ORDER_U32 >> (2 * LIMB_BITS)
};
pub const F_MS_LIMB_BITS: usize = F_MS_LIMB.next_power_of_two().ilog2() as usize;
pub const F_MS_LIMB_TRAILING_ZEROS: u32 = F_MS_LIMB.trailing_zeros();
pub const F_MS_LIMB_LEADING_ONES: u32 = F_MS_LIMB_BITS as u32 - F_MS_LIMB_TRAILING_ZEROS;

const __: () =
    assert!((F_MS_LIMB >> F_MS_LIMB_TRAILING_ZEROS).trailing_ones() == F_MS_LIMB_LEADING_ONES);

pub use air::*;
pub use column::*;
pub use generation::*;

pub struct DecompositionChip<'a> {
    extra_capacity_bits: usize,
    traces: &'a [VerificationTrace],
}

impl<'a> DecompositionChip<'a> {
    pub const fn new(extra_capacity_bits: usize, traces: &'a [VerificationTrace]) -> Self {
        Self {
            extra_capacity_bits,
            traces,
        }
    }
}

impl Chip<F> for DecompositionChip<'_> {
    type Air = HashSigAggAir;
    type Interaction = RangeCheckInteraction;

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::Decomposition(Default::default())
    }

    fn trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn generate_trace(&self, interaction: &Self::Interaction) -> RowMajorMatrix<F> {
        generate_trace(self.extra_capacity_bits, self.traces, interaction)
    }
}
