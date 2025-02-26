use crate::{
    poseidon2::{
        F,
        chip::HashSigAggAir,
        hash_sig::{MSG_FE_LEN, VerificationTrace, encode_tweak_merkle_tree, encode_tweak_msg},
    },
    util::chip::Chip,
};
use core::iter;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

mod poseidon2 {
    pub const WIDTH: usize = 24;
    pub const PARTIAL_ROUNDS: usize = crate::poseidon2::partial_round::<WIDTH>();
}

pub use air::*;
pub use column::*;
pub use generation::*;

pub struct MerkleTreeChip<'a> {
    extra_capacity_bits: usize,
    epoch: u32,
    encoded_msg: [F; MSG_FE_LEN],
    traces: &'a [VerificationTrace],
}

impl<'a> MerkleTreeChip<'a> {
    pub const fn new(
        extra_capacity_bits: usize,
        epoch: u32,
        encoded_msg: [F; MSG_FE_LEN],
        traces: &'a [VerificationTrace],
    ) -> Self {
        Self {
            extra_capacity_bits,
            epoch,
            encoded_msg,
            traces,
        }
    }
}

impl Chip<F> for MerkleTreeChip<'_> {
    type Air = HashSigAggAir;
    type Interaction = ();

    fn air(&self) -> HashSigAggAir {
        HashSigAggAir::MerkleTree(Default::default())
    }

    fn public_values(&self) -> Vec<F> {
        iter::once(F::from_u32(self.epoch))
            .chain(self.encoded_msg)
            .chain(encode_tweak_msg(self.epoch))
            .chain(encode_tweak_merkle_tree(0, self.epoch))
            .collect()
    }

    fn trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn generate_trace(&self, (): &Self::Interaction) -> RowMajorMatrix<F> {
        generate_trace(
            self.extra_capacity_bits,
            self.epoch,
            self.encoded_msg,
            self.traces,
        )
    }
}
