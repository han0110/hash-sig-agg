use crate::{
    air::{HashSigAggAir, HashSigAggInteraction, merkle_tree::generation::generate_trace},
    hash_sig::{F, MSG_FE_LEN, VerificationTrace, encode_tweak_merkle_tree, encode_tweak_msg},
    util::air_instance::AirInstance,
};
use core::iter;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

mod air;
mod column;
mod generation;

mod poseidon2 {
    pub const WIDTH: usize = 24;
    pub const PARTIAL_ROUNDS: usize = crate::hash_sig::partial_round::<WIDTH>();
}

pub use air::*;
pub use column::*;

pub(super) struct MerkleTreeAirInstance<'a> {
    epoch: u32,
    encoded_msg: [F; MSG_FE_LEN],
    traces: &'a [VerificationTrace],
}

impl<'a> MerkleTreeAirInstance<'a> {
    pub const fn new(
        epoch: u32,
        encoded_msg: [F; MSG_FE_LEN],
        traces: &'a [VerificationTrace],
    ) -> Self {
        Self {
            epoch,
            encoded_msg,
            traces,
        }
    }
}

impl AirInstance<F> for MerkleTreeAirInstance<'_> {
    type Air = HashSigAggAir;
    type Interaction = HashSigAggInteraction;

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

    fn generate_trace(
        &self,
        extra_capacity_bits: usize,
        _: &Self::Interaction,
    ) -> RowMajorMatrix<F> {
        generate_trace(
            extra_capacity_bits,
            self.epoch,
            self.encoded_msg,
            self.traces,
        )
    }
}
