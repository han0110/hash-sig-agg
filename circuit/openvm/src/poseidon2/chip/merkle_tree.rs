use crate::poseidon2::{
    chip::merkle_tree::{
        air::MerkleTreeAir, column::NUM_MERKLE_TREE_COLS, generation::generate_trace_rows,
    },
    hash_sig::{encode_tweak_merkle_tree, encode_tweak_msg, VerificationTrace, MSG_FE_LEN},
    F,
};
use core::{any::type_name, iter};
use generation::trace_height;
use openvm_stark_backend::{
    config::{Domain, StarkGenericConfig},
    p3_commit::PolynomialSpace,
    p3_field::FieldAlgebra,
    prover::types::{AirProofInput, AirProofRawInput},
    rap::AnyRap,
    Chip, ChipUsageGetter,
};
use std::sync::Arc;

mod air;
mod column;
mod generation;

const WIDTH: usize = 24;
const PARTIAL_ROUNDS: usize = 21;

#[derive(Clone, Debug)]
pub struct MerkleTreeChip<'a> {
    air: Arc<MerkleTreeAir>,
    extra_capacity_bits: usize,
    epoch: u32,
    encoded_msg: [F; MSG_FE_LEN],
    traces: &'a [VerificationTrace],
}

impl<'a> MerkleTreeChip<'a> {
    pub fn new(
        extra_capacity_bits: usize,
        epoch: u32,
        encoded_msg: [F; MSG_FE_LEN],
        traces: &'a [VerificationTrace],
    ) -> Self {
        Self {
            air: Default::default(),
            extra_capacity_bits,
            epoch,
            encoded_msg,
            traces,
        }
    }
}

impl ChipUsageGetter for MerkleTreeChip<'_> {
    fn air_name(&self) -> String {
        type_name::<MerkleTreeAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn trace_width(&self) -> usize {
        NUM_MERKLE_TREE_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for MerkleTreeChip<'_>
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        self.air.clone()
    }

    fn generate_air_proof_input(self) -> AirProofInput<SC> {
        AirProofInput {
            cached_mains_pdata: Vec::new(),
            raw: AirProofRawInput {
                cached_mains: Vec::new(),
                common_main: Some(generate_trace_rows(
                    self.extra_capacity_bits,
                    self.epoch,
                    self.encoded_msg,
                    self.traces,
                )),
                public_values: iter::empty()
                    .chain([F::from_canonical_u32(self.epoch)])
                    .chain(self.encoded_msg)
                    .chain(encode_tweak_msg(self.epoch))
                    .chain(encode_tweak_merkle_tree(0, self.epoch))
                    .collect(),
            },
        }
    }
}
