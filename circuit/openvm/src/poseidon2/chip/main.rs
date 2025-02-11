use crate::poseidon2::{
    F,
    chip::main::{air::MainAir, column::NUM_MAIN_COLS},
    hash_sig::{VerificationTrace, encode_tweak_merkle_tree},
};
use core::any::type_name;
use generation::{generate_trace_rows, trace_height};
use openvm_stark_backend::{
    Chip, ChipUsageGetter,
    config::{Domain, StarkGenericConfig},
    p3_commit::PolynomialSpace,
    prover::types::{AirProofInput, AirProofRawInput},
    rap::AnyRap,
};
use std::sync::Arc;

mod air;
mod column;
mod generation;

pub struct MainChip<'a> {
    extra_capacity_bits: usize,
    epoch: u32,
    traces: &'a [VerificationTrace],
}

impl<'a> MainChip<'a> {
    pub fn new(extra_capacity_bits: usize, epoch: u32, traces: &'a [VerificationTrace]) -> Self {
        Self {
            extra_capacity_bits,
            epoch,
            traces,
        }
    }
}

impl ChipUsageGetter for MainChip<'_> {
    fn air_name(&self) -> String {
        type_name::<MainAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn trace_width(&self) -> usize {
        NUM_MAIN_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for MainChip<'_>
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        Arc::new(MainAir)
    }

    fn generate_air_proof_input(self) -> AirProofInput<SC> {
        AirProofInput {
            cached_mains_pdata: Vec::new(),
            raw: AirProofRawInput {
                cached_mains: Vec::new(),
                common_main: Some(generate_trace_rows(self.extra_capacity_bits, self.traces)),
                public_values: encode_tweak_merkle_tree(0, self.epoch).to_vec(),
            },
        }
    }
}
