use crate::poseidon2::{
    chip::range_check::{
        air::RangeCheckAir,
        column::NUM_RANGE_CHECK_COLS,
        generation::{generate_trace_rows, trace_height},
    },
    F,
};
use core::any::type_name;
use openvm_stark_backend::{
    config::{Domain, StarkGenericConfig},
    prover::types::{AirProofInput, AirProofRawInput},
    rap::AnyRap,
    Chip, ChipUsageGetter,
};
use p3_commit::PolynomialSpace;
use std::sync::Arc;

mod air;
mod column;
mod generation;

#[derive(Clone, Debug)]
pub struct RangeCheckChip {
    extra_capacity_bits: usize,
    mult: Vec<u32>,
}

impl RangeCheckChip {
    pub const fn new(extra_capacity_bits: usize, mult: Vec<u32>) -> Self {
        Self {
            extra_capacity_bits,
            mult,
        }
    }
}

impl ChipUsageGetter for RangeCheckChip {
    fn air_name(&self) -> String {
        type_name::<RangeCheckAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height()
    }

    fn trace_width(&self) -> usize {
        NUM_RANGE_CHECK_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for RangeCheckChip
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        Arc::new(RangeCheckAir)
    }

    fn generate_air_proof_input(self) -> AirProofInput<SC> {
        AirProofInput {
            cached_mains_pdata: Vec::new(),
            raw: AirProofRawInput {
                cached_mains: Vec::new(),
                common_main: Some(generate_trace_rows(self.extra_capacity_bits, self.mult)),
                public_values: Vec::new(),
            },
        }
    }
}
