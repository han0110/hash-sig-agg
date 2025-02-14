use crate::poseidon2::{
    chip::decomposition::{
        air::DecompositionAir,
        column::NUM_DECOMPOSITION_COLS,
        generation::{generate_trace_rows, trace_height},
    },
    hash_sig::{VerificationTrace, MSG_HASH_FE_LEN},
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
use p3_field::PrimeField32;
use std::sync::Arc;

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

mod air;
mod column;
mod generation;

#[derive(Clone, Copy, Debug)]
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

    pub fn generate_air_proof_input_and_range_check_mult<SC: StarkGenericConfig>(
        self,
    ) -> (AirProofInput<SC>, Vec<u32>)
    where
        Domain<SC>: PolynomialSpace<Val = F>,
    {
        let (trace, mult) = generate_trace_rows(self.extra_capacity_bits, self.traces);
        let api = AirProofInput {
            cached_mains_pdata: Vec::new(),
            raw: AirProofRawInput {
                cached_mains: Vec::new(),
                common_main: Some(trace),
                public_values: Vec::new(),
            },
        };
        (api, mult)
    }
}

impl ChipUsageGetter for DecompositionChip<'_> {
    fn air_name(&self) -> String {
        type_name::<DecompositionAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn trace_width(&self) -> usize {
        NUM_DECOMPOSITION_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for DecompositionChip<'_>
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        Arc::new(DecompositionAir)
    }

    fn generate_air_proof_input(self) -> AirProofInput<SC> {
        AirProofInput {
            cached_mains_pdata: Vec::new(),
            raw: AirProofRawInput {
                cached_mains: Vec::new(),
                common_main: Some(generate_trace_rows(self.extra_capacity_bits, self.traces).0),
                public_values: Vec::new(),
            },
        }
    }
}
