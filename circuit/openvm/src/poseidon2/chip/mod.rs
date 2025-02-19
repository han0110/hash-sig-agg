use crate::poseidon2::{
    chip::main::MainChip,
    hash_sig::{encode_msg, VerificationInput, VerificationTrace},
    F,
};
use chain::ChainChip;
use decomposition::DecompositionChip;
use merkle_tree::MerkleTreeChip;
use openvm_stark_backend::{
    config::{Domain, StarkGenericConfig},
    prover::types::AirProofInput,
    AirRef, Chip,
};
use p3_commit::PolynomialSpace;
use p3_maybe_rayon::prelude::*;
use range_check::RangeCheckChip;
use tracing::instrument;

pub mod chain;
pub mod decomposition;
pub mod main;
pub mod merkle_tree;
pub mod range_check;

#[repr(u8)]
pub enum Bus {
    Parameter,
    MerkleRootAndMsgHash,
    Chain,
    MerkleLeaf,
    Decomposition,
    RangeCheck,
}

#[instrument(name = "generate hash-sig aggregation traces", skip_all)]
pub fn generate_air_proof_inputs<SC: StarkGenericConfig>(
    extra_capacity_bits: usize,
    vi: VerificationInput,
) -> (Vec<AirRef<SC>>, Vec<AirProofInput<SC>>)
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    let encoded_msg = encode_msg(vi.msg);
    let traces = vi
        .pairs
        .into_par_iter()
        .map(|(pk, sig)| VerificationTrace::generate(vi.epoch, encoded_msg, pk, sig))
        .collect::<Vec<_>>();
    let main = MainChip::new(extra_capacity_bits, &traces);
    let chain = ChainChip::new(extra_capacity_bits, &traces);
    let merkle_tree = MerkleTreeChip::new(extra_capacity_bits, vi.epoch, encoded_msg, &traces);
    let decomposition = DecompositionChip::new(extra_capacity_bits, &traces);
    let ((main_api, chain_api), (merkle_tree_api, (decomposition_api, range_check_mult))) = join(
        || {
            join(
                || main.generate_air_proof_input(),
                || chain.clone().generate_air_proof_input(),
            )
        },
        || {
            join(
                || merkle_tree.clone().generate_air_proof_input(),
                || decomposition.generate_air_proof_input_and_range_check_mult(),
            )
        },
    );
    let range_check_chip = RangeCheckChip::new(extra_capacity_bits, range_check_mult);
    (
        vec![
            main.air(),
            chain.air(),
            merkle_tree.air(),
            decomposition.air(),
            range_check_chip.air(),
        ],
        vec![
            main_api,
            chain_api,
            merkle_tree_api,
            decomposition_api,
            range_check_chip.generate_air_proof_input(),
        ],
    )
}

#[cfg(test)]
mod test {
    use crate::{
        poseidon2::{chip::generate_air_proof_inputs, hash_sig::test::mock_vi, E, F},
        util::engine::Engine,
    };
    use openvm_stark_sdk::engine::StarkEngine;

    #[test]
    fn chip() {
        let engine = Engine::<F, E>::fastest();
        for log_sigs in 4..8 {
            let vi = mock_vi(1 << log_sigs);
            let (airs, air_proof_inputs) = generate_air_proof_inputs(engine.log_blowup(), vi);
            engine.run_test_impl(airs, air_proof_inputs).unwrap();
        }
    }
}
