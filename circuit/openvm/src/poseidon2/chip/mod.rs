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

pub mod chain;
pub mod decomposition;
pub mod main;
pub mod merkle_tree;
pub mod range_check;

/// A generic trait for types that can be borrowed from a `[T]` slice.
pub trait AlignBorrow<T>: Sized {
    /// The expected number of columns for this type.
    const NUM_COLS: usize;

    /// Aligns and borrows a reference.
    fn align_borrow(slice: &[T]) -> &Self {
        debug_assert_eq!(slice.len(), Self::NUM_COLS);
        let (prefix, shorts, suffix) = unsafe { slice.align_to::<Self>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }

    /// Aligns and borrows a mutable reference.
    fn align_borrow_mut(slice: &mut [T]) -> &mut Self {
        debug_assert_eq!(slice.len(), Self::NUM_COLS);
        let (prefix, shorts, suffix) = unsafe { slice.align_to_mut::<Self>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

#[repr(u8)]
pub enum Bus {
    Parameter,
    MerkleRootAndMsgHash,
    Chain,
    MerkleLeaf,
    Decomposition,
    RangeCheck,
}

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
        test::run,
    };

    #[test]
    fn chip() {
        for log_sigs in 4..8 {
            let vi = mock_vi(1 << log_sigs);
            let (airs, inputs) = generate_air_proof_inputs(1, vi);
            run::<F, E>(airs, inputs).unwrap();
        }
    }
}
