use crate::{
    poseidon2::{
        F,
        chip::{
            chain::{ChainAir, ChainChip},
            decomposition::{DecompositionAir, DecompositionChip},
            main::{MainAir, MainChip},
            merkle_tree::{MerkleTreeAir, MerkleTreeChip},
            range_check::{RangeCheckAir, RangeCheckChip},
        },
        hash_sig::{MSG_LEN, VerificationInput, VerificationTrace, encode_msg},
    },
    util::chip::Chip,
};
use p3_air::{Air, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark_ext::{InteractionAirBuilder, ProverInput, VerifierInput};
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

#[derive(Clone, Debug)]
pub enum HashSigAggAir {
    Chain(ChainAir),
    Decomposition(DecompositionAir),
    Main(MainAir),
    MerkleTree(MerkleTreeAir),
    RangeCheck(RangeCheckAir),
}

impl BaseAir<F> for HashSigAggAir {
    fn width(&self) -> usize {
        match self {
            Self::Chain(air) => air.width(),
            Self::Decomposition(air) => air.width(),
            Self::Main(air) => air.width(),
            Self::MerkleTree(air) => air.width(),
            Self::RangeCheck(air) => air.width(),
        }
    }
}

impl BaseAirWithPublicValues<F> for HashSigAggAir {
    fn num_public_values(&self) -> usize {
        match self {
            Self::Chain(air) => air.num_public_values(),
            Self::Decomposition(air) => air.num_public_values(),
            Self::Main(air) => air.num_public_values(),
            Self::MerkleTree(air) => air.num_public_values(),
            Self::RangeCheck(air) => air.num_public_values(),
        }
    }
}

impl<AB> Air<AB> for HashSigAggAir
where
    AB: InteractionAirBuilder<F = F> + AirBuilderWithPublicValues,
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Chain(air) => air.eval(builder),
            Self::Decomposition(air) => air.eval(builder),
            Self::Main(air) => air.eval(builder),
            Self::MerkleTree(air) => air.eval(builder),
            Self::RangeCheck(air) => air.eval(builder),
        }
    }
}

#[instrument(name = "generate hash-sig aggregation traces", skip_all)]
pub fn generate_prover_inputs(
    extra_capacity_bits: usize,
    vi: VerificationInput,
) -> Vec<ProverInput<F, HashSigAggAir>> {
    let encoded_msg = encode_msg(vi.msg);
    let traces = vi
        .pairs
        .into_par_iter()
        .map(|(pk, sig)| VerificationTrace::generate(vi.epoch, encoded_msg, pk, sig))
        .collect::<Vec<_>>();

    let chain_chip = ChainChip::new(extra_capacity_bits, vi.epoch, &traces);
    let decomposition_chip = DecompositionChip::new(extra_capacity_bits, &traces);
    let main_chip = MainChip::new(extra_capacity_bits, &traces);
    let merkle_tree_chip = MerkleTreeChip::new(extra_capacity_bits, vi.epoch, encoded_msg, &traces);
    let range_check_chip = RangeCheckChip::new(extra_capacity_bits);
    let range_check_mult = Default::default();

    let (
        (chain_prover_input, main_prover_input),
        (merkle_tree_prover_input, decomposition_prover_input),
    ) = join(
        || {
            join(
                || chain_chip.generate_prover_input(&()),
                || main_chip.generate_prover_input(&()),
            )
        },
        || {
            join(
                || merkle_tree_chip.generate_prover_input(&()),
                || decomposition_chip.generate_prover_input(&range_check_mult),
            )
        },
    );
    let range_check_prover_input = range_check_chip.generate_prover_input(&range_check_mult);

    vec![
        chain_prover_input,
        decomposition_prover_input,
        main_prover_input,
        merkle_tree_prover_input,
        range_check_prover_input,
    ]
}

pub fn verifier_inputs(epoch: u32, msg: [u8; MSG_LEN]) -> Vec<VerifierInput<F, HashSigAggAir>> {
    let encoded_msg = encode_msg(msg);

    let chain_chip = ChainChip::new(0, epoch, &[]);
    let decomposition_chip = DecompositionChip::new(0, &[]);
    let main_chip = MainChip::new(0, &[]);
    let merkle_tree_chip = MerkleTreeChip::new(0, epoch, encoded_msg, &[]);
    let range_check_chip = RangeCheckChip::new(0);

    vec![
        chain_chip.verifier_input(),
        decomposition_chip.verifier_input(),
        main_chip.verifier_input(),
        merkle_tree_chip.verifier_input(),
        range_check_chip.verifier_input(),
    ]
}

#[cfg(test)]
mod test {
    use crate::{
        poseidon2::{chip::generate_prover_inputs, hash_sig::test::mock_vi},
        util::engine::{Engine, keccak::KeccakConfig},
    };

    #[test]
    fn chip() {
        let engine = Engine::<KeccakConfig>::fastest();
        for log_sigs in 4..8 {
            let vi = mock_vi(1 << log_sigs);
            let inputs = generate_prover_inputs(engine.log_blowup(), vi);
            engine.test(inputs);
        }
    }
}
