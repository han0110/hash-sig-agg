use crate::{
    air::{
        chain::{ChainAir, ChainAirInstance},
        decomposition::{DecompositionAir, DecompositionAirInstance},
        main::{MainAir, MainAirInstance},
        merkle_tree::{MerkleTreeAir, MerkleTreeAirInstance},
        range_check::{RangeCheckAir, RangeCheckAirInstance},
    },
    hash_sig::{F, MSG_LEN, VerificationInput, VerificationTrace, encode_msg},
    util::air_instance::AirInstance,
};
use p3_air::{Air, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_air_ext::{InteractionBuilder, ProverInput, VerifierInput};
use p3_maybe_rayon::prelude::*;
use range_check::RangeCheckInteraction;
use tracing::instrument;

pub mod chain;
pub mod decomposition;
pub mod main;
pub mod merkle_tree;
pub mod range_check;

#[repr(u8)]
enum Bus {
    Parameter,
    MerkleRootAndMsgHash,
    Chain,
    MerkleLeaf,
    Decomposition,
    RangeCheck,
}

#[derive(Default)]
struct HashSigAggInteraction {
    range_check: RangeCheckInteraction,
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
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
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

    let chain = ChainAirInstance::new(vi.epoch, &traces);
    let decomposition = DecompositionAirInstance::new(&traces);
    let main = MainAirInstance::new(&traces);
    let merkle_tree = MerkleTreeAirInstance::new(vi.epoch, encoded_msg, &traces);
    let range_check = RangeCheckAirInstance::new();
    let interaction = Default::default();

    let (
        (chain_prover_input, main_prover_input),
        (merkle_tree_prover_input, decomposition_prover_input),
    ) = join(
        || {
            join(
                || chain.prover_input(extra_capacity_bits, &interaction),
                || main.prover_input(extra_capacity_bits, &interaction),
            )
        },
        || {
            join(
                || merkle_tree.prover_input(extra_capacity_bits, &interaction),
                || decomposition.prover_input(extra_capacity_bits, &interaction),
            )
        },
    );
    let range_check_prover_input = range_check.prover_input(extra_capacity_bits, &interaction);

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

    let chain = ChainAirInstance::new(epoch, &[]);
    let decomposition = DecompositionAirInstance::new(&[]);
    let main = MainAirInstance::new(&[]);
    let merkle_tree = MerkleTreeAirInstance::new(epoch, encoded_msg, &[]);
    let range_check = RangeCheckAirInstance::new();

    vec![
        chain.verifier_input(),
        decomposition.verifier_input(),
        main.verifier_input(),
        merkle_tree.verifier_input(),
        range_check.verifier_input(),
    ]
}

#[cfg(test)]
mod test {
    use crate::air::generate_prover_inputs;
    use hash_sig_testdata::mock_vi;
    use p3_air_ext::check_constraints;

    #[test]
    fn airs() {
        for log_sigs in 1..8 {
            let vi = mock_vi(1 << log_sigs);
            let prover_inputs = generate_prover_inputs(0, vi);
            check_constraints(&prover_inputs);
        }
    }
}
