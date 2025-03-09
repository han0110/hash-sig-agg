#![allow(clippy::type_repetition_in_bounds, clippy::multiple_bound_locations)]

use p3_air::Air;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32To64};
use p3_uni_stark_ext::{
    PcsError, Proof, ProverConstraintFolder, ProverInput, ProverInteractionFolder, StarkConfig,
    SymbolicAirBuilder, VerificationError, VerifierConstraintFolder, VerifierInput, prove, verify,
};

type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher32To64<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs<F> = MerkleTreeMmcs<[F; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, 4>;
type ChallengeMmcs<F, E> = ExtensionMmcs<F, E, ValMmcs<F>>;
type ByteHash = Keccak256Hash;
type Challenger<F> = SerializingChallenger32<F, HashChallenger<u8, ByteHash, 32>>;
type Dft<F> = Radix2DitParallel<F>;
type Pcs<F, E> = TwoAdicFriPcs<F, Dft<F>, ValMmcs<F>, ChallengeMmcs<F, E>>;
pub type Config<F, E> = StarkConfig<Pcs<F, E>, E, Challenger<F>>;

const fn new_challenger<F: PrimeField32>() -> Challenger<F> {
    Challenger::from_hasher(vec![], ByteHash {})
}

pub struct Engine<F, E> {
    config: Config<F, E>,
    log_blowup: usize,
}

impl<F, E> Engine<F, E>
where
    F: PrimeField32 + TwoAdicField,
    E: ExtensionField<F> + TwoAdicField,
{
    pub fn new(log_blowup: usize, proof_of_work_bits: usize) -> Self {
        let u64_hash = U64Hash::new(KeccakF {});
        let field_hash = FieldHash::new(u64_hash);
        let compress = Compress::new(u64_hash);
        let val_mmcs = ValMmcs::new(field_hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft::default();
        let num_queries = usize::div_ceil(2 * (128 - proof_of_work_bits), log_blowup);
        let fri_config = FriConfig {
            log_blowup,
            log_final_poly_len: 3,
            num_queries,
            proof_of_work_bits,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        Self {
            config: Config::new(pcs),
            log_blowup,
        }
    }

    pub fn fastest() -> Self {
        Self::new(1, 0)
    }

    pub const fn log_blowup(&self) -> usize {
        self.log_blowup
    }
}

impl<F, E> Engine<F, E>
where
    F: PrimeField32 + TwoAdicField,
    E: ExtensionField<F> + TwoAdicField,
{
    const fn config(&self) -> &Config<F, E> {
        &self.config
    }

    pub fn prove<
        #[cfg(feature = "check-constraints")] A: for<'a> Air<p3_uni_stark_ext::DebugConstraintBuilder<'a, F>>,
        #[cfg(not(feature = "check-constraints"))] A,
    >(
        &self,
        inputs: Vec<ProverInput<F, A>>,
    ) -> Proof<Config<F, E>>
    where
        A: Air<SymbolicAirBuilder<F>>
            + for<'a> Air<ProverConstraintFolder<'a, Config<F, E>>>
            + for<'a> Air<ProverInteractionFolder<'a, Config<F, E>>>,
    {
        let mut challenger = new_challenger();
        prove(self.config(), inputs, &mut challenger)
    }

    pub fn verify<A>(
        &self,
        inputs: Vec<VerifierInput<F, A>>,
        proof: &Proof<Config<F, E>>,
    ) -> Result<(), VerificationError<PcsError<Config<F, E>>>>
    where
        A: Air<SymbolicAirBuilder<F>> + for<'a> Air<VerifierConstraintFolder<'a, Config<F, E>>>,
    {
        let mut challenger = new_challenger();
        verify(self.config(), inputs, &mut challenger, proof)
    }

    #[cfg(test)]
    pub fn test<
        #[cfg(feature = "check-constraints")] A: for<'a> Air<p3_uni_stark_ext::DebugConstraintBuilder<'a, F>>,
        #[cfg(not(feature = "check-constraints"))] A,
    >(
        &self,
        prover_inputs: Vec<ProverInput<F, A>>,
    ) where
        A: Clone
            + Air<SymbolicAirBuilder<F>>
            + for<'a> Air<ProverConstraintFolder<'a, Config<F, E>>>
            + for<'a> Air<ProverInteractionFolder<'a, Config<F, E>>>
            + for<'a> Air<VerifierConstraintFolder<'a, Config<F, E>>>,
    {
        let verifier_inputs = prover_inputs.iter().map(|v| (**v).clone()).collect();
        let proof = self.prove(prover_inputs);
        self.verify(verifier_inputs, &proof).unwrap();
    }
}
