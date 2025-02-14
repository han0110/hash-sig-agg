use openvm_stark_backend::{
    config::StarkConfig, engine::VerificationData, interaction::fri_log_up::FriLogUpPhase,
    prover::types::AirProofInput, verifier::VerificationError, AirRef,
};
use openvm_stark_sdk::{engine::StarkEngine, p3_keccak::Keccak256Hash};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};

type ByteHash = Keccak256Hash;
type LeafHash = SerializingHasher32<ByteHash>;
type Compression = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs<Val> = MerkleTreeMmcs<Val, u8, LeafHash, Compression, 32>;
type ChallengeMmcs<Val, Challenge> = ExtensionMmcs<Val, Challenge, ValMmcs<Val>>;
type Challenger<Val> = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft<Val> = Radix2DitParallel<Val>;
type Pcs<Val, Challenge> =
    TwoAdicFriPcs<Val, Dft<Val>, ValMmcs<Val>, ChallengeMmcs<Val, Challenge>>;
type RapPhase<Val, Challenge> = FriLogUpPhase<Val, Challenge, Challenger<Val>>;
type Config<Val, Challenge> =
    StarkConfig<Pcs<Val, Challenge>, RapPhase<Val, Challenge>, Challenge, Challenger<Val>>;

struct Engine<Val, Challenge> {
    config: Config<Val, Challenge>,
}

impl<Val, Challenge> Engine<Val, Challenge>
where
    Val: PrimeField32 + TwoAdicField,
    Challenge: TwoAdicField + ExtensionField<Val>,
{
    fn new() -> Self {
        let byte_hash = ByteHash {};
        let leaf_hash = LeafHash::new(byte_hash);
        let compress = Compression::new(byte_hash);
        let val_mmcs = ValMmcs::new(leaf_hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft::default();
        let log_blowup = 1;
        let fri_config = FriConfig {
            log_blowup,
            log_final_poly_len: 0,
            num_queries: 256usize.div_ceil(log_blowup),
            proof_of_work_bits: 0,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        let rap_phase = RapPhase::new();
        Self {
            config: Config::new(pcs, rap_phase),
        }
    }
}

impl<Val, Challenge> StarkEngine<Config<Val, Challenge>> for Engine<Val, Challenge>
where
    Val: PrimeField32 + TwoAdicField,
    Challenge: TwoAdicField + ExtensionField<Val>,
{
    fn config(&self) -> &Config<Val, Challenge> {
        &self.config
    }

    fn new_challenger(&self) -> Challenger<Val> {
        Challenger::from_hasher(vec![], ByteHash {})
    }
}

pub fn run<Val, Challenge>(
    airs: Vec<AirRef<Config<Val, Challenge>>>,
    air_proof_inputs: Vec<AirProofInput<Config<Val, Challenge>>>,
) -> Result<VerificationData<Config<Val, Challenge>>, VerificationError>
where
    Val: PrimeField32 + TwoAdicField,
    Challenge: TwoAdicField + ExtensionField<Val>,
{
    Engine::new().run_test_impl(airs, air_proof_inputs)
}
