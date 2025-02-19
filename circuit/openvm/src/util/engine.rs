use openvm_stark_backend::{config::StarkConfig, interaction::fri_log_up::FriLogUpPhase};
use openvm_stark_sdk::engine::StarkEngine;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32To64};

type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher32To64<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs<F> = MerkleTreeMmcs<[F; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, 4>;
type ChallengeMmcs<F, E> = ExtensionMmcs<F, E, ValMmcs<F>>;
type ByteHash = Keccak256Hash;
type Challenger<F> = SerializingChallenger32<F, HashChallenger<u8, ByteHash, 32>>;
type Dft<F> = Radix2DitParallel<F>;
type Pcs<F, E> = TwoAdicFriPcs<F, Dft<F>, ValMmcs<F>, ChallengeMmcs<F, E>>;
type RapPhase<F, E> = FriLogUpPhase<F, E, Challenger<F>>;
pub type Config<F, E> = StarkConfig<Pcs<F, E>, RapPhase<F, E>, E, Challenger<F>>;

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
        let rap_phase = RapPhase::new();
        Self {
            config: Config::new(pcs, rap_phase),
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

impl<F, E> StarkEngine<Config<F, E>> for Engine<F, E>
where
    F: PrimeField32 + TwoAdicField,
    E: ExtensionField<F> + TwoAdicField,
{
    fn config(&self) -> &Config<F, E> {
        &self.config
    }

    fn new_challenger(&self) -> Challenger<F> {
        Challenger::from_hasher(vec![], ByteHash {})
    }
}
