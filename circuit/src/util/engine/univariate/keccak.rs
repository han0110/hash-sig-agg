use crate::{
    poseidon2::{E, F},
    util::engine::{SoundnessType, univariate::UnivariateEngineConfig},
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_fri_ext::{FriConfig, TwoAdicFriPcsSharedCap};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark_ext::StarkConfig;

pub type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
pub type FieldHash = SerializingHasher<U64Hash>;
pub type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
pub type ValMmcs = MerkleTreeMmcs<[F; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, 4>;
pub type ChallengeMmcs = ExtensionMmcs<F, E, ValMmcs>;
pub type ByteHash = Keccak256Hash;
pub type Challenger = SerializingChallenger32<F, HashChallenger<u8, ByteHash, 32>>;
pub type Dft = Radix2DitParallel<F>;
pub type Pcs = TwoAdicFriPcsSharedCap<F, Dft, ValMmcs, ChallengeMmcs, [u64; 4]>;
pub type UnivariateConfigKeccak = StarkConfig<Pcs, E, Challenger>;

impl UnivariateEngineConfig for UnivariateConfigKeccak {
    fn new(
        log_blowup: usize,
        log_final_poly_len: usize,
        proof_of_work_bits: usize,
        soundness_type: SoundnessType,
    ) -> Self {
        let u64_hash = U64Hash::new(KeccakF {});
        let field_hash = FieldHash::new(u64_hash);
        let compress = Compress::new(u64_hash);
        let val_mmcs = ValMmcs::new(field_hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft::default();
        let fri_config = FriConfig {
            log_blowup,
            log_final_poly_len,
            num_queries: soundness_type.num_queries(log_blowup, proof_of_work_bits),
            proof_of_work_bits,
            arity_bits: 3,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        let challenger = Challenger::from_hasher(vec![], ByteHash {});
        Self::new(pcs, challenger)
    }
}
