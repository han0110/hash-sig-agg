use crate::engine::{SecurityAssumption, multilinear::MultilinearEngineConfig};
use hash_sig_agg::hash_sig::{E, F};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_hyperplonk::HyperPlonkConfig;
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_whir::{FoldingFactor, ProtocolParameters, WhirPcs};

type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type Dft = Radix2DitParallel<F>;
type Pcs = WhirPcs<F, Dft, FieldHash, Compress, 32>;
type Challenger = SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>;
pub type MultilinearConfigKeccak = HyperPlonkConfig<Pcs, E, Challenger>;

impl MultilinearEngineConfig for MultilinearConfigKeccak {
    fn new(
        log_blowup: usize,
        proof_of_work_bits: usize,
        security_assumption: SecurityAssumption,
    ) -> Self {
        let dft = Dft::default();
        // FIXME: Set to 128 when higher degree extension field is available.
        let security_level = 100;
        let byte_hash = ByteHash {};
        let field_hash = FieldHash::new(byte_hash);
        let compress = Compress::new(byte_hash);
        let whir_params = ProtocolParameters {
            initial_statement: true,
            security_level,
            pow_bits: proof_of_work_bits,
            folding_factor: FoldingFactor::Constant(4),
            merkle_hash: field_hash,
            merkle_compress: compress,
            soundness_type: match security_assumption {
                SecurityAssumption::JohnsonBound => p3_whir::SecurityAssumption::JohnsonBound,
                SecurityAssumption::CapacityBound => p3_whir::SecurityAssumption::CapacityBound,
            },
            starting_log_inv_rate: log_blowup,
        };
        let pcs = Pcs::new(dft, whir_params);
        let challenger = Challenger::from_hasher(Vec::new(), Keccak256Hash {});
        Self::new(pcs, challenger)
    }
}
