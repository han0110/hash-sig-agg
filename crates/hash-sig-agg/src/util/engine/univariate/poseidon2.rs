use crate::{
    poseidon2::{E, F, Poseidon2, RC16, RC24},
    util::engine::{
        SecurityAssumption,
        univariate::{UnivariateEngineConfig, num_fri_queries},
    },
};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_fri_ext::{FriConfig, TwoAdicFriPcsSharedCap};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark_ext::StarkConfig;

pub type FieldHash = PaddingFreeSponge<Poseidon2<24>, 24, 16, 8>;
pub type Compress = TruncatedPermutation<Poseidon2<16>, 2, 8, 16>;
pub type ValMmcs =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, FieldHash, Compress, 8>;
pub type ChallengeMmcs = ExtensionMmcs<F, E, ValMmcs>;
pub type Challenger = DuplexChallenger<F, Poseidon2<24>, 24, 16>;
pub type Dft = Radix2DitParallel<F>;
pub type Pcs = TwoAdicFriPcsSharedCap<F, Dft, ValMmcs, ChallengeMmcs, [F; 8]>;
pub type UnivariateConfigPoseidon2 = StarkConfig<Pcs, E, Challenger>;

impl UnivariateEngineConfig for UnivariateConfigPoseidon2 {
    fn new(
        log_blowup: usize,
        log_final_poly_len: usize,
        proof_of_work_bits: usize,
        security_assumption: SecurityAssumption,
    ) -> Self {
        let hash = FieldHash::new(Poseidon2::new(
            ExternalLayerConstants::new(
                RC24.beginning_full_round_constants.to_vec(),
                RC24.ending_full_round_constants.to_vec(),
            ),
            RC24.partial_round_constants.to_vec(),
        ));
        let compress = Compress::new(Poseidon2::new(
            ExternalLayerConstants::new(
                RC16.beginning_full_round_constants.to_vec(),
                RC16.ending_full_round_constants.to_vec(),
            ),
            RC16.partial_round_constants.to_vec(),
        ));
        let val_mmcs = ValMmcs::new(hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft::default();
        let fri_config = FriConfig {
            log_blowup,
            log_final_poly_len,
            num_queries: num_fri_queries(log_blowup, proof_of_work_bits, security_assumption),
            proof_of_work_bits,
            arity_bits: 3,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        let challenger = Challenger::new(Poseidon2::new(
            ExternalLayerConstants::new(
                RC24.beginning_full_round_constants.to_vec(),
                RC24.ending_full_round_constants.to_vec(),
            ),
            RC24.partial_round_constants.to_vec(),
        ));
        Self::new(pcs, challenger)
    }
}
