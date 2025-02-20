pub mod chip;
pub mod hash_sig;

pub use koala_bear::*;

pub mod baby_bear {
    pub use hash_sig_verifier::instantiation::poseidon2::baby_bear_horizon::BabyBearHorizon as Poseidon2Parameter;
    pub use p3_baby_bear::BabyBear as F;
    pub use p3_poseidon2_util::instantiation::horizon::baby_bear::constant::{
        partial_round, HALF_FULL_ROUNDS, RC16, RC24, SBOX_DEGREE,
    };
    pub type E = p3_field::extension::BinomialExtensionField<F, 5>; // FIXME: Use higher degree when possible.
    pub type Poseidon2LinearLayers<const WIDTH: usize> =
        p3_poseidon2_util::instantiation::horizon::Poseidon2LinearLayersHorizon<F, WIDTH>;
    pub const SBOX_REGISTERS: usize = 1;
}

pub mod koala_bear {
    pub use hash_sig_verifier::instantiation::poseidon2::koala_bear_horizon::KoalaBearHorizon as Poseidon2Parameter;
    pub use p3_koala_bear::KoalaBear as F;
    pub use p3_poseidon2_util::instantiation::horizon::koala_bear::constant::{
        partial_round, HALF_FULL_ROUNDS, RC16, RC24, SBOX_DEGREE,
    };
    pub type E = p3_field::extension::BinomialExtensionField<F, 4>; // FIXME: Use higher degree when possible.
    pub type Poseidon2LinearLayers<const WIDTH: usize> =
        p3_poseidon2_util::instantiation::horizon::Poseidon2LinearLayersHorizon<F, WIDTH>;
    pub const SBOX_REGISTERS: usize = 0;
}
