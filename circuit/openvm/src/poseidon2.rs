use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3_poseidon2_util::instantiation::horizon;

pub mod chip;
pub mod hash_sig;

pub type F = BabyBear;

pub const SBOX_REGISTERS: usize = 1;

pub use horizon::{
    baby_bear::{
        constant::{HALF_FULL_ROUNDS, RC16, RC24, SBOX_DEGREE},
        poseidon2_baby_bear_horizon_t16 as poseidon2_t16,
        poseidon2_baby_bear_horizon_t24 as poseidon2_t24,
    },
    GenericPoseidon2LinearLayersHorizon,
};

macro_rules! concat_array {
    [$first:expr $(, $rest:expr)* $(,)?] => {{
        let mut iter = $first.into_iter()$(.chain($rest))*;
        ::core::array::from_fn(|_| iter.next().unwrap_or_default())
    }};
}

use concat_array;
