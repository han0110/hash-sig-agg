use crate::instantiation::poseidon2::{Poseidon2Parameter, SPONGE_CAPACITY};
use p3_koala_bear::KoalaBear;
use p3_poseidon2_util::instantiation::horizon::koala_bear::{
    poseidon2_koala_bear_horizon_t16, poseidon2_koala_bear_horizon_t24,
};
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct KoalaBearHorizon;

impl Poseidon2Parameter for KoalaBearHorizon {
    type F = KoalaBear;

    const CAPACITY_VALUES: [KoalaBear; SPONGE_CAPACITY] = KoalaBear::new_array([
        556206383, 1483226447, 2129946760, 642552831, 1982893194, 6966942, 872250907, 2081466424,
        1531740321,
    ]);

    fn permutation_t16(mut state: [KoalaBear; 16]) -> [KoalaBear; 16] {
        poseidon2_koala_bear_horizon_t16().permute_mut(&mut state);
        state
    }

    fn permutation_t24(mut state: [KoalaBear; 24]) -> [KoalaBear; 24] {
        poseidon2_koala_bear_horizon_t24().permute_mut(&mut state);
        state
    }
}

#[cfg(test)]
mod test {
    use crate::instantiation::poseidon2::{
        decompose, koala_bear_horizon::KoalaBearHorizon, Poseidon2Parameter, HASH_FE_LEN,
        NUM_CHUNKS, PARAM_FE_LEN, SPONGE_CAPACITY, TWEAK_FE_LEN,
    };
    use num_bigint::BigUint;
    use p3_koala_bear::KoalaBear;

    #[test]
    fn capacity_values() {
        let shl = |v, shift| BigUint::from(v) << shift;
        assert_eq!(
            KoalaBearHorizon::CAPACITY_VALUES,
            KoalaBearHorizon::compress_t24::<SPONGE_CAPACITY, SPONGE_CAPACITY>(decompose::<
                KoalaBear,
                SPONGE_CAPACITY,
            >(
                shl(PARAM_FE_LEN, 96) + shl(TWEAK_FE_LEN, 64) + shl(NUM_CHUNKS, 32) + HASH_FE_LEN,
            ))
        );
    }
}
