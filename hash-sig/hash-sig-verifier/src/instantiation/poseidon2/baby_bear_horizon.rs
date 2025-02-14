use crate::instantiation::poseidon2::{Poseidon2Parameter, SPONGE_CAPACITY};
use p3_baby_bear::BabyBear;
use p3_poseidon2_util::instantiation::horizon::baby_bear::{
    poseidon2_baby_bear_horizon_t16, poseidon2_baby_bear_horizon_t24,
};
use p3_symmetric::Permutation;

#[derive(Clone, Copy, Debug, Default)]
pub struct BabyBearHorizon;

impl Poseidon2Parameter for BabyBearHorizon {
    type F = BabyBear;

    const CAPACITY_VALUES: [BabyBear; SPONGE_CAPACITY] = BabyBear::new_array([
        1812885503, 1176861807, 135926247, 1170849646, 1751547645, 646603316, 1547513893,
        423708400, 961239569,
    ]);

    fn permutation_t16(mut state: [BabyBear; 16]) -> [BabyBear; 16] {
        poseidon2_baby_bear_horizon_t16().permute_mut(&mut state);
        state
    }

    fn permutation_t24(mut state: [BabyBear; 24]) -> [BabyBear; 24] {
        poseidon2_baby_bear_horizon_t24().permute_mut(&mut state);
        state
    }
}

#[cfg(test)]
mod test {
    use crate::instantiation::poseidon2::{
        baby_bear_horizon::BabyBearHorizon, decompose, Poseidon2Parameter, HASH_FE_LEN, NUM_CHUNKS,
        PARAM_FE_LEN, SPONGE_CAPACITY, TWEAK_FE_LEN,
    };
    use num_bigint::BigUint;
    use p3_baby_bear::BabyBear;

    #[test]
    fn capacity_values() {
        let shl = |v, shift| BigUint::from(v) << shift;
        assert_eq!(
            BabyBearHorizon::CAPACITY_VALUES,
            BabyBearHorizon::compress_t24::<SPONGE_CAPACITY, SPONGE_CAPACITY>(decompose::<
                BabyBear,
                SPONGE_CAPACITY,
            >(
                shl(PARAM_FE_LEN, 96) + shl(TWEAK_FE_LEN, 64) + shl(NUM_CHUNKS, 32) + HASH_FE_LEN,
            ))
        );
    }
}
