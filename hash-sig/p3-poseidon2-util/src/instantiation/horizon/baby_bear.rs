use crate::instantiation::horizon::{
    baby_bear::constant::*, Poseidon2ExternalLayerHorizon, Poseidon2InternalLayerHorizon,
};
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_poseidon2::{ExternalLayerConstants, Poseidon2};
use std::sync::LazyLock;

pub mod constant;

pub type Poseidon2BabyBearHorizon<const WIDTH: usize> = Poseidon2<
    <BabyBear as Field>::Packing,
    Poseidon2ExternalLayerHorizon<BabyBear, WIDTH, SBOX_DEGREE>,
    Poseidon2InternalLayerHorizon<BabyBear, WIDTH, SBOX_DEGREE>,
    WIDTH,
    SBOX_DEGREE,
>;

pub fn poseidon2_baby_bear_horizon_t16() -> &'static Poseidon2BabyBearHorizon<16> {
    static INSTANCE: LazyLock<Poseidon2BabyBearHorizon<16>> = LazyLock::new(|| {
        Poseidon2::new(
            ExternalLayerConstants::new(
                RC16.beginning_full_round_constants.to_vec(),
                RC16.ending_full_round_constants.to_vec(),
            ),
            RC16.partial_round_constants.to_vec(),
        )
    });
    &INSTANCE
}

pub fn poseidon2_baby_bear_horizon_t24() -> &'static Poseidon2BabyBearHorizon<24> {
    static INSTANCE: LazyLock<Poseidon2BabyBearHorizon<24>> = LazyLock::new(|| {
        Poseidon2::new(
            ExternalLayerConstants::new(
                RC24.beginning_full_round_constants.to_vec(),
                RC24.ending_full_round_constants.to_vec(),
            ),
            RC24.partial_round_constants.to_vec(),
        )
    });
    &INSTANCE
}

#[cfg(test)]
mod test {
    use crate::instantiation::horizon::{
        baby_bear::{
            poseidon2_baby_bear_horizon_t16, poseidon2_baby_bear_horizon_t24,
            Poseidon2BabyBearHorizon,
        },
        MatDiagMinusOne,
    };
    use core::array::from_fn;
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use p3_symmetric::Permutation;
    use rand::{rngs::StdRng, SeedableRng};
    use zkhash::{
        ark_ff::{PrimeField, UniformRand},
        fields::babybear::FpBabyBear,
        poseidon2::{
            poseidon2::Poseidon2,
            poseidon2_instance_babybear::{
                POSEIDON2_BABYBEAR_16_PARAMS, POSEIDON2_BABYBEAR_24_PARAMS,
            },
        },
    };

    #[test]
    fn consistency() {
        fn check<const WIDTH: usize>(poseidon2: &Poseidon2BabyBearHorizon<WIDTH>)
        where
            BabyBear: MatDiagMinusOne<WIDTH>,
        {
            let mut rng = StdRng::from_entropy();
            let reference = Poseidon2::new(match WIDTH {
                16 => &*POSEIDON2_BABYBEAR_16_PARAMS,
                24 => &*POSEIDON2_BABYBEAR_24_PARAMS,
                _ => unreachable!(),
            });
            for _ in 0..100 {
                let pre: [FpBabyBear; WIDTH] = from_fn(|_| FpBabyBear::rand(&mut rng));
                let post: [FpBabyBear; WIDTH] = reference.permutation(&pre).try_into().unwrap();
                let mut state = pre.map(horizon_to_p3::<BabyBear>);
                poseidon2.permute_mut(&mut state);
                assert_eq!(state, post.map(horizon_to_p3))
            }
        }

        check(poseidon2_baby_bear_horizon_t16());
        check(poseidon2_baby_bear_horizon_t24());
    }

    fn horizon_to_p3<F: FieldAlgebra>(value: FpBabyBear) -> F {
        F::from_canonical_u64(value.into_bigint().0[0])
    }
}
