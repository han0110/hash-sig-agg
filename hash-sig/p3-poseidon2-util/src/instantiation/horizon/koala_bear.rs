use crate::instantiation::horizon::{
    koala_bear::constant::*, Poseidon2ExternalLayerHorizon, Poseidon2InternalLayerHorizon,
};
use p3_field::Field;
use p3_koala_bear::KoalaBear;
use p3_poseidon2::{ExternalLayerConstants, Poseidon2};
use std::sync::LazyLock;

pub mod constant;

pub type Poseidon2KoalaBearHorizon<const WIDTH: usize> = Poseidon2<
    <KoalaBear as Field>::Packing,
    Poseidon2ExternalLayerHorizon<KoalaBear, WIDTH, SBOX_DEGREE>,
    Poseidon2InternalLayerHorizon<KoalaBear, WIDTH, SBOX_DEGREE>,
    WIDTH,
    SBOX_DEGREE,
>;

pub fn poseidon2_koala_bear_horizon_t16() -> &'static Poseidon2KoalaBearHorizon<16> {
    static INSTANCE: LazyLock<Poseidon2KoalaBearHorizon<16>> = LazyLock::new(|| {
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

pub fn poseidon2_koala_bear_horizon_t24() -> &'static Poseidon2KoalaBearHorizon<24> {
    static INSTANCE: LazyLock<Poseidon2KoalaBearHorizon<24>> = LazyLock::new(|| {
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
