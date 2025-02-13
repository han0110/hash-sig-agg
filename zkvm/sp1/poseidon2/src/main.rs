#![no_main]

use hash_sig::{
    instantiation::{
        poseidon2::{baby_bear_horizon::BabyBearHorizon, Poseidon2Instantiation, NUM_CHUNKS},
        Instantiation,
    },
    VerificationInput,
};
use sp1_zkvm::io::{commit_slice, read_vec};

sp1_zkvm::entrypoint!(main);

// TODO: Use precompile when possible.
// struct Poseidon2BabyBearHorizon;
// impl Poseidon2Parameter for Poseidon2BabyBearHorizon { ... }

pub fn main() {
    type I = Poseidon2Instantiation<BabyBearHorizon>;
    let vi: VerificationInput<I, NUM_CHUNKS> = bincode::deserialize(&read_vec()).unwrap();
    let output = vi
        .pairs
        .chunks(8)
        .map(|pairs| {
            let outputs = pairs
                .iter()
                .map(|(pk, sig)| I::verify(vi.epoch, vi.msg, *pk, *sig).is_ok());
            outputs.rfold(0, |acc, bit| (acc << 1) ^ bit as u8)
        })
        .collect::<Vec<_>>();
    commit_slice(&output);
}
