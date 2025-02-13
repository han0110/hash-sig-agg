extern crate alloc;

use hash_sig::{
    instantiation::{
        poseidon2::{baby_bear_horizon::BabyBearHorizon, Poseidon2Instantiation, NUM_CHUNKS},
        Instantiation,
    },
    VerificationInput,
};
use openvm::io::{read_vec, reveal};

openvm::entry!(main);

// TODO: Use extension when possible.
// struct Poseidon2BabyBearHorizon;
// impl Poseidon2Parameter for Poseidon2BabyBearHorizon { ... }

fn main() {
    type I = Poseidon2Instantiation<BabyBearHorizon>;
    let vi: VerificationInput<I, NUM_CHUNKS> = bincode::deserialize(&read_vec()).unwrap();
    vi.pairs.chunks(32).enumerate().for_each(|(idx, pairs)| {
        let outputs = pairs
            .iter()
            .map(|(pk, sig)| I::verify(vi.epoch, vi.msg, *pk, *sig).is_ok());
        reveal(outputs.rfold(0, |acc, bit| (acc << 1) ^ bit as u32), idx);
    });
}
