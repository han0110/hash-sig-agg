extern crate alloc;

use core::array::from_fn;
use hash_sig_verifier::{
    instantiation::{
        sha3::{Sha3Digest, Sha3TargetSum, NUM_CHUNKS},
        Instantiation,
    },
    VerificationInput,
};
use openvm::io::{read_vec, reveal};
use openvm_keccak256_guest::keccak256;

openvm::entry!(main);

#[derive(Debug)]
struct Keccak256;

impl Sha3Digest for Keccak256 {
    fn sha3_digest<const I: usize, const O: usize>(input: [u8; I]) -> [u8; O] {
        let output = keccak256(&input);
        from_fn(|i| output[i])
    }
}

fn main() {
    type I = Sha3TargetSum<Keccak256>;
    let vi: VerificationInput<I, NUM_CHUNKS> = bincode::deserialize(&read_vec()).unwrap();
    vi.pairs.chunks(32).enumerate().for_each(|(idx, pairs)| {
        let outputs = pairs
            .iter()
            .map(|(pk, sig)| I::verify(vi.epoch, vi.msg, *pk, *sig).is_ok());
        reveal(outputs.rfold(0, |acc, bit| (acc << 1) ^ bit as u32), idx);
    });
}
