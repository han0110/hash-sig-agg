use crate::poseidon2::{Poseidon2Parameter, F};
use core::array::from_fn;
use hash_sig_verifier::{
    concat_array,
    instantiation::{
        self,
        poseidon2::{msg_hash_to_chunks, Poseidon2Parameter as _},
    },
};
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::*;

pub use hash_sig_verifier::{
    instantiation::poseidon2::{
        encode_msg, encode_tweak_chain, encode_tweak_merkle_tree, encode_tweak_msg, CHUNK_SIZE,
        HASH_FE_LEN, MSG_FE_LEN, MSG_HASH_FE_LEN, NUM_CHUNKS, PARAM_FE_LEN, RHO_FE_LEN,
        SPONGE_CAPACITY, SPONGE_INPUT_SIZE, SPONGE_PERM, SPONGE_RATE, TARGET_SUM, TWEAK_FE_LEN,
    },
    LOG_LIFETIME, MSG_LEN,
};

pub type Poseidon2TargetSum = instantiation::poseidon2::Poseidon2TargetSum<Poseidon2Parameter>;

pub type Signature = hash_sig_verifier::Signature<Poseidon2TargetSum, NUM_CHUNKS>;

pub type PublicKey = hash_sig_verifier::PublicKey<Poseidon2TargetSum, NUM_CHUNKS>;

pub type VerificationInput = hash_sig_verifier::VerificationInput<Poseidon2TargetSum, NUM_CHUNKS>;

pub const MODULUS: u32 = F::ORDER_U32;

pub const SPONGE_CAPACITY_VALUES: [F; SPONGE_CAPACITY] = Poseidon2Parameter::CAPACITY_VALUES;

#[derive(Clone, Copy, Debug)]
pub struct VerificationTrace {
    pub pk: PublicKey,
    pub sig: Signature,
    pub msg_hash: [F; MSG_HASH_FE_LEN],
    pub x: [u16; NUM_CHUNKS],
    pub one_time_pk: [[F; HASH_FE_LEN]; NUM_CHUNKS],
    pub chain_inputs: [[F; 16]; TARGET_SUM as usize],
}

impl VerificationTrace {
    pub fn generate(
        epoch: u32,
        encoded_msg: [F; MSG_FE_LEN],
        pk: PublicKey,
        sig: Signature,
    ) -> Self {
        let msg_hash = Poseidon2Parameter::compress_t24::<24, MSG_HASH_FE_LEN>(concat_array![
            sig.rho,
            pk.parameter,
            encode_tweak_msg(epoch),
            encoded_msg,
        ]);
        let x = msg_hash_to_chunks(msg_hash);
        let (one_time_pk, chain_inputs) = (0..NUM_CHUNKS)
            .into_par_iter()
            .map(|i| chain_and_input(epoch, pk.parameter, i as _, x[i], sig.one_time_sig[i]))
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let chain_inputs = {
            let mut iter = chain_inputs.into_iter().flatten();
            let chain_inputs = from_fn(|_| iter.next().unwrap());
            debug_assert!(iter.next().is_none());
            chain_inputs
        };
        Self {
            pk,
            sig,
            msg_hash,
            x,
            one_time_pk: one_time_pk.try_into().unwrap(),
            chain_inputs,
        }
    }

    pub fn msg_hash_preimage(&self, epoch: u32, encoded_msg: [F; MSG_FE_LEN]) -> [F; 24] {
        concat_array![
            self.sig.rho,
            self.pk.parameter,
            encode_tweak_msg(epoch),
            encoded_msg,
        ]
    }

    pub fn merkle_tree_leaf(&self, epoch: u32) -> [F; SPONGE_INPUT_SIZE] {
        concat_array![
            self.pk.parameter,
            encode_tweak_merkle_tree(0, epoch),
            self.one_time_pk.into_iter().flatten()
        ]
    }
}

pub fn chain_and_input(
    epoch: u32,
    parameter: [F; PARAM_FE_LEN],
    i: u16,
    x_i: u16,
    one_time_sig_i: [F; HASH_FE_LEN],
) -> ([F; HASH_FE_LEN], Vec<[F; 16]>) {
    (x_i + 1..(1 << CHUNK_SIZE)).fold((one_time_sig_i, Vec::new()), |(value, mut inputs), k| {
        let input = concat_array![parameter, encode_tweak_chain(epoch, i, k), value];
        inputs.push(input);
        (
            Poseidon2Parameter::compress_t16::<16, HASH_FE_LEN>(input),
            inputs,
        )
    })
}

#[cfg(test)]
pub mod test {
    use crate::poseidon2::hash_sig::VerificationInput;

    pub fn mock_vi(size: usize) -> VerificationInput {
        hash_sig_testdata::mock_vi(size)
    }
}
