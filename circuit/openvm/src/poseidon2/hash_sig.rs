use crate::poseidon2::F;
use core::array::from_fn;
use hash_sig::{
    concat_array,
    instantiation::{
        self,
        poseidon2::{
            baby_bear_horizon::BabyBearHorizon, encode_tweak_chain, encode_tweak_merkle_tree,
            encode_tweak_msg, msg_hash_to_chunks, Poseidon2Parameter,
        },
        Instantiation,
    },
};
use num_bigint::BigUint;
use openvm_stark_backend::p3_field::PrimeField32;
use p3_maybe_rayon::prelude::*;

pub use hash_sig::{
    instantiation::poseidon2::{
        CHUNK_SIZE, HASH_FE_LEN, MSG_FE_LEN, MSG_HASH_FE_LEN, NUM_CHUNKS, PARAM_FE_LEN, RHO_FE_LEN,
        SPONGE_CAPACITY, SPONGE_INPUT_SIZE, SPONGE_PERM, SPONGE_RATE, TWEAK_FE_LEN,
    },
    LOG_LIFETIME, MSG_LEN,
};

pub type Poseidon2Instantiation = instantiation::poseidon2::Poseidon2Instantiation<BabyBearHorizon>;

pub type Signature = hash_sig::Signature<
    <Poseidon2Instantiation as Instantiation<NUM_CHUNKS>>::Rho,
    <Poseidon2Instantiation as Instantiation<NUM_CHUNKS>>::Hash,
    NUM_CHUNKS,
>;

pub type PublicKey = hash_sig::PublicKey<
    <Poseidon2Instantiation as Instantiation<NUM_CHUNKS>>::Parameter,
    <Poseidon2Instantiation as Instantiation<NUM_CHUNKS>>::Hash,
>;

pub type VerificationInput = hash_sig::VerificationInput<Poseidon2Instantiation, NUM_CHUNKS>;

pub const MODULUS: u32 = F::ORDER_U32;

pub const TARGET_SUM: u16 = <Poseidon2Instantiation as Instantiation<NUM_CHUNKS>>::TARGET_SUM;

pub const SPONGE_CAPACITY_VALUES: [F; SPONGE_CAPACITY] = BabyBearHorizon::CAPACITY_VALUES;

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
        let msg_hash = BabyBearHorizon::compress_t24::<24, MSG_HASH_FE_LEN>(concat_array![
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

    pub fn msg_hash_limbs(&self, limb_bits: usize) -> impl Iterator<Item = u32> {
        let mask = (1 << limb_bits) - 1;
        let mut big = self
            .msg_hash
            .into_iter()
            .fold(BigUint::ZERO, |acc, v| acc * MODULUS + v.as_canonical_u32());
        (0..(MSG_HASH_FE_LEN * F::ORDER_U32.next_power_of_two().ilog2() as usize)
            .div_ceil(limb_bits))
            .map(move |_| {
                let limb = big.iter_u32_digits().next().unwrap() & mask;
                big >>= limb_bits;
                limb
            })
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
            BabyBearHorizon::compress_t16::<16, HASH_FE_LEN>(input),
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
