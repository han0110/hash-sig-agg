use crate::{PublicKey, Signature, LOG_LIFETIME, MSG_LEN};
use core::{array::from_fn, fmt::Debug};
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

pub mod poseidon2;
pub mod sha3;

/// Target sum instantiation.
pub trait Instantiation<const NUM_CHUNKS: usize> {
    type Parameter: Clone
        + Copy
        + Debug
        + Default
        + PartialEq
        + Send
        + Sync
        + Serialize
        + DeserializeOwned;
    type Hash: Clone
        + Copy
        + Debug
        + Default
        + PartialEq
        + Send
        + Sync
        + Serialize
        + DeserializeOwned;
    type Rho: Clone
        + Copy
        + Debug
        + Default
        + PartialEq
        + Send
        + Sync
        + Serialize
        + DeserializeOwned;

    const TARGET_SUM: u16 = (NUM_CHUNKS + NUM_CHUNKS.div_ceil(2)) as u16;

    fn random_parameter(rng: impl Rng) -> Self::Parameter;

    fn random_hash(rng: impl Rng) -> Self::Hash;

    fn random_rho(rng: impl Rng) -> Self::Rho;

    fn encode(
        epoch: u32,
        msg: [u8; MSG_LEN],
        parameter: Self::Parameter,
        rho: Self::Rho,
    ) -> [u16; NUM_CHUNKS];

    fn chain(
        epoch: u32,
        parameter: Self::Parameter,
        i: u16,
        x_i: u16,
        one_time_sig_i: Self::Hash,
    ) -> Self::Hash;

    fn merkle_root(
        epoch: u32,
        parameter: Self::Parameter,
        one_time_pk: [Self::Hash; NUM_CHUNKS],
        merkle_siblings: [Self::Hash; LOG_LIFETIME],
    ) -> Self::Hash;

    fn verify(
        epoch: u32,
        msg: [u8; MSG_LEN],
        pk: PublicKey<Self::Parameter, Self::Hash>,
        sig: Signature<Self::Rho, Self::Hash, NUM_CHUNKS>,
    ) -> Result<(), String> {
        let x = Self::encode(epoch, msg, pk.parameter, sig.rho);
        if x.iter().sum::<u16>() != Self::TARGET_SUM {
            return Err("Unmatched target sum".to_string());
        }
        let one_time_pk =
            from_fn(|i| Self::chain(epoch, pk.parameter, i as _, x[i], sig.one_time_sig[i]));
        if Self::merkle_root(epoch, pk.parameter, one_time_pk, sig.merkle_siblings)
            != pk.merkle_root
        {
            return Err("Unmatched merkle root".to_string());
        }
        Ok(())
    }
}
