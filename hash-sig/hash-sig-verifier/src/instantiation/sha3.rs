use crate::{concat_array, instantiation::Instantiation, LOG_LIFETIME, MSG_LEN};
use core::{array::from_fn, fmt::Debug, iter::zip, marker::PhantomData};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::Digest;

pub use sha3::{Keccak256, Sha3_256};

pub const PARAM_LEN: usize = 18;
pub const HASH_LEN: usize = 26;
pub const RHO_LEN: usize = 23;
pub const MSG_HASH_LEN: usize = 18;
pub const TWEAK_CHAIN_LEN: usize = 9;
pub const TWEAK_MERKLE_TREE_LEN: usize = 6;
pub const TWEAK_MSG_LEN: usize = 5;
pub const CHUNK_SIZE: usize = 2;
pub const NUM_CHUNKS: usize = (8 * MSG_HASH_LEN).div_ceil(CHUNK_SIZE);
pub const TARGET_SUM: u16 = (NUM_CHUNKS + NUM_CHUNKS.div_ceil(2)) as u16;

pub trait Sha3Digest: Debug + Sized + Send + Sync {
    fn sha3_digest<const I: usize, const O: usize>(input: [u8; I]) -> [u8; O];
}

impl Sha3Digest for Keccak256 {
    fn sha3_digest<const I: usize, const O: usize>(input: [u8; I]) -> [u8; O] {
        let digest = Self::digest(input);
        from_fn(|i| digest[i])
    }
}

impl Sha3Digest for Sha3_256 {
    fn sha3_digest<const I: usize, const O: usize>(input: [u8; I]) -> [u8; O] {
        let digest = Self::digest(input);
        from_fn(|i| digest[i])
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Sha3TargetSum<P>(PhantomData<P>);

impl<P> Clone for Sha3TargetSum<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Sha3TargetSum<P> {}

impl<P: Sha3Digest> Instantiation<NUM_CHUNKS> for Sha3TargetSum<P> {
    type Parameter = [u8; PARAM_LEN];
    type Hash = [u8; HASH_LEN];
    type Rho = [u8; RHO_LEN];

    fn random_parameter(mut rng: impl Rng) -> Self::Parameter {
        rng.gen()
    }

    fn random_hash(mut rng: impl Rng) -> Self::Hash {
        rng.gen()
    }

    fn random_rho(mut rng: impl Rng) -> Self::Rho {
        rng.gen()
    }

    fn encode(
        epoch: u32,
        msg: [u8; MSG_LEN],
        parameter: Self::Parameter,
        rho: Self::Rho,
    ) -> Result<[u16; NUM_CHUNKS], String> {
        const I: usize = RHO_LEN + PARAM_LEN + TWEAK_MSG_LEN + MSG_LEN;
        let msg_hash = P::sha3_digest::<I, MSG_HASH_LEN>(concat_array![
            rho,
            parameter,
            encode_tweak_msg(epoch),
            msg
        ]);
        let x = msg_hash_to_chunks(msg_hash);
        if x.into_iter().sum::<u16>() != TARGET_SUM {
            return Err("Unmatched target sum".to_string());
        }
        Ok(x)
    }

    fn chain(
        epoch: u32,
        parameter: Self::Parameter,
        i: u16,
        x_i: u16,
        one_time_sig_i: Self::Hash,
    ) -> Self::Hash {
        const I: usize = PARAM_LEN + TWEAK_CHAIN_LEN + HASH_LEN;
        (x_i + 1..(1 << CHUNK_SIZE)).fold(one_time_sig_i, |value, step| {
            P::sha3_digest::<I, HASH_LEN>(concat_array![
                parameter,
                encode_tweak_chain(epoch, i, step),
                value,
            ])
        })
    }

    fn merkle_root(
        epoch: u32,
        parameter: Self::Parameter,
        one_time_pk: [Self::Hash; NUM_CHUNKS],
        merkle_siblings: [Self::Hash; LOG_LIFETIME],
    ) -> Self::Hash {
        zip(1u8.., merkle_siblings).fold(
            {
                const I: usize = PARAM_LEN + TWEAK_MERKLE_TREE_LEN + NUM_CHUNKS * HASH_LEN;
                P::sha3_digest::<I, HASH_LEN>(concat_array![
                    parameter,
                    encode_tweak_merkle_tree(0, epoch),
                    one_time_pk.into_iter().flatten(),
                ])
            },
            |node, (level, sibling)| {
                const I: usize = PARAM_LEN + TWEAK_MERKLE_TREE_LEN + 2 * HASH_LEN;
                P::sha3_digest::<I, HASH_LEN>(concat_array![
                    parameter,
                    encode_tweak_merkle_tree(level, epoch >> level),
                    (if (epoch >> (level - 1)) & 1 == 0 {
                        [node, sibling]
                    } else {
                        [sibling, node]
                    })
                    .into_iter()
                    .flatten(),
                ])
            },
        )
    }
}

fn encode_tweak_chain(epoch: u32, i: u16, k: u16) -> [u8; 9] {
    const SEP: u8 = 0x00;
    concat_array![[SEP], epoch.to_be_bytes(), i.to_be_bytes(), k.to_be_bytes()]
}

fn encode_tweak_merkle_tree(l: u8, i: u32) -> [u8; 6] {
    const SEP: u8 = 0x01;
    concat_array![[SEP, l], i.to_be_bytes()]
}

fn encode_tweak_msg(epoch: u32) -> [u8; 5] {
    const SEP: u8 = 0x02;
    concat_array![[SEP], epoch.to_le_bytes()]
}

fn msg_hash_to_chunks(bytes: [u8; MSG_HASH_LEN]) -> [u16; NUM_CHUNKS] {
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    from_fn(|i| (bytes[(i * CHUNK_SIZE) / 8] >> ((i * CHUNK_SIZE) % 8) & MASK) as _)
}
