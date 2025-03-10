use crate::instantiation::Instantiation;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

pub mod instantiation;
pub mod util;

pub const MSG_LEN: usize = 32;
pub const LOG_LIFETIME: usize = 20;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicKey<I: Instantiation<NUM_CHUNKS>, const NUM_CHUNKS: usize> {
    pub parameter: I::Parameter,
    pub merkle_root: I::Hash,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Signature<I: Instantiation<NUM_CHUNKS>, const NUM_CHUNKS: usize> {
    pub rho: I::Rho,
    #[serde(with = "serde_big_array::BigArray")]
    pub one_time_sig: [I::Hash; NUM_CHUNKS],
    pub merkle_siblings: [I::Hash; LOG_LIFETIME],
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerificationInput<I: Instantiation<NUM_CHUNKS>, const NUM_CHUNKS: usize> {
    pub epoch: u32,
    pub msg: [u8; MSG_LEN],
    pub pairs: Vec<(PublicKey<I, NUM_CHUNKS>, Signature<I, NUM_CHUNKS>)>,
}
