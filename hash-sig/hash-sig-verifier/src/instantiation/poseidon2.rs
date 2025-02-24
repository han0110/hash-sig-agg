use crate::{concat_array, instantiation::Instantiation, LOG_LIFETIME, MSG_LEN};
use core::{array::from_fn, fmt::Debug, iter::zip, marker::PhantomData};
use num_bigint::BigUint;
use p3_field::PrimeField32;
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{Deserialize, Serialize};

pub mod baby_bear_horizon;
pub mod koala_bear_horizon;

pub const PARAM_FE_LEN: usize = 5;
pub const HASH_FE_LEN: usize = 7;
pub const RHO_FE_LEN: usize = 6;
pub const MSG_FE_LEN: usize = (8 * MSG_LEN).div_ceil(31);
pub const MSG_HASH_FE_LEN: usize = 5;
pub const TWEAK_FE_LEN: usize = 2;
pub const CHUNK_SIZE: usize = 2;
pub const NUM_CHUNKS: usize = (31 * MSG_HASH_FE_LEN).div_ceil(CHUNK_SIZE);
pub const TARGET_SUM: u16 = (NUM_CHUNKS + NUM_CHUNKS.div_ceil(2)) as u16;

pub const SPONGE_CAPACITY: usize = 9;
pub const SPONGE_RATE: usize = 24 - SPONGE_CAPACITY;
pub const SPONGE_INPUT_SIZE: usize = PARAM_FE_LEN + TWEAK_FE_LEN + NUM_CHUNKS * HASH_FE_LEN;
pub const SPONGE_PERM: usize = SPONGE_INPUT_SIZE.div_ceil(SPONGE_RATE);

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Poseidon2TargetSum<P>(PhantomData<P>);

impl<P: Poseidon2Parameter> Instantiation<NUM_CHUNKS> for Poseidon2TargetSum<P>
where
    Standard: Distribution<P::F>,
{
    type Parameter = [P::F; PARAM_FE_LEN];
    type Hash = [P::F; HASH_FE_LEN];
    type Rho = [P::F; RHO_FE_LEN];

    fn random_parameter(mut rng: impl Rng) -> Self::Parameter {
        from_fn(|_| rng.gen())
    }

    fn random_hash(mut rng: impl Rng) -> Self::Hash {
        from_fn(|_| rng.gen())
    }

    fn random_rho(mut rng: impl Rng) -> Self::Rho {
        from_fn(|_| rng.gen())
    }

    fn encode(
        epoch: u32,
        msg: [u8; MSG_LEN],
        parameter: Self::Parameter,
        rho: Self::Rho,
    ) -> Result<[u16; NUM_CHUNKS], String> {
        let msg_hash = P::compress_t24::<22, MSG_HASH_FE_LEN>(concat_array![
            rho,
            parameter,
            encode_tweak_msg(epoch),
            encode_msg(msg),
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
        (x_i + 1..(1 << CHUNK_SIZE)).fold(one_time_sig_i, |value, k| {
            const I: usize = PARAM_FE_LEN + TWEAK_FE_LEN + HASH_FE_LEN;
            P::compress_t16::<I, HASH_FE_LEN>(concat_array![
                parameter,
                encode_tweak_chain(epoch, i, k),
                value
            ])
        })
    }

    fn merkle_root(
        epoch: u32,
        parameter: Self::Parameter,
        one_time_pk: [Self::Hash; NUM_CHUNKS],
        merkle_siblings: [Self::Hash; LOG_LIFETIME],
    ) -> Self::Hash {
        zip(1.., merkle_siblings).fold(
            P::sponge::<SPONGE_INPUT_SIZE, HASH_FE_LEN>(concat_array![
                parameter,
                encode_tweak_merkle_tree(0, epoch),
                one_time_pk.into_iter().flatten(),
            ]),
            |node, (level, sibling)| {
                const I: usize = PARAM_FE_LEN + TWEAK_FE_LEN + 2 * HASH_FE_LEN;
                P::compress_t24::<I, HASH_FE_LEN>(concat_array![
                    parameter,
                    encode_tweak_merkle_tree(level, epoch >> level),
                    (if (epoch >> (level - 1)) & 1 == 0 {
                        [node, sibling]
                    } else {
                        [sibling, node]
                    })
                    .into_iter()
                    .flatten()
                ])
            },
        )
    }
}

pub trait Poseidon2Parameter: Clone + Copy + Debug + Sized + Send + Sync {
    type F: PrimeField32;

    const CAPACITY_VALUES: [Self::F; SPONGE_CAPACITY];

    fn permutation_t16(state: [Self::F; 16]) -> [Self::F; 16];

    fn permutation_t24(state: [Self::F; 24]) -> [Self::F; 24];

    fn compress_t16<const I: usize, const O: usize>(input: [Self::F; I]) -> [Self::F; O] {
        const { assert!(I >= O && I <= 16) };
        let padded = from_fn(|i| input.get(i).copied().unwrap_or_default());
        let output = Self::permutation_t16(padded);
        from_fn(|i| input[i] + output[i])
    }

    fn compress_t24<const I: usize, const O: usize>(input: [Self::F; I]) -> [Self::F; O] {
        const { assert!(I >= O && I <= 24) };
        let padded = from_fn(|i| input.get(i).copied().unwrap_or_default());
        let output = Self::permutation_t24(padded);
        from_fn(|i| input[i] + output[i])
    }

    fn sponge<const I: usize, const O: usize>(input: [Self::F; I]) -> [Self::F; O] {
        let mut state = from_fn(|i| {
            i.checked_sub(SPONGE_RATE)
                .map(|i| Self::CAPACITY_VALUES[i])
                .unwrap_or_default()
        });
        input.chunks(SPONGE_RATE).for_each(|block| {
            zip(&mut state, block).for_each(|(state, block)| *state += *block);
            state = Self::permutation_t24(state);
        });
        from_fn(|i| state[i])
    }
}

pub fn msg_hash_to_chunks<F: PrimeField32>(hash: [F; MSG_HASH_FE_LEN]) -> [u16; NUM_CHUNKS] {
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    let bytes = hash
        .into_iter()
        .fold(BigUint::ZERO, |acc, v| {
            acc * F::ORDER_U32 + v.as_canonical_u32()
        })
        .to_bytes_le();
    from_fn(|i| {
        bytes
            .get((i * CHUNK_SIZE) / 8)
            .map_or(0, |byte| ((byte >> ((i * CHUNK_SIZE) % 8)) & MASK))
            .into()
    })
}

pub fn encode_msg<F: PrimeField32>(msg: [u8; MSG_LEN]) -> [F; MSG_FE_LEN] {
    decompose(BigUint::from_bytes_le(&msg))
}

pub fn encode_tweak_chain<F: PrimeField32>(epoch: u32, i: u16, k: u16) -> [F; TWEAK_FE_LEN] {
    const SEP: u32 = 0x00;
    [
        F::from_canonical_u32((epoch << 2) | SEP),
        F::from_canonical_u32((u32::from(i) << 16) | u32::from(k)),
    ]
}

pub fn encode_tweak_merkle_tree<F: PrimeField32>(l: u8, i: u32) -> [F; TWEAK_FE_LEN] {
    const SEP: u32 = 0x01;
    [
        F::from_canonical_u32((u32::from(l) << 2) | SEP),
        F::from_canonical_u32(i),
    ]
}

pub fn encode_tweak_msg<F: PrimeField32>(epoch: u32) -> [F; TWEAK_FE_LEN] {
    const SEP: u32 = 0x02;
    const { assert!(LOG_LIFETIME < 28) };
    [F::from_canonical_u32(epoch << 2 | SEP), F::ZERO]
}

pub fn decompose<F: PrimeField32, const N: usize>(big: impl Into<BigUint>) -> [F; N] {
    let mut big = big.into();
    from_fn(|_| {
        let rem = &big % &BigUint::from(F::ORDER_U32);
        big /= BigUint::from(F::ORDER_U32);
        F::from_canonical_u32(rem.iter_u32_digits().next().unwrap_or_default())
    })
}

#[cfg(test)]
mod test {
    use crate::{
        instantiation::{
            poseidon2::{baby_bear_horizon::BabyBearHorizon, Poseidon2TargetSum},
            Instantiation,
        },
        PublicKey, Signature, LOG_LIFETIME,
    };
    use core::array::from_fn;
    use hashsig::signature::{
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W2NoOff,
        SignatureScheme,
    };
    use num_bigint::BigUint;
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use rand::{thread_rng, Rng};

    #[test]
    fn consistency() {
        type HashSig = SIGTargetSumLifetime20W2NoOff;
        type HashSigVerifier = Poseidon2TargetSum<BabyBearHorizon>;

        let ark_to_p3 = |v| BabyBear::from_canonical_u32(u32::try_from(BigUint::from(v)).unwrap());

        let mut rng = thread_rng();
        let (pk, sk) = HashSig::gen(&mut rng);
        for _ in 0..100 {
            let epoch = rng.gen_range(0..1 << LOG_LIFETIME);
            let msg = rng.gen();
            let sig = HashSig::sign(&mut rng, &sk, epoch, &msg).unwrap();
            assert!(HashSig::verify(&pk, epoch, &msg, &sig));
            assert!(HashSigVerifier::verify(
                epoch,
                msg,
                PublicKey {
                    parameter: pk.parameter().map(ark_to_p3),
                    merkle_root: pk.root().map(ark_to_p3),
                },
                Signature {
                    rho: sig.rho().map(ark_to_p3),
                    one_time_sig: from_fn(|i| sig.hashes()[i].map(ark_to_p3)),
                    merkle_siblings: from_fn(|i| sig.path().co_path()[i].map(ark_to_p3)),
                }
            )
            .is_ok());
        }
    }
}
