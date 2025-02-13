use core::array::from_fn;
use hash_sig::{
    instantiation::{
        poseidon2::{
            self, baby_bear_horizon::BabyBearHorizon, koala_bear_horizon::KoalaBearHorizon,
            Poseidon2Instantiation,
        },
        sha3::{self, Keccak256, Sha3Instantiation, Sha3_256},
        Instantiation,
    },
    PublicKey, Signature, VerificationInput,
};
use rand::{random, thread_rng};
use rayon::prelude::*;
use std::{fs, path::PathBuf};

const SIZES: [usize; 14] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
];

fn main() {
    {
        type I = Sha3Instantiation<Sha3_256>;
        generate_mock_vi::<I, { sha3::NUM_CHUNKS }>("sha3", SIZES);
    }
    {
        type I = Sha3Instantiation<Keccak256>;
        generate_mock_vi::<I, { sha3::NUM_CHUNKS }>("keccak256", SIZES);
    }
    {
        type I = Poseidon2Instantiation<BabyBearHorizon>;
        generate_mock_vi::<I, { poseidon2::NUM_CHUNKS }>("poseidon2_baby_bear_horizon", SIZES);
    }
    {
        type I = Poseidon2Instantiation<KoalaBearHorizon>;
        generate_mock_vi::<I, { poseidon2::NUM_CHUNKS }>("poseidon2_koala_bear_horizon", SIZES);
    }
}

fn generate_mock_vi<I: Instantiation<NUM_CHUNKS>, const NUM_CHUNKS: usize>(
    dir: &str,
    sizes: impl IntoParallelIterator<Item = usize>,
) {
    sizes.into_par_iter().for_each(|size| {
        let vi = mock_vi::<I, NUM_CHUNKS>(size);
        let path = PathBuf::from_iter([env!("CARGO_MANIFEST_DIR"), dir, &format!("{size}")]);
        fs::write(&path, bincode::serialize(&vi).unwrap()).unwrap();
    });
}

fn mock_vi<I: Instantiation<NUM_CHUNKS>, const NUM_CHUNKS: usize>(
    size: usize,
) -> VerificationInput<I, NUM_CHUNKS> {
    let epoch = random();
    let msg = random();
    let pairs = (0..size)
        .into_par_iter()
        .map(|_| {
            let mut rng = thread_rng();
            let mut pk = PublicKey {
                parameter: I::random_parameter(&mut rng),
                merkle_root: Default::default(),
            };
            let mut sig = Signature {
                rho: Default::default(),
                one_time_sig: from_fn(|_| I::random_hash(&mut rng)),
                merkle_siblings: from_fn(|_| I::random_hash(&mut rng)),
            };
            (sig.rho, pk.merkle_root) = {
                let (x, rho) = loop {
                    let rho = I::random_rho(&mut rng);
                    let x = I::encode(epoch, msg, pk.parameter, rho);
                    if x.iter().copied().sum::<u16>() == I::TARGET_SUM {
                        break (x, rho);
                    }
                };

                let one_time_pk: [I::Hash; NUM_CHUNKS] =
                    from_fn(|i| I::chain(epoch, pk.parameter, i as _, x[i], sig.one_time_sig[i]));

                (
                    rho,
                    I::merkle_root(epoch, pk.parameter, one_time_pk, sig.merkle_siblings),
                )
            };
            I::verify(epoch, msg, pk, sig).unwrap();
            (pk, sig)
        })
        .collect::<Vec<_>>();
    VerificationInput { epoch, msg, pairs }
}
