use core::array::from_fn;
use hash_sig_verifier::{
    instantiation::Instantiation, PublicKey, Signature, VerificationInput, LOG_LIFETIME,
};
use rand::{random, thread_rng};
use rayon::prelude::*;

pub fn mock_vi<I: Instantiation<NUM_CHUNKS>, const NUM_CHUNKS: usize>(
    size: usize,
) -> VerificationInput<I, NUM_CHUNKS> {
    let epoch = random::<u32>() % (1 << LOG_LIFETIME);
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
                    if let Ok(x) = I::encode(epoch, msg, pk.parameter, rho) {
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
