use clap::Parser;
use hash_sig_testdata::mock_vi;
use hash_sig_verifier::instantiation::{
    poseidon2::{self, baby_bear_horizon::BabyBearHorizon, Poseidon2TargetSum},
    sha3::{self, Sha3TargetSum, Sha3_256},
};
use sp1_sdk::{client::ProverClientBuilder, include_elf, Prover, SP1Stdin};

const POSEIDON2_ELF: &[u8] = include_elf!("hash-sig-agg-zkvm-sp1-poseidon2-baby-bear");
const SHA3_ELF: &[u8] = include_elf!("hash-sig-agg-zkvm-sp1-sha3");

#[derive(Parser)]
struct Args {
    #[clap(long, short)]
    instantiation: Instantiation,
    #[clap(long)]
    size: usize,
    #[clap(long)]
    debug: bool,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum Instantiation {
    Poseidon2BabyBear,
    Sha3,
}

impl Instantiation {
    fn elf(&self) -> &'static [u8] {
        match self {
            Self::Poseidon2BabyBear => POSEIDON2_ELF,
            Self::Sha3 => SHA3_ELF,
        }
    }

    fn mock_vi(&self, size: usize) -> Vec<u8> {
        match self {
            Self::Sha3 => {
                type I = Sha3TargetSum<Sha3_256>;
                bincode::serialize(&mock_vi::<I, { sha3::NUM_CHUNKS }>(size)).unwrap()
            }
            Self::Poseidon2BabyBear => {
                type I = Poseidon2TargetSum<BabyBearHorizon>;
                bincode::serialize(&mock_vi::<I, { poseidon2::NUM_CHUNKS }>(size)).unwrap()
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    let elf = args.instantiation.elf();

    let client = ProverClientBuilder.cpu().build();

    let (pk, vk) = client.setup(elf);

    let stdin = SP1Stdin::from(&args.instantiation.mock_vi(args.size));

    if args.debug {
        let output = client.execute(elf, &stdin).run().unwrap().0;
        println!("{:?}", output.as_slice());
        output
            .as_slice()
            .iter()
            .flat_map(|byte| (0..8).map(|i| *byte >> i & 1 == 1))
            .take(args.size)
            .for_each(|is_valid| assert!(is_valid));
    };

    let proof = client.prove(&pk, &stdin).run().unwrap();

    client.verify(&proof, &vk).unwrap();
}
