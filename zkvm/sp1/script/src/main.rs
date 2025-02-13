use clap::Parser;
use sp1_sdk::{client::ProverClientBuilder, include_elf, Prover, SP1Stdin};
use std::fs;

const POSEIDON2_ELF: &[u8] = include_elf!("sp1-poseidon2");
const SHA3_ELF: &[u8] = include_elf!("sp1-sha3");

#[derive(Parser)]
struct Args {
    #[clap(long)]
    input: String,
    #[clap(long)]
    debug: bool,
}

fn main() {
    let args = Args::parse();

    let elf = if args.input.contains("poseidon2") {
        POSEIDON2_ELF
    } else if args.input.contains("sha3") {
        SHA3_ELF
    } else {
        unreachable!()
    };

    let client = ProverClientBuilder.cpu().build();

    let (pk, vk) = client.setup(elf);

    let stdin = SP1Stdin::from(&fs::read(args.input).unwrap());

    if args.debug {
        println!("{:?}", client.execute(elf, &stdin).run().unwrap().0);
    };

    let proof = client.prove(&pk, &stdin).run().unwrap();

    client.verify(&proof, &vk).unwrap();
}
