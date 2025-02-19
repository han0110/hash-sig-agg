use clap::Parser;
use core::iter::zip;
use hash_sig_agg_circuit_openvm::{
    poseidon2::{chip::generate_air_proof_inputs, E, F},
    util::engine::Engine,
};
use hash_sig_testdata::mock_vi;
use openvm_stark_backend::{engine::StarkEngine, prover::types::ProofInput};
use std::time::{Duration, Instant};
use tracing_forest::{util::LevelFilter, ForestLayer};
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

#[derive(Clone, Debug, clap::Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, short = 'r', default_value_t = 1)]
    log_blowup: usize,
    #[arg(long, short = 'l', default_value_t = 13)]
    log_signatures: usize,
    #[arg(long, short = 'p', default_value_t = 0)]
    proof_of_work_bits: usize,
    #[arg(long, short)]
    trace: bool,
}

fn main() {
    let args: Args = Parser::parse();

    let engine = Engine::<F, E>::new(args.log_blowup, args.proof_of_work_bits);
    let vi = mock_vi(1 << args.log_signatures);

    let pk = {
        let (airs, _) = generate_air_proof_inputs(args.log_blowup, vi.clone());
        let mut keygen_builder = engine.keygen_builder();
        engine.set_up_keygen_builder(&mut keygen_builder, &airs);
        keygen_builder.generate_pk()
    };

    // Warm up
    {
        let mut elapsed = Duration::default();
        while elapsed.as_secs() < 3 {
            let start = Instant::now();
            let (_, inputs) = generate_air_proof_inputs(args.log_blowup, vi.clone());
            engine.prove(&pk, ProofInput::new(zip(0.., inputs.clone()).collect()));
            elapsed += start.elapsed();
        }
    }

    if args.trace {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    }

    let start = Instant::now();
    let (_, inputs) = generate_air_proof_inputs(args.log_blowup, vi);
    let proof = engine.prove(&pk, ProofInput::new(zip(0.., inputs).collect()));
    let proving_time = start.elapsed();

    let start = Instant::now();
    engine.verify(&pk.get_vk(), &proof).unwrap();
    let verifying_time = start.elapsed();

    let throughput = f64::from(1 << args.log_signatures) / proving_time.as_secs_f64();
    let proof_size_mb = (bincode::serialize(&proof).unwrap().len() as f64) / 1024f64 / 1024f64;

    println!(
        r"proving time: {proving_time:.2?}
throughput: {throughput:.2} sigs/s
proof_size: {proof_size_mb:.2} MB
verifying time: {verifying_time:.2?}"
    );
}
