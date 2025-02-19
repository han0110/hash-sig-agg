use clap::Parser;
use core::iter::zip;
use hash_sig_agg_circuit_openvm::{
    poseidon2::{chip::generate_air_proof_inputs, E, F},
    util::engine::Engine,
};
use hash_sig_testdata::mock_vi;
use metrics::Key;
use metrics_tracing_context::TracingContextLayer;
use metrics_util::{
    debugging::{DebugValue, DebuggingRecorder, Snapshot},
    layers::Layer,
    CompositeKey, MetricKind,
};
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

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let recorder = TracingContextLayer::all().layer(recorder);
    metrics::set_global_recorder(recorder).unwrap();

    let start = Instant::now();
    let (_, inputs) = generate_air_proof_inputs(args.log_blowup, vi);
    let witgen_time = start.elapsed();
    let proof = engine.prove(&pk, ProofInput::new(zip(0.., inputs).collect()));
    let proving_time = start.elapsed();
    let proving_time_parts = proving_time_parts(proving_time, witgen_time, snapshotter.snapshot());

    let start = Instant::now();
    engine.verify(&pk.get_vk(), &proof).unwrap();
    let verifying_time = start.elapsed();

    let throughput = f64::from(1 << args.log_signatures) / proving_time.as_secs_f64();
    let proof_size_mb = (bincode::serialize(&proof).unwrap().len() as f64) / 1024f64 / 1024f64;

    println!(
        r"proving time: {proving_time:.2?}
{proving_time_parts}
throughput: {throughput:.2} sigs/s
proof_size: {proof_size_mb:.2} MB
verifying time: {verifying_time:.2?}",
    );
}

fn proving_time_parts(proving: Duration, witgen: Duration, snapshot: Snapshot) -> String {
    #[allow(clippy::mutable_key_type)]
    let snapshot = snapshot.into_hashmap();

    let part = |name| {
        let key = CompositeKey::new(MetricKind::Gauge, Key::from_name(name));
        match snapshot[&key].2 {
            #[allow(clippy::cast_sign_loss)]
            DebugValue::Gauge(value) => Duration::from_millis(value.0 as u64),
            _ => unreachable!(),
        }
    };
    let [commit_main, compute_perm, commit_perm, compute_quot, commit_quot, opening] = [
        "main_trace_commit_time_ms",
        "generate_perm_trace_time_ms",
        "perm_trace_commit_time_ms",
        "quotient_poly_compute_time_ms",
        "quotient_poly_commit_time_ms",
        "pcs_opening_time_ms",
    ]
    .map(part);

    let rest = proving
        - (witgen
            + commit_main
            + compute_perm
            + commit_perm
            + compute_quot
            + commit_quot
            + opening);

    let ratio = |n: Duration| 100.0 * n.as_secs_f64() / proving.as_secs_f64();
    format!(
        r"  witgen: {witgen:.2?} ({:02.2}%)
  commit_main: {commit_main:?} ({:02.2}%)
  compute_perm: {compute_perm:?} ({:02.2}%)
  commit_perm: {commit_perm:?} ({:02.2}%)
  compute_quot: {compute_quot:?} ({:02.2}%)
  commit_quot: {commit_quot:?} ({:02.2}%)
  opening: {opening:?} ({:02.2}%)
  rest: {rest:.2?} ({:02.2}%)",
        ratio(witgen),
        ratio(commit_main),
        ratio(compute_perm),
        ratio(commit_perm),
        ratio(compute_quot),
        ratio(commit_quot),
        ratio(opening),
        ratio(rest)
    )
}
