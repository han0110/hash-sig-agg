use clap::Parser;
use core::{fmt::Write, iter::zip};
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

    let metric = |key_name| {
        let key = CompositeKey::new(MetricKind::Gauge, Key::from_name(key_name));
        match snapshot[&key].2 {
            #[allow(clippy::cast_sign_loss)]
            DebugValue::Gauge(value) => Duration::from_millis(value.0 as u64),
            _ => unreachable!(),
        }
    };

    let mut parts = vec![("witgen", witgen)];
    parts.extend(
        [
            ("commit_main", "main_trace_commit_time_ms"),
            ("compute_perm", "generate_perm_trace_time_ms"),
            ("commit_perm", "perm_trace_commit_time_ms"),
            ("compute_quot", "quotient_poly_compute_time_ms"),
            ("commit_quot", "quotient_poly_commit_time_ms"),
            ("opening", "pcs_opening_time_ms"),
        ]
        .map(|(name, key_name)| (name, metric(key_name))),
    );
    parts.push(("rest", proving - parts.iter().map(|(_, time)| time).sum()));

    let ratio = |time: Duration| 100.0 * time.as_secs_f64() / proving.as_secs_f64();
    let mut s = String::new();
    for (idx, (name, time)) in parts.into_iter().enumerate() {
        s.extend((idx > 0).then_some('\n'));
        write!(&mut s, "  {name}: {time:.2?} ({:02.2}%)", ratio(time)).unwrap();
    }
    s
}
