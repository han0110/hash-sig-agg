use clap::{Parser, builder::PossibleValuesParser};
use core::fmt::Debug;
use hash_sig_agg_circuit_openvm::{
    poseidon2::{
        F,
        chip::{generate_prover_inputs, verifier_inputs},
    },
    util::engine::{Engine, EngineConfig, keccak::KeccakConfig, poseidon2::Poseidon2Config},
};
use hash_sig_testdata::mock_vi;
use p3_commit::{Pcs, PolynomialSpace};
use std::time::Instant;
use util::{human_size, human_time, init_tracing, proving_time_components};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone, Debug, clap::Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, short = 'm', default_value_t = String::from("keccak"), value_parser = PossibleValuesParser::new(["keccak", "poseidon2"]))]
    pcs_merkle_hash: String,
    #[arg(long, short = 'r', default_value_t = 1)]
    log_blowup: usize,
    #[arg(long, short = 'l', default_value_t = 13)]
    log_signatures: usize,
    #[arg(long, short = 'p', default_value_t = 0)]
    proof_of_work_bits: usize,
    #[arg(long, short = 's', default_value_t = String::from("provable"), value_parser = PossibleValuesParser::new(["provable", "conjecture"]))]
    soundness_type: String,
}

fn main() {
    let Args {
        pcs_merkle_hash,
        log_blowup,
        log_signatures,
        proof_of_work_bits,
        soundness_type,
    }: Args = Parser::parse();
    let soundness_type = soundness_type.parse().unwrap();
    let log_final_poly_len = log_signatures.saturating_sub(1).min(3);

    match pcs_merkle_hash.as_str() {
        "keccak" => {
            let engine = Engine::<KeccakConfig>::new(
                log_blowup,
                log_final_poly_len,
                proof_of_work_bits,
                soundness_type,
            );
            run(&engine, log_signatures);
        }
        "poseidon2" => {
            let engine = Engine::<Poseidon2Config>::new(
                log_blowup,
                log_final_poly_len,
                proof_of_work_bits,
                soundness_type,
            );
            run(&engine, log_signatures);
        }
        _ => unreachable!(),
    }
}

fn run<C: EngineConfig>(engine: &Engine<C>, log_signatures: usize)
where
    <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Domain: PolynomialSpace<Val = F>,
{
    let vi = mock_vi(1 << log_signatures);
    let verifier_inputs = verifier_inputs(vi.epoch, vi.msg);
    let (vk, pk) = engine.keygen(&verifier_inputs);

    // Warm up
    {
        let start = Instant::now();
        while Instant::now().duration_since(start).as_secs() < 3 {
            engine.prove(&pk, generate_prover_inputs(engine.log_blowup(), vi.clone()));
        }
    }

    init_tracing();

    let start = Instant::now();
    let prover_inputs = generate_prover_inputs(engine.log_blowup(), vi);
    let proof = engine.prove(&pk, prover_inputs);
    let proving_time = start.elapsed();
    let proving_time_components = proving_time_components(proving_time);

    let start = Instant::now();
    engine.verify(&vk, verifier_inputs, &proof).unwrap();
    let verifying_time = start.elapsed();

    let throughput = (f64::from(1 << log_signatures) / proving_time.as_secs_f64()).floor();
    let proving_time = human_time(proving_time.as_nanos());
    let proof_size = human_size(bincode::serialize(&proof).unwrap().len());
    let verifying_time = human_time(verifying_time.as_nanos());

    println!("proving time: {proving_time}");
    if let Some(proving_time_components) = proving_time_components {
        println!("{proving_time_components}");
    }
    println!("throughput: {throughput} sig/s");
    println!("proof size: {proof_size}");
    println!("verifying time: {verifying_time}");
}

mod util {
    use core::{
        fmt::{Debug, Write},
        iter::Sum,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use itertools::{chain, izip};
    use tracing_forest::{
        ForestLayer, PrettyPrinter, Processor,
        tree::{Span, Tree},
        util::LevelFilter,
    };
    use tracing_subscriber::{EnvFilter, Registry, prelude::*};

    pub fn init_tracing() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::WARN.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::from(ProvingTimeComponents))
            .init();
    }

    pub fn human_time(time: impl TryInto<u64, Error: Debug>) -> String {
        let time = time.try_into().unwrap();
        if time < 1_000 {
            format!("{time} ns")
        } else if time < 1_000_000 {
            format!("{:.2} µs", time as f64 / 1_000.0)
        } else if time < 1_000_000_000 {
            format!("{:.2} ms", time as f64 / 1_000_000.0)
        } else {
            format!("{:.2} s", time as f64 / 1_000_000_000.0)
        }
    }

    pub fn human_size(size: usize) -> String {
        if size < 1 << 10 {
            format!("{size} B")
        } else if size < 1 << 20 {
            format!("{:.2} kB", size as f64 / 2f64.powi(10))
        } else {
            format!("{:.2} MB", size as f64 / 2f64.powi(20))
        }
    }

    pub struct ProvingTimeComponents;

    impl Processor for ProvingTimeComponents {
        fn process(&self, tree: Tree) -> tracing_forest::processor::Result {
            match &tree {
                Tree::Event(_) => {}
                Tree::Span(span) => Self::process_span(span),
            }
            PrettyPrinter::new().process(tree)
        }
    }

    static PROVING_TIME_COMPONENTS: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];

    impl ProvingTimeComponents {
        fn process_span(span: &Span) {
            let idx = match span.name() {
                "generate hash-sig aggregation traces" => Some(0),
                "commit to main data" => Some(1),
                "compute log up traces" => Some(2),
                "commit to log up data" => Some(3),
                "compute quotient polynomials" => Some(4),
                "commit to quotient poly chunks" => Some(5),
                "open" => Some(6),
                _ => None,
            };
            if let Some(idx) = idx {
                PROVING_TIME_COMPONENTS[idx].store(
                    u64::try_from(span.total_duration().as_nanos()).unwrap(),
                    Ordering::Relaxed,
                );
            }
            span.nodes().iter().for_each(|tree| match tree {
                Tree::Event(_) => {}
                Tree::Span(span) => Self::process_span(span),
            });
        }
    }

    pub fn proving_time_components(proving_time: Duration) -> Option<String> {
        let names = [
            "trace_gen main",
            "commit main",
            "trace_gen log_up",
            "commit log_up",
            "trace_gen quotient",
            "commit quotient",
            "open",
            "rest",
        ];
        let components = PROVING_TIME_COMPONENTS
            .each_ref()
            .map(|v| v.load(Ordering::Relaxed));
        if components.iter().all(|v| *v == 0) {
            return None;
        }

        let proving_time = u64::try_from(proving_time.as_nanos()).unwrap();
        let rest = proving_time - u64::sum(components.iter());

        let ratio = |time| 100.0 * time as f64 / proving_time as f64;
        izip!(names, chain![components, [rest]])
            .enumerate()
            .fold(String::new(), |mut s, (idx, (name, time))| {
                s.extend((idx > 0).then_some('\n'));
                let ratio = ratio(time);
                let time = human_time(time);
                let indent = String::from_iter([
                    if idx == 7 { "└" } else { "├" },
                    "─".repeat(19 - name.len()).as_str(),
                ]);
                write!(&mut s, "  {indent} {name} [ {time:>9} | {ratio:>5.2}% ]").unwrap();
                s
            })
            .into()
    }
}
