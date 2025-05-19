use clap::{
    Parser,
    builder::{PossibleValuesParser, RangedU64ValueParser},
};
use core::fmt::Debug;
use hash_sig_agg_circuit_openvm::{
    poseidon2::{
        F,
        chip::{generate_prover_inputs, verifier_inputs},
    },
    util::engine::{
        multilinear::{MultilinearEngineConfig, MultilnearEngine, keccak::MultilinearConfigKeccak},
        univariate::{
            UnivariateEngine, UnivariateEngineConfig, keccak::UnivariateConfigKeccak,
            poseidon2::UnivariateConfigPoseidon2,
        },
    },
};
use hash_sig_testdata::mock_vi;
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::TwoAdicField;
use p3_ml_pcs::MlPcs;
use std::{process, time::Instant};
use util::{init_tracing, print_summary};

#[cfg_attr(not(target_env = "msvc"), global_allocator)]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone, Debug, clap::Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, short = 'i', default_value_t = String::from("univariate"), value_parser = PossibleValuesParser::new(["univariate", "multilinear"]))]
    piop: String,
    #[arg(long, short = 'm', default_value_t = String::from("poseidon2"), value_parser = PossibleValuesParser::new(["keccak", "poseidon2"]))]
    pcs_merkle_hash: String,
    #[arg(long, short = 'r', default_value_t = 1, value_parser = RangedU64ValueParser::<usize>::new().range(1..F::TWO_ADICITY as _))]
    log_blowup: usize,
    /// Logarithmic amount of signatures to aggregate.
    /// Requires 'log-blowup + log-signatures <= 17' when 'piop = univariate'.
    /// Requires 'log-blowup + log-signatures <= 7' when 'piop = multilinear'.
    #[arg(long, short = 'l', verbatim_doc_comment)]
    log_signatures: Option<usize>,
    #[arg(long, short = 'p', default_value_t = 0)]
    pow_bits: usize,
    #[arg(long, short = 's', default_value_t = String::from("provable"), value_parser = PossibleValuesParser::new(["provable", "conjecture"]))]
    soundness_type: String,
}

fn main() {
    let Args {
        piop,
        pcs_merkle_hash,
        log_blowup,
        log_signatures,
        pow_bits,
        soundness_type,
    }: Args = Parser::parse();

    let log_signatures = match (piop.as_str(), log_signatures) {
        ("univariate", Some(log_signatures)) if log_blowup + log_signatures > 17 => {
            eprintln!(
                "error: insufficient two-adicity, requires 'log_blowup + log_signatures <= 17' but got {}",
                log_blowup + log_signatures
            );
            process::exit(2)
        }
        ("multilinear", Some(log_signatures)) if log_blowup + log_signatures > 7 => {
            eprintln!(
                "error: insufficient two-adicity, requires 'log_blowup + log_signatures <= 7' but got {}",
                log_blowup + log_signatures
            );
            process::exit(2)
        }
        ("univariate", log_signatures) => log_signatures.unwrap_or(13),
        ("multilinear", log_signatures) => log_signatures.unwrap_or(6),
        _ => unreachable!(),
    };
    let soundness_type = soundness_type.parse().unwrap();

    match piop.as_str() {
        "univariate" => {
            let log_final_poly_len = log_signatures.saturating_sub(1).min(3);
            match pcs_merkle_hash.as_str() {
                "keccak" => {
                    let engine = UnivariateEngine::<UnivariateConfigKeccak>::new(
                        log_blowup,
                        log_final_poly_len,
                        pow_bits,
                        soundness_type,
                    );
                    run_univariate(&engine, log_signatures);
                }
                "poseidon2" => {
                    let engine = UnivariateEngine::<UnivariateConfigPoseidon2>::new(
                        log_blowup,
                        log_final_poly_len,
                        pow_bits,
                        soundness_type,
                    );
                    run_univariate(&engine, log_signatures);
                }
                _ => unreachable!(),
            }
        }
        "multilinear" => match pcs_merkle_hash.as_str() {
            "keccak" => {
                let engine = MultilnearEngine::<MultilinearConfigKeccak>::new(
                    log_blowup,
                    pow_bits,
                    soundness_type,
                );
                run_multilinear(&engine, log_signatures);
            }
            "poseidon2" => unimplemented!(),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

fn run_univariate<C: UnivariateEngineConfig>(engine: &UnivariateEngine<C>, log_signatures: usize)
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

    let tracing_processor = init_tracing();

    let start = Instant::now();
    let prover_inputs = generate_prover_inputs(engine.log_blowup(), vi);
    let proof = engine.prove(&pk, prover_inputs);
    let proving_time = start.elapsed();
    let proving_time_components = tracing_processor.format_by_components(
        proving_time,
        &[
            ("generate hash-sig aggregation traces", "trace_gen main"),
            ("commit to main data", "commit main"),
            ("compute log up traces", "trace_gen log_up"),
            ("commit to log up data", "commit log_up"),
            ("compute quotient polynomials", "trace_gen quotient"),
            ("commit to quotient poly chunks", "commit quotient"),
            ("open", "open"),
        ],
    );

    let start = Instant::now();
    engine.verify(&vk, verifier_inputs, &proof).unwrap();
    let verifying_time = start.elapsed();

    print_summary(
        log_signatures,
        proving_time,
        &proof,
        verifying_time,
        proving_time_components,
    );
}

fn run_multilinear<C: MultilinearEngineConfig>(engine: &MultilnearEngine<C>, log_signatures: usize)
where
    C::Pcs: MlPcs<C::Challenge, C::Challenger, Val = F>,
{
    let vi = mock_vi(1 << log_signatures);
    let verifier_inputs = verifier_inputs(vi.epoch, vi.msg);
    let (vk, pk) = engine.keygen(&verifier_inputs);

    // Warm up
    {
        let start = Instant::now();
        while Instant::now().duration_since(start).as_secs() < 3 {
            engine.prove(&pk, generate_prover_inputs(0, vi.clone()));
        }
    }

    let tracing_processor = init_tracing();

    let start = Instant::now();
    let prover_inputs = generate_prover_inputs(0, vi);
    let proof = engine.prove(&pk, prover_inputs);
    let proving_time = start.elapsed();
    let proving_time_components = tracing_processor.format_by_components(
        proving_time,
        &[
            ("generate hash-sig aggregation traces", "trace_gen main"),
            ("commit to main data", "commit main"),
            ("pack traces", "pack traces"),
            ("prove_fractional_sum", "prove fractional sum"),
            ("prove_air", "prove air"),
            ("open", "open"),
        ],
    );

    let start = Instant::now();
    engine.verify(&vk, verifier_inputs, &proof).unwrap();
    let verifying_time = start.elapsed();

    print_summary(
        log_signatures,
        proving_time,
        &proof,
        verifying_time,
        proving_time_components,
    );
}

mod util {
    use core::{
        fmt::{Debug, Write},
        iter::Sum,
        time::Duration,
    };
    use itertools::{Itertools, chain, izip};
    use serde::Serialize;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use tracing_forest::{
        ForestLayer, PrettyPrinter, Processor,
        tree::{Span, Tree},
        util::LevelFilter,
    };
    use tracing_subscriber::{EnvFilter, Registry, prelude::*};

    pub fn init_tracing() -> Arc<ProvingTimeComponents> {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::WARN.into())
            .from_env_lossy();

        let processor = Arc::new(ProvingTimeComponents::default());

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::from(Arc::clone(&processor)))
            .init();

        processor
    }

    #[derive(Default)]
    pub struct ProvingTimeComponents(Mutex<BTreeMap<String, u64>>);

    impl Processor for ProvingTimeComponents {
        fn process(&self, tree: Tree) -> tracing_forest::processor::Result {
            match &tree {
                Tree::Event(_) => {}
                Tree::Span(span) => self.process_span(span),
            }
            PrettyPrinter::new().process(tree)
        }
    }

    impl ProvingTimeComponents {
        fn process_span(&self, span: &Span) {
            self.0
                .lock()
                .unwrap()
                .entry(span.name().to_string())
                .or_insert_with(|| u64::try_from(span.total_duration().as_nanos()).unwrap());
            span.nodes().iter().for_each(|tree| match tree {
                Tree::Event(_) => {}
                Tree::Span(span) => self.process_span(span),
            });
        }

        pub fn format_by_components(
            &self,
            total: Duration,
            components: &[(&str, &str)],
        ) -> Option<String> {
            let names = components.iter().map(|(_, name)| *name).collect_vec();
            let max_name_len = names.iter().map(|name| name.len()).max().unwrap();
            let durations = components
                .iter()
                .map(|(key, _)| {
                    self.0
                        .lock()
                        .unwrap()
                        .get(*key)
                        .copied()
                        .unwrap_or_default()
                })
                .collect_vec();
            if durations.iter().all(|v| *v == 0) {
                return None;
            }

            let total = u64::try_from(total.as_nanos()).unwrap();
            let rest = total - u64::sum(durations.iter());

            let ratio = |time| 100.0 * time as f64 / total as f64;
            izip!(chain![&names, &["rest"]], chain![durations, [rest]])
                .enumerate()
                .fold(String::new(), |mut s, (idx, (name, time))| {
                    s.extend((idx > 0).then_some('\n'));
                    let ratio = ratio(time);
                    let time = human_time(time);
                    let indent = String::from_iter([
                        if idx == names.len() { "└" } else { "├" },
                        "─".repeat(max_name_len - name.len() + 1).as_str(),
                    ]);
                    write!(&mut s, "  {indent} {name} [ {time:>9} | {ratio:>5.2}% ]").unwrap();
                    s
                })
                .into()
        }
    }

    pub fn print_summary(
        log_signatures: usize,
        proving_time: Duration,
        proof: &impl Serialize,
        verifying_time: Duration,
        proving_time_components: Option<String>,
    ) {
        let throughput = (f64::from(1 << log_signatures) / proving_time.as_secs_f64()).floor();
        let proving_time = human_time(proving_time.as_nanos());
        let proof_size = human_size(bincode::serialize(proof).unwrap().len());
        let verifying_time = human_time(verifying_time.as_nanos());

        println!("proving time: {proving_time}");
        if let Some(proving_time_components) = proving_time_components {
            println!("{proving_time_components}");
        }
        println!("throughput: {throughput} sig/s");
        println!("proof size: {proof_size}");
        println!("verifying time: {verifying_time}");
    }

    fn human_time(time: impl TryInto<u64, Error: Debug>) -> String {
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

    fn human_size(size: usize) -> String {
        if size < 1 << 10 {
            format!("{size} B")
        } else if size < 1 << 20 {
            format!("{:.2} kB", size as f64 / 2f64.powi(10))
        } else {
            format!("{:.2} MB", size as f64 / 2f64.powi(20))
        }
    }
}
