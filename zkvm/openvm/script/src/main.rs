use clap::Parser;
use hash_sig_testdata::mock_vi;
use hash_sig_verifier::instantiation::{
    poseidon2::{self, baby_bear_horizon::BabyBearHorizon, Poseidon2TargetSum},
    sha3::{self, Keccak256, Sha3TargetSum},
};
use openvm_build::{build_guest_package, get_package, guest_methods, GuestOptions};
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::{
    config::FriParameters, openvm_stark_backend::p3_field::PrimeField32, p3_baby_bear::BabyBear,
};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE, FromElf};
use std::{fs, path::PathBuf, sync::Arc};

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
    Keccak256,
    Poseidon2BabyBear,
}

impl Instantiation {
    fn dir(&self) -> &str {
        match self {
            Self::Keccak256 => "keccak256",
            Self::Poseidon2BabyBear => "poseidon2-baby-bear",
        }
    }

    fn mock_vi(&self, size: usize) -> Vec<u8> {
        match self {
            Self::Keccak256 => {
                type I = Sha3TargetSum<Keccak256>;
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

    let (exe, config) = build_program(args.instantiation);
    let pk = {
        let app_config = AppConfig::new(FriParameters::standard_fast(), config.clone());
        Arc::new(Sdk.app_keygen(app_config).unwrap())
    };

    let stdin = StdIn::from_bytes(&args.instantiation.mock_vi(args.size));

    if args.debug {
        let output = Sdk
            .execute(exe.clone(), config.clone(), stdin.clone())
            .unwrap();
        println!("{:?}", output);
        output
            .iter()
            .flat_map(|byte| (0..8).map(|i| byte.as_canonical_u32() >> i & 1 == 1))
            .take(args.size)
            .for_each(|is_valid| assert!(is_valid));
    }

    let committed_exe = Sdk.commit_app_exe(pk.app_fri_params(), exe).unwrap();
    let proof = Sdk
        .generate_app_proof(pk.clone(), committed_exe, stdin)
        .unwrap();
    Sdk.verify_app_proof(&pk.get_app_vk(), &proof).unwrap();
}

fn build_program(instantiation: Instantiation) -> (VmExe<BabyBear>, SdkVmConfig) {
    let elf = {
        let workspace_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
        let target_dir =
            PathBuf::from_iter([workspace_dir, "target", "openvm", instantiation.dir()]);
        let pkg = get_package(PathBuf::from_iter([workspace_dir, instantiation.dir()]));
        let guest_opts = GuestOptions::default()
            .with_target_dir(&target_dir)
            .with_profile("release".to_string());
        build_guest_package(&pkg, &guest_opts, None, &None).unwrap();
        let elf_path = guest_methods(&pkg, &target_dir, &guest_opts.features, &guest_opts.profile)
            .pop()
            .unwrap();
        let data = fs::read(elf_path).unwrap();
        Elf::decode(&data, MEM_SIZE as u32).unwrap()
    };
    let config = match instantiation {
        Instantiation::Keccak256 => SdkVmConfig::builder()
            .system(Default::default())
            .rv32i(Default::default())
            .rv32m(Default::default())
            .io(Default::default())
            .keccak(Default::default())
            .build(),
        Instantiation::Poseidon2BabyBear => SdkVmConfig::builder()
            .system(Default::default())
            .rv32i(Default::default())
            .rv32m(Default::default())
            .io(Default::default())
            .build(),
    };
    (VmExe::from_elf(elf, config.transpiler()).unwrap(), config)
}
