use sp1_helper::build_program_with_args;

fn main() {
    build_program_with_args("../poseidon2-baby-bear", Default::default());
    build_program_with_args("../sha3", Default::default());
}
