use core::str::FromStr;

pub mod multilinear;
pub mod univariate;

#[derive(Clone, Copy, Debug)]
pub enum SoundnessType {
    Provable,
    Conjecture,
}

impl FromStr for SoundnessType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "provable" => Self::Provable,
            "conjecture" => Self::Conjecture,
            _ => unreachable!(),
        })
    }
}

impl SoundnessType {
    // TODO: Calculate accurate number of queries.
    pub const fn num_queries(&self, log_blowup: usize, proof_of_work_bits: usize) -> usize {
        match self {
            Self::Provable => usize::div_ceil(2 * (128 - proof_of_work_bits), log_blowup),
            Self::Conjecture => usize::div_ceil(128 - proof_of_work_bits, log_blowup),
        }
    }
}
