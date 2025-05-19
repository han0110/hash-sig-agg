use core::str::FromStr;

pub mod multilinear;
pub mod univariate;

#[derive(Clone, Copy, Debug)]
pub enum SecurityAssumption {
    JohnsonBound,
    CapacityBound,
}

impl FromStr for SecurityAssumption {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "johnson-bound" => Self::JohnsonBound,
            "capacity-bound" => Self::CapacityBound,
            _ => unreachable!(),
        })
    }
}
