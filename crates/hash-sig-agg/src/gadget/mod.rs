use p3_field::PrimeCharacteristicRing;

pub mod cycle_bits;
pub mod cycle_int;
pub mod is_equal;
pub mod is_zero;
pub mod lower_rows_filter;
pub mod strictly_increasing;

#[cfg(test)]
mod test_utils;

pub fn not<F: PrimeCharacteristicRing>(value: F) -> F {
    F::ONE - value
}

pub fn select<F: PrimeCharacteristicRing>(cond: F, when_false: F, when_true: F) -> F {
    not(cond.clone()) * when_false + cond * when_true
}
