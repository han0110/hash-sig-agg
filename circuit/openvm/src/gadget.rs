use openvm_stark_backend::p3_field::FieldAlgebra;

pub mod cycle_bits;
pub mod is_equal;
pub mod is_zero;
pub mod lower_rows_filter;

pub fn not<F: FieldAlgebra>(value: F) -> F {
    F::ONE - value
}

pub fn select<F: FieldAlgebra>(cond: F, when_false: F, when_true: F) -> F {
    not(cond.clone()) * when_false + cond * when_true
}
