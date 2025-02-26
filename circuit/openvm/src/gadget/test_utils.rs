use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use p3_matrix::dense::RowMajorMatrix;

pub struct MockAirBuilder {
    constraints: Vec<BabyBear>,
}

impl MockAirBuilder {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
        }
    }

    pub fn constraints(&self) -> &[BabyBear] {
        &self.constraints
    }
}

impl AirBuilder for MockAirBuilder {
    type Expr = BabyBear;
    type Var = BabyBear;
    type M = RowMajorMatrix<BabyBear>;
    type F = BabyBear;

    fn main(&self) -> Self::M {
        unreachable!()
    }

    fn is_first_row(&self) -> Self::Expr {
        unreachable!()
    }

    fn is_last_row(&self) -> Self::Expr {
        unreachable!()
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        unreachable!()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x = x.into();
        if x == BabyBear::ZERO {
            self.constraints.push(x);
        } else {
            panic!("Assertion failed: x should be zero, but got {x:?}");
        }
    }
}
