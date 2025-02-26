use p3_air::Air;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark_ext::{ProverInput, SymbolicAirBuilder, VerifierInput};

pub trait Chip<Val> {
    type Air;
    type Interaction: Default + Send + Sync;

    fn air(&self) -> Self::Air;

    fn public_values(&self) -> Vec<Val> {
        Vec::new()
    }

    fn verifier_input(&self) -> VerifierInput<Val, Self::Air>
    where
        Val: Field,
        Self::Air: Air<SymbolicAirBuilder<Val>>,
    {
        VerifierInput::new(self.air(), self.public_values())
    }

    fn trace_height(&self) -> usize;

    fn generate_trace(&self, interaction: &Self::Interaction) -> RowMajorMatrix<Val>;

    fn generate_prover_input(&self, interaction: &Self::Interaction) -> ProverInput<Val, Self::Air>
    where
        Val: Field,
        Self::Air: Air<SymbolicAirBuilder<Val>>,
    {
        ProverInput::new(
            self.air(),
            self.public_values(),
            self.generate_trace(interaction),
        )
    }
}
