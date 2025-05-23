use p3_air::{Air, BaseAirWithPublicValues};
use p3_air_ext::{ProverInput, SymbolicAirBuilder, VerifierInput};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

pub trait AirInstance<Val> {
    type Air;
    type Interaction: Default + Send + Sync;

    fn air(&self) -> Self::Air;

    fn public_values(&self) -> Vec<Val> {
        Vec::new()
    }

    fn generate_trace(
        &self,
        extra_capacity_bits: usize,
        interaction: &Self::Interaction,
    ) -> RowMajorMatrix<Val>;

    fn prover_input(
        &self,
        extra_capacity_bits: usize,
        interaction: &Self::Interaction,
    ) -> ProverInput<Val, Self::Air>
    where
        Self: Sized,
        Val: Field,
        Self::Air: BaseAirWithPublicValues<Val> + Air<SymbolicAirBuilder<Val>>,
    {
        ProverInput::new(
            self.air(),
            self.public_values(),
            self.generate_trace(extra_capacity_bits, interaction),
        )
    }

    fn verifier_input(&self) -> VerifierInput<Val, Self::Air>
    where
        Self: Sized,
        Val: Field,
        Self::Air: BaseAirWithPublicValues<Val> + Air<SymbolicAirBuilder<Val>>,
    {
        VerifierInput::new(self.air(), self.public_values())
    }
}
