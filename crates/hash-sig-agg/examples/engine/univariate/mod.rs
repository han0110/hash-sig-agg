use crate::engine::SecurityAssumption;
use p3_air::{Air, BaseAirWithPublicValues};
use p3_uni_stark_ext::{
    PcsError, Proof, ProverConstraintFolder, ProverInput, ProverInteractionFolder, ProvingKey,
    StarkGenericConfig, SymbolicAirBuilder, Val, VerificationError, VerifierConstraintFolder,
    VerifierInput, VerifyingKey, keygen, prove, verify,
};

pub mod keccak;
pub mod poseidon2;

pub trait UnivariateEngineConfig: StarkGenericConfig {
    fn new(
        log_blowup: usize,
        log_final_poly_len: usize,
        proof_of_work_bits: usize,
        security_assumption: SecurityAssumption,
    ) -> Self;
}

pub struct UnivariateEngine<C: UnivariateEngineConfig> {
    config: C,
    log_blowup: usize,
}

impl<C: UnivariateEngineConfig> UnivariateEngine<C> {
    pub fn new(
        log_blowup: usize,
        log_final_poly_len: usize,
        proof_of_work_bits: usize,
        security_assumption: SecurityAssumption,
    ) -> Self {
        Self {
            config: C::new(
                log_blowup,
                log_final_poly_len,
                proof_of_work_bits,
                security_assumption,
            ),
            log_blowup,
        }
    }

    pub const fn log_blowup(&self) -> usize {
        self.log_blowup
    }

    pub const fn config(&self) -> &C {
        &self.config
    }

    pub fn keygen<'a, A>(
        &self,
        inputs: impl IntoIterator<Item = &'a VerifierInput<Val<C>, A>>,
    ) -> (VerifyingKey, ProvingKey)
    where
        A: 'a + BaseAirWithPublicValues<Val<C>> + Air<SymbolicAirBuilder<Val<C>>>,
    {
        keygen(
            (1 << self.log_blowup) + 1,
            inputs.into_iter().map(VerifierInput::air),
        )
    }

    pub fn prove<A>(&self, pk: &ProvingKey, inputs: Vec<ProverInput<Val<C>, A>>) -> Proof<C>
    where
        A: for<'a> Air<ProverConstraintFolder<'a, C>>
            + for<'a> Air<ProverInteractionFolder<'a, Val<C>, C::Challenge>>,
    {
        prove(self.config(), pk, inputs)
    }

    pub fn verify<A>(
        &self,
        vk: &VerifyingKey,
        inputs: Vec<VerifierInput<Val<C>, A>>,
        proof: &Proof<C>,
    ) -> Result<(), VerificationError<PcsError<C>>>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, C>>,
    {
        verify(self.config(), vk, inputs, proof)
    }
}

pub const fn num_fri_queries(
    log_blowup: usize,
    proof_of_work_bits: usize,
    security_assumption: SecurityAssumption,
) -> usize {
    match security_assumption {
        SecurityAssumption::JohnsonBound => {
            usize::div_ceil(2 * (128 - proof_of_work_bits), log_blowup)
        }
        SecurityAssumption::CapacityBound => usize::div_ceil(128 - proof_of_work_bits, log_blowup),
    }
}
