#![allow(clippy::type_repetition_in_bounds, clippy::multiple_bound_locations)]

use crate::util::engine::SoundnessType;
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
        soundness_type: SoundnessType,
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
        soundness_type: SoundnessType,
    ) -> Self {
        Self {
            config: C::new(
                log_blowup,
                log_final_poly_len,
                proof_of_work_bits,
                soundness_type,
            ),
            log_blowup,
        }
    }

    pub fn fastest() -> Self {
        Self::new(1, 0, 0, SoundnessType::Provable)
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

    pub fn prove<
        #[cfg(feature = "check-constraints")] A: for<'a> Air<p3_uni_stark_ext::DebugConstraintBuilder<'a, Val<C>>>,
        #[cfg(not(feature = "check-constraints"))] A,
    >(
        &self,
        pk: &ProvingKey,
        inputs: Vec<ProverInput<Val<C>, A>>,
    ) -> Proof<C>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<ProverConstraintFolder<'a, C>>
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
        A: Air<SymbolicAirBuilder<Val<C>>> + for<'a> Air<VerifierConstraintFolder<'a, C>>,
    {
        verify(self.config(), vk, inputs, proof)
    }

    #[cfg(test)]
    pub fn test<
        #[cfg(feature = "check-constraints")] A: for<'a> Air<p3_uni_stark_ext::DebugConstraintBuilder<'a, Val<C>>>,
        #[cfg(not(feature = "check-constraints"))] A,
    >(
        &self,
        prover_inputs: Vec<ProverInput<Val<C>, A>>,
    ) where
        A: Clone
            + BaseAirWithPublicValues<Val<C>>
            + Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<ProverConstraintFolder<'a, C>>
            + for<'a> Air<ProverInteractionFolder<'a, Val<C>, C::Challenge>>
            + for<'a> Air<VerifierConstraintFolder<'a, C>>,
    {
        let verifier_inputs = prover_inputs
            .iter()
            .map(ProverInput::to_verifier_input)
            .collect();
        let (vk, pk) = self.keygen(&verifier_inputs);
        let proof = self.prove(&pk, prover_inputs);
        self.verify(&vk, verifier_inputs, &proof).unwrap();
    }
}
