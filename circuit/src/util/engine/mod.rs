#![allow(clippy::type_repetition_in_bounds, clippy::multiple_bound_locations)]

use core::str::FromStr;
use p3_air::{Air, BaseAirWithPublicValues};
use p3_uni_stark_ext::{
    PcsError, Proof, ProverConstraintFolder, ProverInput, ProverInteractionFolder, ProvingKey,
    StarkGenericConfig, SymbolicAirBuilder, Val, VerificationError, VerifierConstraintFolder,
    VerifierInput, VerifyingKey, keygen, prove, verify,
};

pub mod keccak;
pub mod poseidon2;

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

pub trait EngineConfig: StarkGenericConfig {
    fn new(
        log_blowup: usize,
        log_final_poly_len: usize,
        proof_of_work_bits: usize,
        soundness_type: SoundnessType,
    ) -> Self;

    fn new_challenger() -> Self::Challenger;
}

pub struct Engine<C: EngineConfig> {
    config: C,
    log_blowup: usize,
}

impl<C: EngineConfig> Engine<C> {
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
            + for<'a> Air<ProverInteractionFolder<'a, C>>,
    {
        let mut challenger = C::new_challenger();
        prove(self.config(), pk, inputs, &mut challenger)
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
        let mut challenger = C::new_challenger();
        verify(self.config(), vk, inputs, &mut challenger, proof)
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
            + for<'a> Air<ProverInteractionFolder<'a, C>>
            + for<'a> Air<VerifierConstraintFolder<'a, C>>,
    {
        let verifier_inputs = prover_inputs.iter().map(|v| (**v).clone()).collect();
        let (vk, pk) = self.keygen(&verifier_inputs);
        let proof = self.prove(&pk, prover_inputs);
        self.verify(&vk, verifier_inputs, &proof).unwrap();
    }
}
