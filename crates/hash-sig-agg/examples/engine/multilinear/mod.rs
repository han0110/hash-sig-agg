use crate::engine::SecurityAssumption;
use p3_air::{Air, BaseAirWithPublicValues};
use p3_field::{PrimeField32, TwoAdicField};
use p3_hyperplonk::{
    HyperPlonkGenericConfig, PcsError, Proof, ProverConstraintFolderOnExtension,
    ProverConstraintFolderOnExtensionPacking, ProverConstraintFolderOnPacking, ProverInput,
    ProverInteractionFolderOnExtension, ProverInteractionFolderOnPacking, ProvingKey,
    SymbolicAirBuilder, Val, VerificationError, VerifierConstraintFolder, VerifierInput,
    VerifyingKey, keygen, prove, verify,
};

pub mod keccak;

pub trait MultilinearEngineConfig: HyperPlonkGenericConfig {
    fn new(
        log_blowup: usize,
        proof_of_work_bits: usize,
        security_assumption: SecurityAssumption,
    ) -> Self;
}

pub struct MultilnearEngine<C> {
    config: C,
}

impl<C> MultilnearEngine<C>
where
    C: MultilinearEngineConfig,
    Val<C>: TwoAdicField + PrimeField32,
{
    pub fn new(
        log_blowup: usize,
        proof_of_work_bits: usize,
        security_assumption: SecurityAssumption,
    ) -> Self {
        Self {
            config: C::new(log_blowup, proof_of_work_bits, security_assumption),
        }
    }

    #[allow(clippy::unused_self)]
    pub fn keygen<'a, A>(
        &self,
        inputs: impl IntoIterator<Item = &'a VerifierInput<Val<C>, A>>,
    ) -> (VerifyingKey, ProvingKey)
    where
        A: 'a + BaseAirWithPublicValues<Val<C>> + Air<SymbolicAirBuilder<Val<C>>>,
    {
        keygen(inputs.into_iter().map(VerifierInput::air))
    }

    pub fn prove<A>(&self, pk: &ProvingKey, inputs: Vec<ProverInput<Val<C>, A>>) -> Proof<C>
    where
        A: for<'t> Air<ProverInteractionFolderOnPacking<'t, Val<C>, C::Challenge>>
            + for<'t> Air<ProverInteractionFolderOnExtension<'t, Val<C>, C::Challenge>>
            + for<'t> Air<ProverConstraintFolderOnPacking<'t, Val<C>, C::Challenge>>
            + for<'t> Air<ProverConstraintFolderOnExtension<'t, Val<C>, C::Challenge>>
            + for<'t> Air<ProverConstraintFolderOnExtensionPacking<'t, Val<C>, C::Challenge>>,
    {
        prove(&self.config, pk, inputs)
    }

    pub fn verify<A>(
        &self,
        vk: &VerifyingKey,
        inputs: Vec<VerifierInput<Val<C>, A>>,
        proof: &Proof<C>,
    ) -> Result<(), VerificationError<PcsError<C>>>
    where
        A: for<'t> Air<VerifierConstraintFolder<'t, Val<C>, C::Challenge>>,
    {
        verify(&self.config, vk, inputs, proof)
    }
}
