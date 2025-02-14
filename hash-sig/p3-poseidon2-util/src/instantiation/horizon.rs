use core::{
    iter::zip,
    marker::PhantomData,
    ops::{AddAssign, Mul},
};
use p3_field::FieldAlgebra;
use p3_poseidon2::{
    add_rc_and_sbox_generic, external_initial_permute_state, external_terminal_permute_state,
    mds_light_permutation, ExternalLayer, ExternalLayerConstants, ExternalLayerConstructor,
    GenericPoseidon2LinearLayers, HLMDSMat4, InternalLayer, InternalLayerConstructor,
};

pub mod baby_bear;
pub mod koala_bear;

pub trait MatDiagMinusOne<const WIDTH: usize>: Sized {
    const MAT_DIAG_M_1: [Self; WIDTH];
}

#[derive(Clone, Debug)]
pub struct Poseidon2ExternalLayerHorizon<F, const WIDTH: usize, const SBOX_DEGREE: u64>(
    Vec<[F; WIDTH]>,
    Vec<[F; WIDTH]>,
);

impl<F: Copy, FA: FieldAlgebra<F = F>, const WIDTH: usize, const SBOX_DEGREE: u64>
    ExternalLayerConstructor<FA, WIDTH> for Poseidon2ExternalLayerHorizon<F, WIDTH, SBOX_DEGREE>
{
    fn new_from_constants(external_constants: ExternalLayerConstants<FA::F, WIDTH>) -> Self {
        let initial = external_constants.get_initial_constants().clone();
        let terminal = external_constants.get_terminal_constants().clone();
        Self(initial, terminal)
    }
}

impl<F: Sync + Copy, FA: FieldAlgebra<F = F>, const WIDTH: usize, const SBOX_DEGREE: u64>
    ExternalLayer<FA, WIDTH, SBOX_DEGREE> for Poseidon2ExternalLayerHorizon<F, WIDTH, SBOX_DEGREE>
{
    fn permute_state_initial(&self, state: &mut [FA; WIDTH]) {
        external_initial_permute_state(
            state,
            &self.0,
            add_rc_and_sbox_generic::<_, SBOX_DEGREE>,
            &HLMDSMat4,
        );
    }

    fn permute_state_terminal(&self, state: &mut [FA; WIDTH]) {
        external_terminal_permute_state(
            state,
            &self.1,
            add_rc_and_sbox_generic::<_, SBOX_DEGREE>,
            &HLMDSMat4,
        );
    }
}

#[derive(Clone, Debug)]
pub struct Poseidon2InternalLayerHorizon<F, const WIDTH: usize, const SBOX_DEGREE: u64>(Vec<F>);

impl<F, FA: FieldAlgebra<F = F>, const WIDTH: usize, const SBOX_DEGREE: u64>
    InternalLayerConstructor<FA> for Poseidon2InternalLayerHorizon<F, WIDTH, SBOX_DEGREE>
{
    fn new_from_constants(internal_constants: Vec<FA::F>) -> Self {
        Self(internal_constants)
    }
}

impl<F: Sync + Copy, FA, const WIDTH: usize, const SBOX_DEGREE: u64>
    InternalLayer<FA, WIDTH, SBOX_DEGREE> for Poseidon2InternalLayerHorizon<F, WIDTH, SBOX_DEGREE>
where
    F: MatDiagMinusOne<WIDTH>,
    FA: FieldAlgebra<F = F> + AddAssign<F> + Mul<F, Output = FA>,
{
    fn permute_state(&self, state: &mut [FA; WIDTH]) {
        self.0.iter().for_each(|rc| {
            state[0] += *rc;
            state[0] = state[0].exp_const_u64::<SBOX_DEGREE>();
            let sum = state.iter().cloned().sum::<FA>();
            zip(&mut *state, F::MAT_DIAG_M_1).for_each(|(state, mat_diag_m_1)| {
                *state = state.clone() * mat_diag_m_1 + sum.clone()
            });
        })
    }
}

#[derive(Clone, Debug)]
pub struct Poseidon2LinearLayersHorizon<F, const WIDTH: usize>(PhantomData<F>);

impl<F: Sync + Copy + MatDiagMinusOne<WIDTH>, FA, const WIDTH: usize>
    GenericPoseidon2LinearLayers<FA, WIDTH> for Poseidon2LinearLayersHorizon<F, WIDTH>
where
    FA: FieldAlgebra<F = F> + Mul<F, Output = FA>,
{
    fn internal_linear_layer(state: &mut [FA; WIDTH]) {
        let sum = state.iter().cloned().sum::<FA>();
        zip(&mut *state, F::MAT_DIAG_M_1)
            .for_each(|(state, mat_diag_m_1)| *state = state.clone() * mat_diag_m_1 + sum.clone());
    }

    fn external_linear_layer(state: &mut [FA; WIDTH]) {
        mds_light_permutation(state, &HLMDSMat4)
    }
}
