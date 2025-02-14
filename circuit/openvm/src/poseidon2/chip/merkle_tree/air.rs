use crate::{
    gadget::not,
    poseidon2::{
        chip::{
            merkle_tree::{
                column::{MerkleTreeCols, NUM_MERKLE_TREE_COLS},
                poseidon2::{PARTIAL_ROUNDS, WIDTH},
            },
            Bus,
        },
        hash_sig::{HASH_FE_LEN, MSG_FE_LEN, SPONGE_CAPACITY_VALUES, SPONGE_RATE, TWEAK_FE_LEN},
        Poseidon2LinearLayers, F, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE, SBOX_REGISTERS,
    },
};
use core::{
    array::from_fn,
    borrow::Borrow,
    iter::{self, zip},
};
use openvm_stark_backend::{
    air_builders::sub::SubAirBuilder,
    interaction::InteractionBuilder,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use p3_poseidon2_air::{num_cols, Poseidon2Air};

#[derive(Debug)]
pub struct MerkleTreeAir(
    Poseidon2Air<
        F,
        Poseidon2LinearLayers<WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
);

impl Default for MerkleTreeAir {
    fn default() -> Self {
        Self(Poseidon2Air::new(RC24.into()))
    }
}

impl BaseAir<F> for MerkleTreeAir {
    fn width(&self) -> usize {
        NUM_MERKLE_TREE_COLS
    }
}

impl PartitionedBaseAir<F> for MerkleTreeAir {}

impl BaseAirWithPublicValues<F> for MerkleTreeAir {
    fn num_public_values(&self) -> usize {
        1 + MSG_FE_LEN + 2 * TWEAK_FE_LEN
    }
}

impl<AB> Air<AB> for MerkleTreeAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
    AB::Expr: FieldAlgebra<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        self.0.eval(&mut SubAirBuilder::<
            _,
            Poseidon2Air<
                F,
                Poseidon2LinearLayers<WIDTH>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
            _,
        >::new(
            builder,
            0..num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(),
        ));

        // TODO:
        // 1. Make sure `encoded_tweak_merkle_tree` (`perm.inputs[PARAM_FE_LEN..][..TWEAK_FE_LEN]`) of path is correct.

        let main = builder.main();

        let mut public_values = builder.public_values().iter().copied().map(Into::into);
        let epoch = public_values.next().unwrap();
        let encoded_msg: [_; MSG_FE_LEN] = from_fn(|_| public_values.next().unwrap());
        let encoded_tweak_msg: [_; TWEAK_FE_LEN] = from_fn(|_| public_values.next().unwrap());
        let encoded_tweak_merkle_leaf: [_; TWEAK_FE_LEN] =
            from_fn(|_| public_values.next().unwrap());

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &MerkleTreeCols<AB::Var> = (*local).borrow();
        let next: &MerkleTreeCols<AB::Var> = (*next).borrow();

        // When every row
        eval_every_row(builder, local);
        eval_merkle_leaf_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_zero(local.sig_idx);
            builder.assert_one(local.is_msg);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_sig_transition(&mut builder, local, next);
            eval_msg_transition(
                &mut builder,
                encoded_tweak_msg,
                encoded_msg,
                encoded_tweak_merkle_leaf,
                local,
                next,
            );
            eval_merkle_leaf_transition(&mut builder, local, next);
            eval_merkle_leaf_last_row(&mut builder, epoch, local, next);
            eval_merkle_path_transition(&mut builder, local, next);
            eval_merkle_path_last_row(&mut builder, local, next);
            eval_padding_transition(&mut builder, local, next);
        }

        // Interaction
        receive_msg_hash(builder, local);
        receive_merkle_tree(builder, local, next);
    }
}

#[inline]
fn eval_every_row<AB>(builder: &mut AB, cols: &MerkleTreeCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    builder.assert_bool(cols.is_msg);
    builder.assert_bool(cols.is_merkle_leaf);
    builder.assert_eq(
        cols.is_merkle_leaf_transition,
        cols.is_merkle_leaf * not(cols.is_last_sponge_step::<AB>()),
    );
    builder.assert_bool(cols.is_merkle_path);
    builder.assert_eq(
        cols.is_merkle_path_transition,
        cols.is_merkle_path * not(cols.is_last_level::<AB>()),
    );
    cols.is_recevie_merkle_tree.map(|v| builder.assert_bool(v));
    builder
        .assert_bool(cols.is_msg.into() + cols.is_merkle_leaf.into() + cols.is_merkle_path.into());
    cols.sponge_step.eval_every_row(builder);
    cols.level.eval_every_row(builder);
    builder.assert_bool(cols.is_right);
}

#[inline]
fn eval_sig_transition<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_sig_transition::<AB>());

    zip(local.root, next.root).for_each(|(a, b)| builder.assert_eq(a, b));
    builder.assert_eq(local.sig_idx, next.sig_idx);
}

#[inline]
fn eval_msg_transition<AB>(
    builder: &mut AB,
    encoded_tweak_msg: [AB::Expr; TWEAK_FE_LEN],
    encoded_msg: [AB::Expr; MSG_FE_LEN],
    encoded_tweak_merkle_leaf: [AB::Expr; TWEAK_FE_LEN],
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_msg);

    builder.assert_one(next.is_merkle_leaf);
    zip(local.encoded_tweak_msg(), encoded_tweak_msg).for_each(|(a, b)| builder.assert_eq(a, b));
    zip(local.encoded_msg(), encoded_msg).for_each(|(a, b)| builder.assert_eq(a, b));
    zip(next.merkle_leaf_parameter(), local.msg_hash_parameter())
        .for_each(|(a, b)| builder.assert_eq(a, b));
    zip(next.encoded_tweak_merkle_leaf(), encoded_tweak_merkle_leaf)
        .for_each(|(a, b)| builder.assert_eq(a, b));
    eval_merkle_leaf_first_row(&mut builder, next);
}

#[inline]
fn eval_merkle_leaf_every_row<AB>(builder: &mut AB, cols: &MerkleTreeCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(cols.is_merkle_leaf);

    builder.assert_eq(
        AB::Expr::TWO,
        cols.leaf_chunk_start_ind[1..]
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
    );
}

#[inline]
fn eval_merkle_leaf_first_row<AB>(builder: &mut AB, cols: &MerkleTreeCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    cols.sponge_step.eval_first_row(builder);
    builder.assert_zero(cols.leaf_chunk_idx);
    (0..SPONGE_RATE)
        .step_by(HASH_FE_LEN)
        .for_each(|i| builder.assert_one(cols.leaf_chunk_start_ind[i]));
    zip(&cols.perm.inputs[..SPONGE_RATE], cols.sponge_block)
        .for_each(|(a, b)| builder.assert_eq(*a, b));
    zip(&cols.perm.inputs[SPONGE_RATE..], SPONGE_CAPACITY_VALUES)
        .for_each(|(a, b)| builder.assert_eq(*a, b));
}

#[inline]
fn eval_merkle_leaf_transition<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_merkle_leaf_transition);

    builder.assert_one(next.is_merkle_leaf);
    local
        .sponge_step
        .eval_transition(&mut builder, &next.sponge_step);
    (1..=HASH_FE_LEN).for_each(|i| {
        (i - 1..HASH_FE_LEN).step_by(HASH_FE_LEN).for_each(|j| {
            builder
                .when(local.leaf_chunk_start_ind[i])
                .assert_one(next.leaf_chunk_start_ind[j]);
        });
    });
    zip(next.perm.inputs, local.sponge_output())
        .enumerate()
        .for_each(|(idx, (input, output))| {
            if let Some(block) = next.sponge_block.get(idx).copied() {
                builder.assert_eq(input, output + block.into());
            } else {
                builder.assert_eq(input, output);
            }
        });
}

#[inline]
fn eval_merkle_leaf_last_row<AB>(
    builder: &mut AB,
    epoch: AB::Expr,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder =
        builder.when(local.is_merkle_leaf.into() - local.is_merkle_leaf_transition.into());

    builder.assert_one(next.is_merkle_path);
    next.level.eval_first_row(&mut builder);
    builder.assert_eq(next.epoch_dec, epoch);
    zip(next.path_right(), local.sponge_output())
        .for_each(|(a, b)| builder.when(next.is_right).assert_eq(a, b));
    zip(next.path_left(), local.sponge_output())
        .for_each(|(a, b)| builder.when(not(next.is_right.into())).assert_eq(a, b));
}

#[inline]
fn eval_merkle_path_transition<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_merkle_path_transition);

    builder.assert_one(next.is_merkle_path);
    local.level.eval_transition(&mut builder, &next.level);
    builder.assert_eq(
        next.epoch_dec.into().double() + local.is_right.into(),
        local.epoch_dec,
    );
    zip(next.path_right(), local.compress_output::<AB>())
        .for_each(|(a, b)| builder.when(next.is_right).assert_eq(a, b));
    zip(next.path_left(), local.compress_output::<AB>())
        .for_each(|(a, b)| builder.when(not(next.is_right.into())).assert_eq(a, b));
}

#[inline]
fn eval_merkle_path_last_row<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder =
        builder.when(local.is_merkle_path.into() - local.is_merkle_path_transition.into());

    builder.assert_zero(next.is_merkle_leaf.into() + next.is_merkle_path.into());
    zip(local.root, local.compress_output::<AB>()).for_each(|(a, b)| builder.assert_eq(a, b));
    builder
        .when(next.is_msg)
        .assert_eq(next.sig_idx, local.sig_idx + F::ONE);
}

#[inline]
fn eval_padding_transition<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_padding::<AB>());

    builder.assert_zero(local.sig_idx);
    local.is_recevie_merkle_tree.map(|v| builder.assert_zero(v));
    builder.assert_one(next.is_padding::<AB>());
}

#[inline]
fn receive_msg_hash<AB>(builder: &mut AB, local: &MerkleTreeCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::MsgHash as usize,
        iter::empty()
            .chain([local.sig_idx.into()])
            .chain(local.msg_hash_parameter().map(Into::into))
            .chain(local.root.map(Into::into))
            .chain(local.msg_hash::<AB>()),
        local.is_msg,
    );
}

#[inline]
fn receive_merkle_tree<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::MerkleLeaf as usize,
        iter::empty()
            .chain([local.sig_idx.into(), local.leaf_chunk_idx.into()])
            .chain(
                local.sponge_block[..HASH_FE_LEN]
                    .iter()
                    .copied()
                    .map(Into::into),
            ),
        local.is_recevie_merkle_tree[0] * local.leaf_chunk_start_ind[0].into(),
    );
    builder.push_receive(
        Bus::MerkleLeaf as usize,
        iter::empty()
            .chain([
                local.sig_idx.into(),
                local.leaf_chunk_idx.into() + local.leaf_chunk_start_ind[0].into(),
            ])
            .chain((0..HASH_FE_LEN).map(|i| {
                (1..)
                    .take(HASH_FE_LEN)
                    .map(|j| local.leaf_chunk_start_ind[j] * local.sponge_block[j + i])
                    .sum()
            })),
        local.is_recevie_merkle_tree[1],
    );
    builder.push_receive(
        Bus::MerkleLeaf as usize,
        iter::empty()
            .chain([
                local.sig_idx.into(),
                local.leaf_chunk_idx.into() + local.leaf_chunk_start_ind[0].into() + AB::Expr::ONE,
            ])
            .chain((0..HASH_FE_LEN).map(|i| {
                (1 + HASH_FE_LEN..)
                    .take(HASH_FE_LEN)
                    .map(|j| {
                        local.leaf_chunk_start_ind[j]
                            * (if j + i < SPONGE_RATE {
                                local.sponge_block[j + i]
                            } else {
                                next.sponge_block[j + i - SPONGE_RATE]
                            })
                    })
                    .sum()
            })),
        local.is_recevie_merkle_tree[2] * not(local.is_last_sponge_step::<AB>()),
    );
}
