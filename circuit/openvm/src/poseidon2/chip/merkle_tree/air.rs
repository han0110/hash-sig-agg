use crate::{
    gadget::{not, select},
    poseidon2::{
        chip::{
            merkle_tree::{
                column::{MerkleTreeCols, NUM_MERKLE_TREE_COLS},
                poseidon2::{PARTIAL_ROUNDS, WIDTH},
            },
            Bus,
        },
        hash_sig::{
            HASH_FE_LEN, MSG_FE_LEN, PARAM_FE_LEN, SPONGE_CAPACITY_VALUES, SPONGE_RATE,
            TWEAK_FE_LEN,
        },
        Poseidon2LinearLayers, F, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE, SBOX_REGISTERS,
    },
    util::zip,
};
use core::{array::from_fn, borrow::Borrow, iter};
use itertools::Itertools;
use openvm_stark_backend::{
    air_builders::sub::SubAirBuilder,
    interaction::InteractionBuilder,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use p3_poseidon2_air::{num_cols, Poseidon2Air};

/// Alias for `Poseidon2Air` specialized with merkle-tree-related parameters.
type Poseidon2AirMerkleTree = Poseidon2Air<
    F,
    Poseidon2LinearLayers<WIDTH>,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

#[derive(Debug)]
pub struct MerkleTreeAir(Poseidon2AirMerkleTree);

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
        self.0
            .eval(&mut SubAirBuilder::<_, Poseidon2AirMerkleTree, _>::new(
                builder,
                0
                    ..num_cols::<
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >(),
            ));

        // TODO:
        // 1. Make sure `encoded_tweak_merkle_tree` (`perm.inputs[PARAM_FE_LEN..][..TWEAK_FE_LEN]`) of path is correct.

        let main = builder.main();

        let mut public_values = builder.public_values().iter().copied().map_into();
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
        eval_merkle_path_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_zero(local.sig_idx);
            builder.assert_one(local.is_merkle_leaf);
            eval_merkle_leaf_first_row(&mut builder, encoded_tweak_merkle_leaf.clone(), local);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_sig_transition(&mut builder, local, next);
            eval_merkle_leaf_transition(&mut builder, local, next);
            eval_merkle_leaf_last_row(&mut builder, epoch, local, next);
            eval_merkle_path_transition(&mut builder, local, next);
            eval_merkle_path_last_row(&mut builder, local, next);
            eval_msg(
                &mut builder,
                encoded_tweak_msg,
                encoded_msg,
                encoded_tweak_merkle_leaf,
                local,
                next,
            );
            eval_padding_transition(&mut builder, local, next);
        }

        // Interaction
        receive_merkle_root_and_msg_hash(builder, local, next);
        receive_merkle_leaf(builder, local, next);
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
    cols.is_receive_merkle_tree.map(|v| builder.assert_bool(v));
    builder.when(not(cols.is_merkle_leaf.into())).assert_zero(
        cols.is_receive_merkle_tree
            .iter()
            .copied()
            .map_into()
            .sum::<AB::Expr>(),
    );
    builder
        .assert_bool(cols.is_msg.into() + cols.is_merkle_leaf.into() + cols.is_merkle_path.into());
    cols.sponge_step.eval_every_row(builder);
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

    builder.assert_eq(local.sig_idx, next.sig_idx);
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
            .map_into()
            .sum::<AB::Expr>(),
    );
}

#[inline]
fn eval_merkle_leaf_first_row<AB>(
    builder: &mut AB,
    encoded_tweak_merkle_leaf: [AB::Expr; TWEAK_FE_LEN],
    cols: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    cols.sponge_step.eval_first_row(builder);
    builder.assert_zero(cols.leaf_chunk_idx);
    (0..SPONGE_RATE)
        .step_by(HASH_FE_LEN)
        .for_each(|i| builder.assert_one(cols.leaf_chunk_start_ind[i]));
    zip!(cols.merkle_parameter(), cols.merkle_parameter_register())
        .for_each(|(a, b)| builder.assert_eq(a, b));
    zip!(cols.encoded_tweak_merkle(), encoded_tweak_merkle_leaf)
        .for_each(|(a, b)| builder.assert_eq(a, b));
    zip!(
        &cols.perm.inputs[PARAM_FE_LEN + TWEAK_FE_LEN..SPONGE_RATE],
        &cols.sponge_block[PARAM_FE_LEN + TWEAK_FE_LEN..]
    )
    .for_each(|(a, b)| builder.assert_eq(*a, *b));
    zip!(&cols.perm.inputs[SPONGE_RATE..], SPONGE_CAPACITY_VALUES)
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
    zip!(next.perm.inputs, local.sponge_output())
        .enumerate()
        .for_each(|(idx, (input, output))| {
            if let Some(block) = next.sponge_block.get(idx).copied() {
                builder.assert_eq(input, output + block.into());
            } else {
                builder.assert_eq(input, output);
            }
        });
    zip!(
        next.merkle_parameter_register(),
        local.merkle_parameter_register()
    )
    .for_each(|(a, b)| builder.assert_eq(a, b));
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
    let mut builder = builder.when(local.is_last_merkle_leaf_row::<AB>());

    local.merkle_leaf_padding().map(|v| builder.assert_zero(v));
    builder.assert_one(next.is_merkle_path);
    next.level.eval_first_row(&mut builder);
    builder.assert_eq(next.epoch_dec, epoch);
    zip!(next.merkle_parameter(), local.merkle_parameter_register())
        .for_each(|(a, b)| builder.assert_eq(a, b));
    zip!(
        next.merkle_path_left(),
        next.merkle_path_right(),
        local.sponge_output().into_iter().take(HASH_FE_LEN)
    )
    .for_each(|(left, right, output)| {
        builder.assert_eq(
            output,
            select(next.is_right.into(), left.into(), right.into()),
        );
    });
}

#[inline]
fn eval_merkle_path_every_row<AB>(builder: &mut AB, cols: &MerkleTreeCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(cols.is_merkle_path);

    cols.level.eval_every_row(&mut builder);
    builder.assert_bool(cols.is_right);
    cols.merkle_path_padding().map(|v| builder.assert_zero(v));
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
    zip!(next.merkle_parameter(), local.merkle_parameter())
        .for_each(|(a, b)| builder.assert_eq(a, b));
    zip!(
        next.merkle_path_left(),
        next.merkle_path_right(),
        local.compress_output::<AB>()
    )
    .for_each(|(left, right, output)| {
        builder.assert_eq(
            output,
            select(next.is_right.into(), left.into(), right.into()),
        );
    });
}

#[inline]
fn eval_merkle_path_last_row<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.is_last_merkle_path_row::<AB>());

    builder.assert_eq(local.epoch_dec, local.is_right);
    zip!(local.merkle_parameter(), next.msg_hash_parameter())
        .for_each(|(a, b)| builder.assert_eq(a, b));
}

#[inline]
fn eval_msg<AB>(
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

    zip!(local.encoded_tweak_msg(), encoded_tweak_msg).for_each(|(a, b)| builder.assert_eq(a, b));
    zip!(local.encoded_msg(), encoded_msg).for_each(|(a, b)| builder.assert_eq(a, b));
    local.msg_hash_padding().map(|v| builder.assert_zero(v));
    builder.assert_zero(next.is_msg.into() + next.is_merkle_path.into());

    let mut builder = builder.when(next.is_merkle_leaf);
    builder.assert_eq(next.sig_idx, local.sig_idx + F::ONE);
    eval_merkle_leaf_first_row(&mut builder, encoded_tweak_merkle_leaf, next);
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
    local.is_receive_merkle_tree.map(|v| builder.assert_zero(v));
    builder.assert_one(next.is_padding::<AB>());
}

#[inline]
fn receive_merkle_root_and_msg_hash<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::MerkleRootAndMsgHash as usize,
        iter::once(local.sig_idx.into())
            .chain(local.merkle_parameter().map(Into::into))
            .chain(local.compress_output::<AB>())
            .chain(next.msg_hash::<AB>()),
        local.is_last_merkle_path_row::<AB>(),
    );
}

#[inline]
fn receive_merkle_leaf<AB>(
    builder: &mut AB,
    local: &MerkleTreeCols<AB::Var>,
    next: &MerkleTreeCols<AB::Var>,
) where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        Bus::MerkleLeaf as usize,
        [local.sig_idx.into(), local.leaf_chunk_idx.into()]
            .into_iter()
            .chain(local.sponge_block[..HASH_FE_LEN].iter().copied().map_into()),
        local.is_receive_merkle_tree[0] * local.leaf_chunk_start_ind[0].into(),
    );
    builder.push_receive(
        Bus::MerkleLeaf as usize,
        [
            local.sig_idx.into(),
            local.leaf_chunk_idx.into() + local.leaf_chunk_start_ind[0].into(),
        ]
        .into_iter()
        .chain((0..HASH_FE_LEN).map(|i| {
            (1..)
                .take(HASH_FE_LEN)
                .map(|j| local.leaf_chunk_start_ind[j] * local.sponge_block[j + i])
                .sum()
        })),
        local.is_receive_merkle_tree[1],
    );
    builder.push_receive(
        Bus::MerkleLeaf as usize,
        [
            local.sig_idx.into(),
            local.leaf_chunk_idx.into() + local.leaf_chunk_start_ind[0].into() + AB::Expr::ONE,
        ]
        .into_iter()
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
        local.is_receive_merkle_tree[2] * not(local.is_last_sponge_step::<AB>()),
    );
}
