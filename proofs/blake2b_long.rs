use vstd::prelude::*;
use crate::specs;
use crate::blake2b_update_model as model;

verus! {
pub open spec fn length_prefix(length: u32) -> Seq<u8> {
    seq![length as u8, (length >> 8) as u8, (length >> 16) as u8, (length >> 24) as u8]
}

pub proof fn digest_length(out_len: nat, message: Seq<u8>)
    requires 1 <= out_len <= 64, message.len() <= u128::MAX as int,
    ensures model::blake2b_stream_digest(specs::blake2b_initial_h(out_len), 0u128, message).len() == 64,
{
    hide(specs::blake2b_compress_block);
    reveal(model::blake2b_stream_digest);
}

#[verifier::opaque]
pub open spec fn chain(seed: Seq<u8>, rounds: nat) -> Seq<u8>
    recommends seed.len() == 64,
    decreases rounds,
{
    if rounds == 0 {
        seed
    } else {
        model::blake2b_stream_digest(specs::blake2b_initial_h(64), 0u128, chain(seed, (rounds - 1) as nat))
    }
}

pub proof fn chain_length(seed: Seq<u8>, rounds: nat)
    requires seed.len() == 64,
    ensures chain(seed, rounds).len() == 64,
    decreases rounds,
{
    reveal(chain);
    if rounds > 0 {
        chain_length(seed, (rounds - 1) as nat);
        digest_length(64, chain(seed, (rounds - 1) as nat));
    }
}

pub proof fn chain_next(seed: Seq<u8>, rounds: nat)
    requires seed.len() == 64,
    ensures chain(seed, rounds + 1) == model::blake2b_stream_digest(
        specs::blake2b_initial_h(64), 0u128, chain(seed, rounds),
    ),
{
    reveal(chain);
}

#[verifier::opaque]
pub open spec fn output_prefix(seed: Seq<u8>, completed: nat) -> Seq<u8>
    recommends seed.len() == 64,
{
    Seq::new(32 * completed, |index: int| chain(seed, (index / 32) as nat)[index % 32])
}

pub proof fn output_prefix_extend(seed: Seq<u8>, completed: nat)
    requires seed.len() == 64,
    ensures output_prefix(seed, completed + 1)
        == output_prefix(seed, completed) + chain(seed, completed).take(32),
{
    reveal(output_prefix);
    chain_length(seed, completed);
    let extended = output_prefix(seed, completed + 1);
    let joined = output_prefix(seed, completed) + chain(seed, completed).take(32);
    assert forall|index: int| 0 <= index < extended.len() implies
        #[trigger] extended[index] == joined[index] by {
        if index >= 32 * completed {
            assert(index / 32 == completed);
            assert(index % 32 == index - 32 * completed);
        }
    }
    assert(extended =~= joined);
}

#[verifier::opaque]
pub open spec fn h_prime(out_len: nat, message: Seq<u8>) -> Seq<u8>
    recommends 1 <= out_len <= u32::MAX as nat, message.len() + 4 <= u128::MAX as int,
{
    let input = length_prefix(out_len as u32) + message;
    if out_len <= 64 {
        model::blake2b_stream_digest(specs::blake2b_initial_h(out_len), 0u128, input).take(out_len as int)
    } else {
        let seed = model::blake2b_stream_digest(specs::blake2b_initial_h(64), 0u128, input);
        let completed = ((out_len + 31) / 32 - 2) as nat;
        let remaining = out_len - 32 * completed;
        output_prefix(seed, completed)
            + model::blake2b_stream_digest(
                specs::blake2b_initial_h(remaining as nat), 0u128, chain(seed, (completed - 1) as nat),
            ).take(remaining)
    }
}
}