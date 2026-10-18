use crate::specs::h_prime::{length_prefix, chain, output_prefix, h_prime};
use vstd::prelude::*;
use crate::specs;
use crate::blake2b_update_model as model;

verus! {
pub proof fn digest_length(out_len: nat, message: Seq<u8>)
    requires 1 <= out_len <= 64, message.len() <= u128::MAX as int,
    ensures crate::specs::digest::blake2b_stream_digest(specs::blake2b_initial_h(out_len), 0u128, message).len() == 64,
{
    hide(specs::blake2b_compress_block);
    reveal(crate::specs::digest::blake2b_stream_digest);
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
    ensures chain(seed, rounds + 1) == crate::specs::digest::blake2b_stream_digest(
        specs::blake2b_initial_h(64), 0u128, chain(seed, rounds),
    ),
{
    reveal(chain);
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


}