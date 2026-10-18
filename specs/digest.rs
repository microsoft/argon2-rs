//! Canonical unkeyed BLAKE2b digest; not the streaming implementation trace.

use vstd::prelude::*;
use crate::specs;

verus! {
// recursive non-final block processing; RFC 7693 section 3.3.
// https://www.rfc-editor.org/rfc/rfc7693.html#section-3.3
#[verifier::opaque]
pub open spec fn blake2b_nonfinal_blocks(
    initial_h: Seq<u64>, initial_counter: u128, message: Seq<u8>, blocks: nat,
) -> Seq<u64>
    recommends initial_h.len() == 8, 128 * blocks <= message.len(),
        initial_counter as int + 128 * blocks <= u128::MAX as int,
    decreases blocks,
{
    if blocks == 0 {
        initial_h
    } else {
        specs::blake2b_compress_block(
            blake2b_nonfinal_blocks(initial_h, initial_counter, message, (blocks - 1) as nat),
            message.subrange(128 * (blocks - 1), (128 * blocks) as int),
            (initial_counter as int + 128 * blocks) as u128, false,
        )
    }
}

// unkeyed digest including the empty-message case; RFC 7693 section 3.3.
// https://www.rfc-editor.org/rfc/rfc7693.html#section-3.3
#[verifier::opaque]
pub open spec fn blake2b_stream_digest(
    initial_h: Seq<u64>, initial_counter: u128, message: Seq<u8>,
) -> Seq<u8>
    recommends initial_h.len() == 8,
        initial_counter as int + message.len() <= u128::MAX as int,
{
    let blocks = if message.len() == 0 { 0nat } else { ((message.len() - 1) / 128) as nat };
    let remaining = message.len() - 128 * blocks;
    let padded = Seq::new(128, |index: int|
        if index < remaining { message[128 * blocks + index] } else { 0u8 });
    let state = specs::blake2b_compress_block(
        blake2b_nonfinal_blocks(initial_h, initial_counter, message, blocks), padded,
        (initial_counter as int + message.len()) as u128, true,
    );
    specs::blake2b_serialize_state(state)
}
}
