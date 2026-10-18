//! Canonical first-block construction and placement; independent of partial-write proof helpers.

use vstd::prelude::*;
use crate::specs::h_prime as hash;

verus! {
// steps 3-4: recursive lane initialization, retained in the semantic audit; RFC 9106 section 3.2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
#[verifier::opaque]
pub open spec fn initialized_prefix(
    before: Seq<u64>, h0: Seq<u8>, lane_length: nat, completed: nat,
) -> Seq<u64>
    recommends h0.len() == 64, lane_length >= 2,
        completed <= 2 * u32::MAX as nat,
        ((completed + 1) / 2) * lane_length * 128 <= before.len(),
    decreases completed,
{
    if completed == 0 { before } else {
        let previous = (completed - 1) as nat;
        let memory = initialized_prefix(before, h0, lane_length, previous);
        let start = 128 * ((previous / 2) * lane_length + previous % 2) as int;
        let output = block(h0, (previous % 2) as u32, (previous / 2) as u32);
        Seq::new(before.len(), |i: int|
            if start <= i < start + 128 { output[i - start] } else { memory[i] })
    }
}

// steps 3-4: H0, column and lane seed; RFC 9106 section 3.2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub open spec fn seed(h0: Seq<u8>, column: u32, lane: u32) -> Seq<u8>
    recommends h0.len() == 64, column < 2,
{
    h0 + hash::length_prefix(column) + hash::length_prefix(lane)
}

// LE64 decoding of a 1024-byte block; RFC 9106 section 2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-2
pub open spec fn decode(bytes: Seq<u8>) -> Seq<u64>
    recommends bytes.len() == 1024,
{
    Seq::new(128, |word: int| {
        (bytes[8 * word] as u64)
        | ((bytes[8 * word + 1] as u64) << 8)
        | ((bytes[8 * word + 2] as u64) << 16)
        | ((bytes[8 * word + 3] as u64) << 24)
        | ((bytes[8 * word + 4] as u64) << 32)
        | ((bytes[8 * word + 5] as u64) << 40)
        | ((bytes[8 * word + 6] as u64) << 48)
        | ((bytes[8 * word + 7] as u64) << 56)
    })
}

// steps 3-4: H-prime lane starting block; RFC 9106 section 3.2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
#[verifier::opaque]
pub open spec fn block(h0: Seq<u8>, column: u32, lane: u32) -> Seq<u64>
    recommends h0.len() == 64, column < 2,
{
    decode(hash::h_prime(1024, seed(h0, column, lane)))
}
}
