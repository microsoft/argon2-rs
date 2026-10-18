//! Canonical H-prime; all recursive/concatenation definitions here require RFC review.

use vstd::prelude::*;
use crate::specs;
use crate::specs::digest as model;

verus! {
// LE32 encoding; RFC 9106 section 2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-2
pub open spec fn length_prefix(length: u32) -> Seq<u8> {
    seq![length as u8, (length >> 8) as u8, (length >> 16) as u8, (length >> 24) as u8]
}

// V_i digest chain; RFC 9106 section 3.3.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.3
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

// concatenation of the low 32 bytes of each V_i; RFC 9106 section 3.3.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.3
#[verifier::opaque]
pub open spec fn output_prefix(seed: Seq<u8>, completed: nat) -> Seq<u8>
    recommends seed.len() == 64,
{
    Seq::new(32 * completed, |index: int| chain(seed, (index / 32) as nat)[index % 32])
}

// H-prime, including both output-length cases; RFC 9106 section 3.3.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.3
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
