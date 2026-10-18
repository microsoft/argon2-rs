//! Canonical initial hashing and API-to-RFC field mapping.

use vstd::prelude::*;
use crate::specs;
use crate::specs::digest as stream;
use crate::specs::h_prime as bytes;
use crate::parameters::{Algorithm, Params, Version};

verus! {
// algorithm discriminator y; RFC 9106 section 3.1.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1
pub open spec fn algorithm_word(algorithm: Algorithm) -> u32 {
    match algorithm { Algorithm::Argon2d => 0, Algorithm::Argon2i => 1, Algorithm::Argon2id => 2 }
}

// version v; 0x10 is a legacy extension, not RFC 9106; RFC 9106 section 3.1.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1
pub open spec fn version_word(version: Version) -> u32 {
    match version { Version::V0x10 => 0x10, Version::V0x13 => 0x13 }
}

// step 1: requested parameter ordering; RFC 9106 section 3.2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub open spec fn parameter_fields(
    algorithm: Algorithm, version: Version, params: &Params, tag_len: nat,
) -> Seq<u32>
    recommends tag_len <= u32::MAX as nat,
{
    seq![params.parallelism, tag_len as u32, params.memory_kib, params.iterations,
        version_word(version), algorithm_word(algorithm)]
}

// step 1: serialized parameter header; RFC 9106 section 3.2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub open spec fn header(fields: Seq<u32>) -> Seq<u8>
    recommends fields.len() == 6,
{
    Seq::new(24, |index: int| (fields[index / 4] >> (8 * (index % 4))) as u8)
}

// step 1: input concatenation including length fields; RFC 9106 section 3.2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub open spec fn message(
    fields: Seq<u32>, password: Seq<u8>, salt: Seq<u8>, secret: Seq<u8>, ad: Seq<u8>,
) -> Seq<u8>
    recommends fields.len() == 6,
        password.len() <= u32::MAX as int, salt.len() <= u32::MAX as int,
        secret.len() <= u32::MAX as int, ad.len() <= u32::MAX as int,
{
    header(fields)
        + bytes::length_prefix(password.len() as u32) + password
        + bytes::length_prefix(salt.len() as u32) + salt
        + bytes::length_prefix(secret.len() as u32) + secret
        + bytes::length_prefix(ad.len() as u32) + ad
}

// step 1: initial 64-byte H0 digest; RFC 9106 section 3.2.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub open spec fn h0(
    fields: Seq<u32>, password: Seq<u8>, salt: Seq<u8>, secret: Seq<u8>, ad: Seq<u8>,
) -> Seq<u8> {
    stream::blake2b_stream_digest(
        specs::blake2b_initial_h(64), 0u128, message(fields, password, salt, secret, ad),
    )
}
}
