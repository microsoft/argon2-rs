use vstd::prelude::*;
use crate::specs;
use crate::blake2b_update_model as stream;
use crate::blake2b_long_model as bytes;

verus! {
pub proof fn parts_step(parts: Seq<&[u8]>, completed: nat)
    requires completed <= parts.len(),
    ensures completed == 0 ==> stream::blake2b_parts_prefix(parts, completed) == Seq::empty(),
        completed > 0 ==> stream::blake2b_parts_prefix(parts, completed)
            == stream::blake2b_parts_prefix(parts, (completed - 1) as nat)
                + parts[(completed - 1) as int]@,
{
    reveal(stream::blake2b_parts_prefix);
}

pub open spec fn header(fields: Seq<u32>) -> Seq<u8>
    recommends fields.len() == 6,
{
    Seq::new(24, |index: int| (fields[index / 4] >> (8 * (index % 4))) as u8)
}

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

pub open spec fn h0(
    fields: Seq<u32>, password: Seq<u8>, salt: Seq<u8>, secret: Seq<u8>, ad: Seq<u8>,
) -> Seq<u8> {
    stream::blake2b_stream_digest(
        specs::blake2b_initial_h(64), 0u128, message(fields, password, salt, secret, ad),
    )
}
}