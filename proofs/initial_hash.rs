use crate::specs::initial_hash::{algorithm_word, version_word, parameter_fields, header, message, h0};
use vstd::prelude::*;
use crate::specs;
use crate::blake2b_update_model as stream;
use crate::blake2b_long_model as bytes;
use crate::parameters::{Algorithm, Params, Version};

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


}