//! Forced-scalar Argon2 caller composition.

use crate::core_backend::Backend;
#[cfg(verus_keep_ghost)]
use crate::specs;
use crate::{core_final, core_segment, memory::Memory};
use crate::{Algorithm, Error, Params, Version};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
// Complete scalar tag composition: RFC 9106 section 3.2, steps 1-8.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
// Legacy 0x10 is an extension; see specs/README.md for the complete audit boundary.
pub(crate) open spec fn scalar_tag_model(
    algorithm: Algorithm,
    version: Version,
    params: &Params,
    tag_len: nat,
    password: Seq<u8>,
    salt: Seq<u8>,
    secret: Seq<u8>,
    ad: Seq<u8>,
) -> Seq<u8> {
    let h0 = crate::specs::initial_hash::h0(
        crate::specs::initial_hash::parameter_fields(algorithm, version, params, tag_len),
        password, salt, secret, ad,
    );
    let lanes = params.parallelism;
    let blocks = specs::memory_blocks(params.memory_kib, lanes);
    let lane_length = blocks / lanes as int;
    let segment_length = lane_length / 4;
    let initial = crate::specs::initialization::initialized_prefix(
        Seq::new(blocks as nat * 128, |_index: int| 0u64),
        h0, lane_length as nat, 2 * lanes as nat,
    );
    let segment = core_segment::Segment {
        algorithm, version, lanes, lane_length: lane_length as u32,
        segment_length: segment_length as u32, memory_blocks: blocks as u32,
        total_passes: params.iterations, pass: 0, lane: 0, slice: 0,
    };
    let final_memory = core_segment::traversal_prefix(initial, segment, params.iterations as nat);
    crate::specs::h_prime::h_prime(tag_len,
        core_final::serialize_words(core_final::final_xor(
            final_memory, lanes as nat, lane_length as nat, lanes as nat))
    )
}
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires out.len() == tag.len(),
    ensures final(out)@ == tag@,
))]
fn copy_tag(out: &mut [u8], tag: &[u8]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant out.len() == tag.len(),
            forall|index: int| 0 <= index < out.len() ==>
            out@[index] == if index < offset as int {
                tag@[index]
            } else { old(out)@[index] },
        decreases tag.len() - offset,
    ))]
    for offset in 0..tag.len() {
        out[offset] = tag[offset];
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(verus_keep_ghost, verifier::spinoff_prover)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result matches Ok(()) ==> final(out)@ == scalar_tag_model(
        algorithm, version, params, final(out).len() as nat, password@, salt@, secret@, ad@),
))]
pub(crate) fn hash_into_scalar(
    algorithm: Algorithm,
    version: Version,
    params: &Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let h0 = crate::wipe::Bytes(crate::initial_hash::checked_h0(
        algorithm,
        version,
        params,
        password,
        salt,
        secret,
        ad,
        out.len(),
    )?);
    let (mut memory, memory_blocks, lane_length, segment_length) =
        Memory::zeroed_initialized(&h0.0, params, salt.len(), out.len())?;
    #[cfg(verus_keep_ghost)]
    let (geometry_blocks, geometry_lane_length, geometry_segment_length) =
        crate::core_primitives::memory_geometry(params.memory_kib, params.parallelism);
    let seg = core_segment::Segment {
        algorithm,
        version,
        lanes: params.parallelism,
        lane_length,
        segment_length,
        memory_blocks,
        total_passes: params.iterations,
        pass: 0,
        lane: 0,
        slice: 0,
    };
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(seg.valid());
    }
    core_segment::fill_memory(&mut memory, &seg);
    let tag = crate::wipe::ByteVec(core_final::scalar_tag(
        &memory,
        params.parallelism,
        lane_length,
        out.len(),
    ));
    copy_tag(out, &tag.0);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires _backend == Backend::Scalar,
    ensures result matches Ok(()) ==> final(out)@ == scalar_tag_model(
            algorithm, version, params, final(out).len() as nat, password@, salt@, secret@, ad@),
))]
pub(crate) fn scalar_backend(
    _backend: Backend,
    algorithm: Algorithm,
    version: Version,
    params: &Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    hash_into_scalar(algorithm, version, params, password, salt, secret, ad, out)
}
