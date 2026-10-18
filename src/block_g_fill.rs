//! Scalar Argon2 block compression G over one 128-word block.

use crate::block_g;
use crate::block_g_columns;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == specs::xor_words(prev@, reference@),
))]
fn xor_inputs(prev: &[u64; 128], reference: &[u64; 128]) -> [u64; 128] {
    let mut r = [0u64; 128];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 128 ==>
                if i < index as int {
                    r@[i] == prev@[i] ^ reference@[i]
                } else {
                    r@[i] == 0
                },
        decreases 128 - index,
    ))]
    for index in 0..128 {
        r[index] = prev[index] ^ reference[index];
    }
    r
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == if with_xor {
        specs::xor_words(r@, old_next@)
    } else {
        r@
    },
))]
fn prepare_tmp(r: &[u64; 128], old_next: &[u64; 128], with_xor: bool) -> [u64; 128] {
    let mut tmp = *r;
    if with_xor {
        #[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                tmp@ == crate::invariant_specs::xor_words_prefix(r@, old_next@, index as int),
            decreases 128 - index,
        ))]
        for index in 0..128 {
            tmp[index] ^= old_next[index];
        }
    }
    tmp
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(words)@ == specs::permute_columns(specs::permute_rows(old(words)@)),
))]
fn permute_block(words: &mut [u64; 128]) {
    #[cfg(verus_keep_ghost)]
    proof! { crate::invariant_specs::complete_rows(words@); }
    block_g::permute_rows(words);
    #[cfg(verus_keep_ghost)]
    proof! { crate::invariant_specs::complete_columns(words@); }
    block_g_columns::permute_columns(words);
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(next)@ == specs::xor_words(tmp@, transformed@),
))]
fn xor_output(tmp: &[u64; 128], transformed: &[u64; 128], next: &mut [u64; 128]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 128 ==>
                if i < index as int {
                    next@[i] == tmp@[i] ^ transformed@[i]
                } else {
                    next@[i] == old(next)@[i]
                },
        decreases 128 - index,
    ))]
    for index in 0..128 {
        next[index] = tmp[index] ^ transformed[index];
    }
}

#[inline(always)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(next)@ == specs::fill_block_result(prev@, reference@, old(next)@, with_xor),
))]
pub fn fill_block(
    prev: &[u64; 128],
    reference: &[u64; 128],
    next: &mut [u64; 128],
    with_xor: bool,
) {
    let mut r = crate::wipe::Words(xor_inputs(prev, reference));
    let tmp = crate::wipe::Words(prepare_tmp(&r.0, next, with_xor));
    permute_block(&mut r.0);
    xor_output(&tmp.0, &r.0, next);
}
