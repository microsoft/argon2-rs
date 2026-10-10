//! Verifiable 128-word scalar compression helpers.

use crate::block_primitives;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires row < 8,
    ensures result@ == specs::gather_row(words@, row as int),
))]
pub(crate) fn gather_row(words: &[u64; 128], row: usize) -> [u64; 16] {
    let mut gathered = [0u64; 16];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 16 ==>
                if i < index as int {
                    gathered@[i] == specs::gather_row(words@, row as int)[i]
                } else {
                    gathered@[i] == 0
                },
    ))]
    for index in 0..16 {
        gathered[index] = words[16 * row + index];
    }
    gathered
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires row < 8,
    ensures final(words)@ == specs::scatter_row_prefix(
        old(words)@, row as int, 16, output@),
))]
pub(crate) fn scatter_row(words: &mut [u64; 128], row: usize, output: &[u64; 16]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            words@ == specs::scatter_row_prefix(
                old(words)@, row as int, index as int, output@),
    ))]
    for index in 0..16 {
        words[16 * row + index] = output[index];
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(words)@ == specs::permute_rows_prefix(old(words)@, 8),
))]
#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]
pub(crate) fn permute_rows(words: &mut [u64; 128]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            words@ == specs::permute_rows_prefix(old(words)@, row as nat),
    ))]
    for row in 0..8 {
        let gathered = gather_row(words, row);
        let output = block_primitives::permute(gathered);
        scatter_row(words, row, &output);
    }
}
