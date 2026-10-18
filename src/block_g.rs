//! Verifiable 128-word scalar compression helpers.

use crate::block_primitives;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
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
        decreases 16 - index,
    ))]
    for index in 0..16 {
        gathered[index] = words[16 * row + index];
    }
    gathered
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires row < 8,
    ensures final(words)@ == crate::invariant_specs::scatter_row_prefix(
        old(words)@, row as int, 16, output@),
))]
pub(crate) fn scatter_row(words: &mut [u64; 128], row: usize, output: &[u64; 16]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            words@ == crate::invariant_specs::scatter_row_prefix(
                old(words)@, row as int, index as int, output@),
        decreases 16 - index,
    ))]
    for index in 0..16 {
        words[16 * row + index] = output[index];
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(words)@ == crate::invariant_specs::permute_rows_prefix(old(words)@, 8),
))]
#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
pub(crate) fn permute_rows(words: &mut [u64; 128]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            words@ == crate::invariant_specs::permute_rows_prefix(old(words)@, row as nat),
        decreases 8 - row,
    ))]
    for row in 0..8 {
        let gathered = crate::wipe::Words(gather_row(words, row));
        let output = crate::wipe::Words(block_primitives::permute(&gathered.0));
        scatter_row(words, row, &output.0);
    }
}
