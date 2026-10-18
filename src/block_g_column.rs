//! Verifiable gather, permutation, and scatter helpers for one 16-word column.

use crate::block_primitives;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires column < 8,
    ensures result@ == specs::gather_column(words@, column as int),
))]
pub(crate) fn gather_column(words: &[u64; 128], column: usize) -> [u64; 16] {
    let mut gathered = [0u64; 16];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 16 ==>
                if i < index as int {
                    gathered@[i] == specs::gather_column(words@, column as int)[i]
                } else {
                    gathered@[i] == 0
                },
        decreases 16 - index,
    ))]
    for index in 0..16 {
        gathered[index] = words[16 * (index / 2) + 2 * column + index % 2];
    }
    gathered
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires column < 8,
    ensures final(words)@ == crate::invariant_specs::scatter_column_prefix(
        old(words)@, column as int, 8, output@),
))]
pub(crate) fn scatter_column(words: &mut [u64; 128], column: usize, output: &[u64; 16]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            words@ == crate::invariant_specs::scatter_column_prefix(
                old(words)@, column as int, row as int, output@),
        decreases 8 - row,
    ))]
    for row in 0..8 {
        words[16 * row + 2 * column] = output[2 * row];
        words[16 * row + 2 * column + 1] = output[2 * row + 1];
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires column < 8,
    ensures final(words)@ == specs::permute_one_column(old(words)@, column as int),
))]
pub(crate) fn permute_column(words: &mut [u64; 128], column: usize) {
    let gathered = crate::wipe::Words(gather_column(words, column));
    let output = crate::wipe::Words(block_primitives::permute(&gathered.0));
    scatter_column(words, column, &output.0);
}
