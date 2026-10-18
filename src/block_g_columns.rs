//! Eight-column orchestration for the scalar Argon2 block transform.

use crate::block_g_column;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(words)@ == crate::invariant_specs::permute_columns_prefix(old(words)@, 8),
))]
pub(crate) fn permute_columns(words: &mut [u64; 128]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            words@ == crate::invariant_specs::permute_columns_prefix(old(words)@, column as nat),
        decreases 8 - column,
    ))]
    for column in 0..8 {
        block_g_column::permute_column(words, column);
    }
}
