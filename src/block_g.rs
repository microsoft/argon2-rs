//! Verifiable 128-word scalar compression helpers.

use crate::block_primitives;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures specs::rows_are_permuted(old(rows)@, final(rows)@),
))]
#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]
pub(crate) fn permute_rows(rows: &mut [[u64; 16]]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            specs::permute_rows_prefix(old(rows)@, rows@, row as int),
    ))]
    for row in 0..rows.len() {
        rows[row] = block_primitives::permute(rows[row]);
    }
}
