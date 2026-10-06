//! Eight-column orchestration for the scalar Argon2 block transform.

use crate::block_g_column;

pub(crate) fn permute_columns(words: &mut [u64; 128]) {
    for column in 0..8 {
        block_g_column::permute_column(words, column);
    }
}
