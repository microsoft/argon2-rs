//! Internal loop/streaming relations; not definitions of the canonical hash.

use vstd::prelude::*;
use crate::specs::*;

verus! {
pub proof fn word_notation_equivalence(x: u64)
    ensures WORD_BITS == 64,
        WORD_MODULUS == 0x1_0000_0000_0000_0000u128,
        LOW_WORD_MODULUS == 0x1_0000_0000u64,
        WORD_MODULUS == 1u128 << WORD_BITS,
        LOW_WORD_MODULUS == 1u64 << 32,
        trunc(x) == (x as u32) as u64,
        (x ^ WORD_MASK) == !x,
{
    assert(0x1_0000_0000_0000_0000u128 == 1u128 << 64) by(bit_vector);
    assert(0x1_0000_0000u64 == 1u64 << 32) by(bit_vector);
    assert(x % 0x1_0000_0000u64 == (x as u32) as u64) by(bit_vector);
    assert(x ^ 0xffff_ffff_ffff_ffffu64 == !x) by(bit_vector);
}

pub proof fn complete_rows(words: Seq<u64>)
    requires words.len() == 128,
    ensures permute_rows_prefix(words, 8) == permute_rows(words),
{
    hide(permute_one_row);
    reveal(permute_rows);
    reveal_with_fuel(permute_rows_prefix, 9);
}

pub proof fn complete_columns(words: Seq<u64>)
    requires words.len() == 128,
    ensures permute_columns_prefix(words, 8) == permute_columns(words),
{
    hide(permute_one_column);
    reveal(permute_columns);
    reveal_with_fuel(permute_columns_prefix, 9);
}

pub open spec fn blake2b_buffer_append_prefix(
    before: Seq<u8>,
    start: int,
    data: Seq<u8>,
    copied: int,
) -> Seq<u8>
    recommends before.len() == 128, 0 <= start <= 128,
        start + data.len() <= 128, 0 <= copied <= data.len(),
{
    Seq::new(128, |i: int| {
        if start <= i && i < start + copied {
            data[i - start]
        } else {
            before[i]
        }
    })
}

pub open spec fn blake2b_buffer_append(
    before: Seq<u8>,
    start: int,
    data: Seq<u8>,
) -> Seq<u8>
    recommends before.len() == 128, 0 <= start <= 128,
        start + data.len() <= 128,
{
    blake2b_buffer_append_prefix(before, start, data, data.len() as int)
}

pub open spec fn blake2b_update_take(buffered_len: nat, input_len: nat) -> nat
    recommends buffered_len <= 128,
{
    let available = (128nat - buffered_len) as nat;
    if input_len < available { input_len } else { available }
}

pub open spec fn blake2b_update_step(
    h: Seq<u64>,
    counter: u128,
    buffer: Seq<u8>,
    buffered_len: nat,
    input: Seq<u8>,
) -> (Seq<u64>, u128, Seq<u8>, nat, nat)
    recommends h.len() == 8, buffer.len() == 128,
        buffered_len <= 128, input.len() > 0,
        counter as int + buffered_len as int + input.len() as int <= u128::MAX as int,
        buffered_len < 128 || counter <= u128::MAX - 128,
{
    let (next_h, next_counter, next_len) = if buffered_len == 128 {
        (
            blake2b_compress_block(h, buffer, (counter as int + 128) as u128, false),
            (counter as int + 128) as u128,
            0nat,
        )
    } else {
        (h, counter, buffered_len)
    };
    let take = blake2b_update_take(next_len, input.len());
    let chunk = Seq::new(take, |i: int| input[i]);
    let next_buffer = blake2b_buffer_append(buffer, next_len as int, chunk);
    (next_h, next_counter, next_buffer, next_len + take, take)
}

pub proof fn blake2b_update_step_progress(
    h: Seq<u64>, counter: u128, buffer: Seq<u8>, buffered_len: nat, input: Seq<u8>,
)
    requires h.len() == 8, buffer.len() == 128, buffered_len <= 128,
        input.len() > 0,
        counter as int + buffered_len as int + input.len() as int <= u128::MAX as int,
    ensures ({
        let next = blake2b_update_step(h, counter, buffer, buffered_len, input);
        &&& 0 < next.4 <= input.len()
        &&& next.3 <= 128
        &&& next.1 as int + next.3 as int
            == counter as int + buffered_len as int + next.4 as int
    }),
{
}

pub open spec fn scatter_row_prefix(
    before: Seq<u64>,
    row: int,
    completed_words: int,
    output: Seq<u64>,
) -> Seq<u64>
    recommends before.len() == 128, output.len() == 16,
        0 <= row < 8, 0 <= completed_words <= 16,
{
    Seq::new(128, |i: int| {
        if i / 16 == row && i % 16 < completed_words {
            output[i % 16]
        } else {
            before[i]
        }
    })
}

pub open spec fn permute_rows_prefix(words: Seq<u64>, completed: nat) -> Seq<u64>
    recommends words.len() == 128, completed <= 8,
    decreases completed,
{
    if completed == 0 {
        words
    } else {
        permute_one_row(
            permute_rows_prefix(words, (completed - 1nat) as nat),
            (completed - 1nat) as int,
        )
    }
}

pub open spec fn scatter_column_prefix(
    before: Seq<u64>,
    column: int,
    completed_rows: int,
    output: Seq<u64>,
) -> Seq<u64>
    recommends before.len() == 128, output.len() == 16,
        0 <= column < 8, 0 <= completed_rows <= 8,
{
    Seq::new(128, |i: int| {
        let row = i / 16;
        let col = (i % 16) / 2;
        let half = i % 2;
        if col == column && row < completed_rows {
            output[2 * row + half]
        } else {
            before[i]
        }
    })
}

pub open spec fn permute_columns_prefix(words: Seq<u64>, completed: nat) -> Seq<u64>
    recommends words.len() == 128, completed <= 8,
    decreases completed,
{
    if completed == 0 {
        words
    } else {
        permute_one_column(
            permute_columns_prefix(words, (completed - 1nat) as nat),
            (completed - 1nat) as int,
        )
    }
}

pub open spec fn xor_words_prefix(
    left: Seq<u64>,
    right: Seq<u64>,
    completed: int,
) -> Seq<u64>
    recommends left.len() == 128, right.len() == 128, 0 <= completed <= 128,
{
    Seq::new(128, |i: int| {
        if i < completed {
            left[i] ^ right[i]
        } else {
            left[i]
        }
    })
}

pub open spec fn replace_prefix(
    before: Seq<u64>,
    replacement: Seq<u64>,
    completed: int,
) -> Seq<u64>
    recommends before.len() == 128, replacement.len() == 128,
        0 <= completed <= 128,
{
    Seq::new(128, |i: int| if i < completed { replacement[i] } else { before[i] })
}
}
