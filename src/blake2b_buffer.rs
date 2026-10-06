//! Contracted byte-buffer operations for streaming BLAKE2b.

#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::blake2b_compress::compress_block;

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires start + data.len() <= 128,
    ensures final(buffer)@ == specs::blake2b_buffer_append(
        old(buffer)@, start as int, data@),
))]
pub(crate) fn append(buffer: &mut [u8; 128], start: usize, data: &[u8]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            buffer@ == specs::blake2b_buffer_append_prefix(
                old(buffer)@, start as int, data@, index as int),
    ))]
    for index in 0..data.len() {
        buffer[start + index] = data[index];
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires counter <= u128::MAX - 128,
    ensures result.0@ == specs::blake2b_compress_block(
        h@, buffer@, ((counter as int) + 128) as u128, false),
        result.1 == ((counter as int) + 128) as u128,
))]
pub(crate) fn flush_full_buffer(
    h: [u64; 8],
    counter: u128,
    buffer: &[u8; 128],
) -> ([u64; 8], u128) {
    let counter = counter + 128;
    let h = crate::blake2b_compress::compress_block(h, buffer, counter, false);
    (h, counter)
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires buffered_len <= 128, input.len() > 0,
        counter as int + buffered_len as int + input.len() as int <= u128::MAX as int,
        buffered_len < 128 || counter <= u128::MAX - 128,
    ensures result.0@ == specs::blake2b_update_step(
        h@, counter, buffer@, buffered_len as nat, input@).0,
        result.1 == specs::blake2b_update_step(
            h@, counter, buffer@, buffered_len as nat, input@).1,
        result.2@ == specs::blake2b_update_step(
            h@, counter, buffer@, buffered_len as nat, input@).2,
        result.3 as nat == specs::blake2b_update_step(
            h@, counter, buffer@, buffered_len as nat, input@).3,
        result.4 as nat == specs::blake2b_update_step(
            h@, counter, buffer@, buffered_len as nat, input@).4,
        result.4 as nat == specs::blake2b_update_take(
            if buffered_len == 128 { 0nat } else { buffered_len as nat }, input@.len()),
        0 < result.4 <= input.len(), result.3 <= 128,
        result.1 as int + result.3 as int
            == counter as int + buffered_len as int + result.4 as int,
))]
pub(crate) fn update_step(
    h: [u64; 8],
    counter: u128,
    buffer: [u8; 128],
    buffered_len: usize,
    input: &[u8],
) -> ([u64; 8], u128, [u8; 128], usize, usize) {
    #[cfg(verus_keep_ghost)]
    proof! {
        specs::blake2b_update_step_progress(h@, counter, buffer@, buffered_len as nat, input@);
    }
    let mut h = h;
    let mut counter = counter;
    let mut buffer = buffer;
    let mut buffered_len = buffered_len;
    if buffered_len == 128 {
        let (compressed_h, next_counter) = flush_full_buffer(h, counter, &buffer);
        h = compressed_h;
        counter = next_counter;
        buffered_len = 0;
    }
    let available = 128 - buffered_len;
    let take = if input.len() < available { input.len() } else { available };
    append(&mut buffer, buffered_len, &input[..take]);
    buffered_len += take;
    (h, counter, buffer, buffered_len, take)
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires buffered_len <= 128,
    ensures result@ == specs::blake2b_pad_final_block(buffer@, buffered_len as nat),
))]
pub(crate) fn pad_final_block(buffer: &[u8; 128], buffered_len: usize) -> [u8; 128] {
    let mut padded = *buffer;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 128 ==>
                if i < buffered_len as int {
                    padded@[i] == buffer@[i]
                } else if i < index as int {
                    padded@[i] == 0
                } else {
                    padded@[i] == buffer@[i]
                },
    ))]
    for index in buffered_len..128 {
        padded[index] = 0;
    }
    padded
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires buffered_len <= 128,
        counter as int + buffered_len as int <= u128::MAX as int,
    ensures result@ == specs::blake2b_finalize_result(
        h@, counter, buffer@, buffered_len as nat),
))]
pub(crate) fn finalize_state(
    h: &[u64; 8],
    counter: u128,
    buffer: &[u8; 128],
    buffered_len: usize,
) -> [u8; 64] {
    let padded = pad_final_block(buffer, buffered_len);
    let final_counter = counter + buffered_len as u128;
    let state = crate::blake2b_compress::compress_block(*h, &padded, final_counter, true);
    let mut output = [0u8; 64];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 64 ==>
                if i < index as int {
                    output@[i] == (state@[(i / 8)] >> (8 * (i % 8))) as u8
                } else {
                    output@[i] == 0
                },
    ))]
    for index in 0..64 {
        output[index] = (state[index / 8] >> (8 * (index % 8))) as u8;
    }
    output
}
