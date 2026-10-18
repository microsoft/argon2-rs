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
    ensures final(h)@ == specs::blake2b_compress_block(
        old(h)@, buffer@, ((counter as int) + 128) as u128, false),
        result == ((counter as int) + 128) as u128,
))]
pub(crate) fn flush_full_buffer(h: &mut [u64; 8], counter: u128, buffer: &[u8; 128]) -> u128 {
    let counter = counter + 128;
    crate::blake2b_compress::compress_block(h, buffer, counter, false);
    counter
}

#[cfg_attr(verus_keep_ghost, verifier::spinoff_prover)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires *old(buffered_len) <= 128, input.len() > 0,
        *old(counter) as int + *old(buffered_len) as int + input.len() as int <= u128::MAX as int,
        *old(buffered_len) < 128 || *old(counter) <= u128::MAX - 128,
    ensures final(h)@ == specs::blake2b_update_step(
        old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, input@).0,
        *final(counter) == specs::blake2b_update_step(
            old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, input@).1,
        final(buffer)@ == specs::blake2b_update_step(
            old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, input@).2,
        *final(buffered_len) as nat == specs::blake2b_update_step(
            old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, input@).3,
        result as nat == specs::blake2b_update_step(
            old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, input@).4,
        result as nat == specs::blake2b_update_take(
            if *old(buffered_len) == 128 { 0nat } else { *old(buffered_len) as nat }, input@.len()),
        0 < result <= input.len(), *final(buffered_len) <= 128,
        *final(counter) as int + *final(buffered_len) as int
            == *old(counter) as int + *old(buffered_len) as int + result as int,
))]
pub(crate) fn update_step(
    h: &mut [u64; 8],
    counter: &mut u128,
    buffer: &mut [u8; 128],
    buffered_len: &mut usize,
    input: &[u8],
) -> usize {
    #[cfg(verus_keep_ghost)]
    proof! {
        specs::blake2b_update_step_progress(h@, *counter, buffer@, *buffered_len as nat, input@);
    }
    if *buffered_len == 128 {
        *counter = flush_full_buffer(h, *counter, buffer);
        *buffered_len = 0;
    }
    let available = 128 - *buffered_len;
    let take = if input.len() < available { input.len() } else { available };
    append(buffer, *buffered_len, &input[..take]);
    *buffered_len += take;
    take
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
    let padded = crate::wipe::Bytes(pad_final_block(buffer, buffered_len));
    let final_counter = counter + buffered_len as u128;
    let mut state = crate::wipe::Words(*h);
    crate::blake2b_compress::compress_block(&mut state.0, &padded.0, final_counter, true);
    let mut output = [0u8; 64];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 64 ==>
                if i < index as int {
                    output@[i] == (state.0@[(i / 8)] >> (8 * (i % 8))) as u8
                } else {
                    output@[i] == 0
                },
    ))]
    for index in 0..64 {
        output[index] = (state.0[index / 8] >> (8 * (index % 8))) as u8;
    }
    output
}
