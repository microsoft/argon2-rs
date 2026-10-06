//! Iterative streaming update loop for the BLAKE2b state.

use crate::blake2b_buffer::update_step;

pub(crate) fn update(
    h: &mut [u64; 8],
    counter: &mut u128,
    buffer: &mut [u8; 128],
    buffered_len: &mut usize,
    data: &mut &[u8],
) {
    while !data.is_empty() {
        let input = *data;
        let (next_h, next_counter, next_buffer, next_len, consumed) =
            update_step(*h, *counter, *buffer, *buffered_len, input);
        *h = next_h;
        *counter = next_counter;
        *buffer = next_buffer;
        *buffered_len = next_len;
        *data = &input[consumed..];
    }
}
