//! Same-source BLAKE2b mixing transition used by the compression function.

#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == specs::blake2b_decode_block(block@),
))]
pub(crate) fn decode_message(block: &[u8; 128]) -> [u64; 16] {
    let mut message = [0u64; 16];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 16 ==>
                if i < word_index as int {
                    message@[i] == specs::blake2b_decode_block(block@)[i]
                } else {
                    message@[i] == 0
                },
        decreases 16 - word_index,
    ))]
    for word_index in 0..16 {
        let byte_index = word_index * 8;
        message[word_index] = (block[byte_index] as u64)
            | ((block[byte_index + 1] as u64) << 8)
            | ((block[byte_index + 2] as u64) << 16)
            | ((block[byte_index + 3] as u64) << 24)
            | ((block[byte_index + 4] as u64) << 32)
            | ((block[byte_index + 5] as u64) << 40)
            | ((block[byte_index + 6] as u64) << 48)
            | ((block[byte_index + 7] as u64) << 56);
    }
    message
}

#[cfg_attr(verus_keep_ghost, verifier::rlimit(30))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result == specs::blake2b_g(a, b, c, d, x, y),
))]
pub(crate) fn g_values(a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> (u64, u64, u64, u64) {
    let a = a.wrapping_add(b).wrapping_add(x);
    let d = ((d ^ a) >> 32) | ((d ^ a) << 32);
    let c = c.wrapping_add(d);
    let b = ((b ^ c) >> 24) | ((b ^ c) << 40);
    let a = a.wrapping_add(b).wrapping_add(y);
    let d = ((d ^ a) >> 16) | ((d ^ a) << 48);
    let c = c.wrapping_add(d);
    let b = ((b ^ c) >> 63) | ((b ^ c) << 1);
    (a, b, c, d)
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires a < 16, b < 16, c < 16, d < 16,
        a != b, a != c, a != d, b != c, b != d, c != d,
    ensures final(v)@ == specs::blake2b_g_update(
        old(v)@, a as int, b as int, c as int, d as int, x, y),
))]
pub(crate) fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    let (new_a, new_b, new_c, new_d) = g_values(v[a], v[b], v[c], v[d], x, y);
    v[a] = new_a;
    v[b] = new_b;
    v[c] = new_c;
    v[d] = new_d;
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires specs::valid_blake2b_round_sigma(sigma@),
    ensures final(v)@ == specs::blake2b_round(old(v)@, message@, sigma@),
))]
pub(crate) fn round(v: &mut [u64; 16], message: &[u64; 16], sigma: &[usize; 16]) {
    g(v, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
    g(v, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
    g(v, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
    g(v, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);
    g(v, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
    g(v, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
    g(v, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
    g(v, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == specs::blake2b_initial_v(h@, iv@, counter, last),
))]
fn initialize_state(h: &[u64; 8], iv: &[u64; 8], counter: u128, last: bool) -> [u64; 16] {
    let mut state = [0u64; 16];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 16 ==>
                if i < index as int {
                    state@[i] == h@[i]
                } else {
                    state@[i] == 0
                },
        decreases 8 - index,
    ))]
    for index in 0..8 {
        state[index] = h[index];
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 16 ==>
                if i < 8 {
                    state@[i] == h@[i]
                } else if i < 8 + index as int {
                    state@[i] == iv@[i - 8]
                } else {
                    state@[i] == 0
                },
        decreases 8 - index,
    ))]
    for index in 0..8 {
        state[8 + index] = iv[index];
    }
    state[12] ^= counter as u64;
    state[13] ^= (counter >> 64) as u64;
    if last {
        #[cfg(verus_keep_ghost)]
        proof! { crate::invariant_specs::word_notation_equivalence(state[14]); }
        state[14] = !state[14];
    }
    state
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires specs::valid_blake2b_sigma(sigma@),
    ensures final(state)@ == specs::blake2b_rounds_prefix(old(state)@, message@, sigma@, 12),
))]
fn run_rounds(state: &mut [u64; 16], message: &[u64; 16], sigma: &[[usize; 16]; 12]) {
    #[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            state@ == specs::blake2b_rounds_prefix(
                old(state)@, message@, sigma@, round_index as nat),
        decreases 12 - round_index,
    ))]
    for round_index in 0..12 {
        round(state, message, &sigma[round_index]);
    }
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(h)@ == specs::blake2b_fold(old(h)@, state@),
))]
fn fold_state(h: &mut [u64; 8], state: &[u64; 16]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|i: int| 0 <= i < 8 ==>
                if i < index as int {
                    h@[i] == old(h)@[i] ^ state@[i] ^ state@[i + 8]
                } else {
                    h@[i] == old(h)@[i]
                },
        decreases 8 - index,
    ))]
    for index in 0..8 {
        h[index] = h[index] ^ state[index] ^ state[index + 8];
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires specs::valid_blake2b_sigma(sigma@),
    ensures final(h)@ == specs::blake2b_compress_state(
        old(h)@, message@, counter, last, iv@, sigma@),
))]
pub(crate) fn compress_state_with_params(
    h: &mut [u64; 8],
    message: &[u64; 16],
    counter: u128,
    last: bool,
    iv: &[u64; 8],
    sigma: &[[usize; 16]; 12],
) {
    let mut state = crate::wipe::Words(initialize_state(h, iv, counter, last));
    run_rounds(&mut state.0, message, sigma);
    fold_state(h, &state.0);
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(h)@ == specs::blake2b_rfc_compress_state(old(h)@, message@, counter, last),
))]
pub(crate) fn compress_rfc_state(h: &mut [u64; 8], message: &[u64; 16], counter: u128, last: bool) {
    let iv = crate::blake2b_tables::iv();
    let sigma = crate::blake2b_tables::sigma();
    #[cfg(verus_keep_ghost)]
    proof! { assert(specs::valid_blake2b_sigma(sigma@)); }
    compress_state_with_params(h, message, counter, last, &iv, &sigma)
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(h)@ == specs::blake2b_compress_block(old(h)@, block@, counter, last),
))]
pub(crate) fn compress_block(h: &mut [u64; 8], block: &[u8; 128], counter: u128, last: bool) {
    let message = crate::wipe::Words(decode_message(block));
    compress_rfc_state(h, &message.0, counter, last)
}
