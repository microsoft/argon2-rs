//! Final lane reduction and little-endian block serialization.

use crate::memory::Memory;
#[cfg(verus_keep_ghost)]
use crate::{memory, specs};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
// Lane-tail reduction: RFC 9106 section 3.2 step 7.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
#[verifier::opaque]
pub(crate) open spec fn final_xor(words: Seq<u64>, lanes: nat, lane_length: nat, completed: nat) -> Seq<u64>
    decreases completed,
{
    if completed == 0 {
        Seq::new(128, |_index: int| 0u64)
    } else {
        specs::xor_words(
            final_xor(words, lanes, lane_length, (completed - 1) as nat),
            memory::block_words(words, ((completed - 1) * lane_length + lane_length - 1) as int),
        )
    }
}

// LE64 block encoding: RFC 9106 sections 2 and 3.2 step 8.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-2
pub(crate) open spec fn serialize_words(words: Seq<u64>) -> Seq<u8>
    recommends words.len() == 128,
{
    Seq::new(1024, |position: int|
        (words[position / 8] >> ((position % 8) * 8)) as u8)
}
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires words@.len() == 128,
    ensures final(words)@ == specs::xor_words(old(words)@, block@),
))]
fn xor_block(words: &mut [u64; 128], block: &[u64; 128]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant forall|index: int| 0 <= index < 128 ==>
            words@[index] == if index < offset as int {
                old(words)@[index] ^ block@[index]
            } else { old(words)@[index] },
    ))]
    for offset in 0..128 {
        words[offset] ^= block[offset];
    }
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires lanes > 0, lane_length >= 8,
        lanes as int * lane_length as int <= u32::MAX as int,
        lanes as int * lane_length as int * 128 == memory.words().len(),
        old(result)@ == Seq::new(128, |_index: int| 0u64),
    ensures final(result)@ == final_xor(memory.words(), lanes as nat, lane_length as nat, lanes as nat),
))]
pub(crate) fn final_block(memory: &Memory, lanes: u32, lane_length: u32, result: &mut [u64; 128]) {
    let mut lane = 0u32;
    let mut lane_base = 0u32;
    #[cfg(verus_keep_ghost)]
    proof! { reveal(final_xor); }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant result@ == final_xor(memory.words(), lanes as nat, lane_length as nat, lane as nat),
            lane_base as int == lane as int * lane_length as int,
            lane <= lanes,
            lane_base as int <= lanes as int * lane_length as int,
        decreases lanes - lane,
    ))]
    while lane < lanes {
        #[cfg(verus_keep_ghost)]
        proof! {
            assert((lane as int + 1) * lane_length as int
                <= lanes as int * lane_length as int) by(nonlinear_arith) requires
                    lane < lanes, lane_length >= 8;
            assert(lane_base as int + lane_length as int
                <= lanes as int * lane_length as int) by(nonlinear_arith) requires
                    lane_base as int == lane as int * lane_length as int,
                    lane < lanes, lane_length >= 8;
        }
        let block_index = lane_base + lane_length - 1;
        #[cfg(verus_keep_ghost)]
        proof! {
            assert((block_index as int + 1) * 128 <= memory.words().len())
                by(nonlinear_arith) requires
                    block_index as int == lane_base as int + lane_length as int - 1,
                    lane_base as int + lane_length as int <= lanes as int * lane_length as int,
                    lanes as int * lane_length as int * 128 == memory.words().len();
        }
        let block = crate::wipe::Words(memory.block_copy(block_index as usize));
        xor_block(result, &block.0);
        #[cfg(verus_keep_ghost)]
        proof_decl! { let ghost old_base = lane_base as int; let ghost old_lane = lane as int; }
        lane_base += lane_length;
        lane += 1;
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(lane_base as int == lane as int * lane_length as int)
                by(nonlinear_arith) requires
                    old_base == old_lane * lane_length as int,
                    lane_base as int == old_base + lane_length as int,
                    lane as int == old_lane + 1;
            reveal(final_xor);
        }
    }
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires old(bytes)@ == Seq::new(1024, |_index: int| 0u8),
    ensures final(bytes)@ == serialize_words(words@),
))]
pub(crate) fn serialize_block(words: &[u64; 128], bytes: &mut [u8; 1024]) {
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant forall|position: int| 0 <= position < 1024 ==>
            bytes@[position] == if position < offset as int {
                (words@[position / 8] >> ((position % 8) * 8)) as u8
            } else { 0u8 },
    ))]
    for offset in 0..1024 {
        let word = offset / 8;
        let byte = offset % 8;
        bytes[offset] = (words[word] >> (byte * 8)) as u8;
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires 1 <= out_len <= u32::MAX as usize,
        out_len <= isize::MAX as usize,
    ensures result@ == crate::specs::h_prime::h_prime(out_len as nat, serialize_words(words@)),
        result@.len() == out_len as nat,
))]
pub(crate) fn tag_from_block(out_len: usize, words: &[u64; 128]) -> Vec<u8> {
    let mut bytes = crate::wipe::Bytes([0u8; 1024]);
    #[cfg(verus_keep_ghost)]
    proof! { assert(bytes.0@ =~= Seq::new(1024, |_index: int| 0u8)); }
    serialize_block(words, &mut bytes.0);
    let parts: [&[u8]; 1] = [&bytes.0];
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::blake2b_update_model::blake2b_parts_single(parts@);
    }
    crate::blake2b::blake2b_long(out_len, &parts)
}

#[cfg_attr(verus_keep_ghost, verifier::spinoff_prover)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires lanes > 0, lane_length >= 8,
        lanes as int * lane_length as int <= u32::MAX as int,
        lanes as int * lane_length as int * 128 == memory.words().len(),
        1 <= out_len <= u32::MAX as usize,
        out_len <= isize::MAX as usize,
    ensures result@ == crate::specs::h_prime::h_prime(
        out_len as nat, serialize_words(final_xor(memory.words(), lanes as nat,
            lane_length as nat, lanes as nat))),
        result@.len() == out_len as nat,
))]
pub(crate) fn scalar_tag(memory: &Memory, lanes: u32, lane_length: u32, out_len: usize) -> Vec<u8> {
    let mut words = crate::wipe::Words([0u64; 128]);
    #[cfg(verus_keep_ghost)]
    proof! { assert(words.0@ =~= Seq::new(128, |_index: int| 0u64)); }
    final_block(memory, lanes, lane_length, &mut words.0);
    tag_from_block(out_len, &words.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_matches_block_byte_encoding() {
        let words = core::array::from_fn(|index| {
            (index as u64).wrapping_mul(0x9e3779b97f4a7c15) ^ 0x0123456789abcdef
        });
        let mut bytes = [0u8; 1024];
        serialize_block(&words, &mut bytes);
        assert_eq!(bytes, crate::block::Block(words).to_bytes());
    }
}
