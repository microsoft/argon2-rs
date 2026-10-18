//! Zero-dependency BLAKE2b (RFC 7693) implementation.
//!
//! Only the subset needed by Argon2 is exposed: a one-shot hash of up to
//! 64 bytes (`blake2b`), and the Argon2 variable-length hash `H'` built on
//! top of it (`blake2b_long`), as specified in section 3.2 of the Argon2
//! spec ("Variable-length hash function").

use crate::blake2b_tables::initial_h;

#[cfg(verus_keep_ghost)]
use crate::blake2b_long_model as long_model;
#[cfg(verus_keep_ghost)]
use crate::blake2b_update_model as model;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

const BLOCK_BYTES: usize = 128;

/// Streaming BLAKE2b hasher (unkeyed), output length 1..=64 bytes.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Blake2b {
    h: [u64; 8],
    t: u128,
    buf: [u8; BLOCK_BYTES],
    buf_len: usize,
}

impl Drop for Blake2b {
    fn drop(&mut self) {
        crate::wipe::bytes(&mut self.buf);
        crate::wipe::words(&mut self.h);
    }
}

#[cfg(verus_keep_ghost)]
verus! {
impl Blake2b {
    pub closed spec fn state(&self) -> (Seq<u64>, u128, Seq<u8>, nat) {
        (self.h@, self.t, self.buf@, self.buf_len as nat)
    }
}
}

#[cfg_attr(verus_keep_ghost, cfg_eval)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Blake2b {
    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        requires 1 <= out_len <= 64,
        ensures result.state().0 == specs::blake2b_initial_h(out_len as nat),
            result.state().1 == 0, result.state().3 == 0,
            forall|index: int| 0 <= index < 128 ==> result.state().2[index] == 0,
    ))]
    pub fn new(out_len: usize) -> Self {
        assert!((1..=64).contains(&out_len), "blake2b output length must be 1..=64");
        let h = initial_h(out_len);
        Self { h, t: 0, buf: [0u8; BLOCK_BYTES], buf_len: 0 }
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires old(self).state().3 <= 128,
            old(self).state().1 as int + old(self).state().3 + data@.len() <= u128::MAX as int,
        ensures final(self).state().3 <= 128,
            final(self).state().1 as int + final(self).state().3
                == old(self).state().1 as int + old(self).state().3 + data@.len(),
            exists|blocks: nat| model::blake2b_update_semantic_at(
                (old(self).state().0, old(self).state().1, old(self).state().2, old(self).state().3, 0nat),
                data@,
                (final(self).state().0, final(self).state().1, final(self).state().2,
                    final(self).state().3, data@.len()),
                blocks,
            ),
    ))]
    pub fn update(&mut self, mut data: &[u8]) {
        crate::blake2b_update::update(
            &mut self.h,
            &mut self.t,
            &mut self.buf,
            &mut self.buf_len,
            &mut data,
        );
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        requires self.state().3 <= 128,
            self.state().1 as int + self.state().3 <= u128::MAX as int,
        ensures result@ == specs::blake2b_finalize_result(
            self.state().0, self.state().1, self.state().2, self.state().3),
    ))]
    pub fn finalize(self) -> [u8; 64] {
        crate::blake2b_buffer::finalize_state(&self.h, self.t, &self.buf, self.buf_len)
    }
}

/// One-shot BLAKE2b over `parts` (concatenated), with `out_len` in 1..=64.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires 1 <= out_len <= 64,
        model::blake2b_parts_prefix(parts@, parts@.len()).len() <= u128::MAX as int,
    ensures result@ == model::blake2b_stream_digest(
        specs::blake2b_initial_h(out_len as nat), 0u128,
        model::blake2b_parts_prefix(parts@, parts@.len()),
    ),
))]
pub fn blake2b(out_len: usize, parts: &[&[u8]]) -> [u8; 64] {
    blake2b_prefixed(out_len, &[], parts)
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires 1 <= out_len <= 64,
        prefix@.len() + model::blake2b_parts_prefix(parts@, parts@.len()).len() <= u128::MAX as int,
    ensures result@ == model::blake2b_stream_digest(
        specs::blake2b_initial_h(out_len as nat), 0u128,
        prefix@ + model::blake2b_parts_prefix(parts@, parts@.len()),
    ),
))]
fn blake2b_prefixed(out_len: usize, prefix: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Blake2b::new(out_len);
    #[cfg(verus_keep_ghost)]
    proof_decl! {
        let ghost initial = (h.state().0, h.state().1, h.state().2, h.state().3, 0nat);
    }
    h.update(prefix);
    #[cfg(verus_keep_ghost)]
    proof_decl! {
        let ghost mut blocks = choose|completed: nat| model::blake2b_update_semantic_at(
            initial, prefix@,
            (h.state().0, h.state().1, h.state().2, h.state().3, prefix@.len()), completed,
        );
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(model::blake2b_parts_prefix);
        assert(model::blake2b_parts_prefix(parts@, 0) == Seq::empty());
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            1 <= out_len <= 64,
            prefix@.len() + model::blake2b_parts_prefix(parts@, parts@.len()).len() <= u128::MAX as int,
            initial.0 == specs::blake2b_initial_h(out_len as nat),
            initial.1 == 0, initial.3 == 0, initial.4 == 0,
            model::blake2b_update_state_valid(initial,
                prefix@.len() + model::blake2b_parts_prefix(parts@, parts@.len()).len()),
            h.state().3 <= 128,
            h.state().1 as int + h.state().3
                == prefix@.len() + model::blake2b_parts_prefix(parts@, index as nat).len(),
            model::blake2b_update_semantic_at(initial,
                prefix@ + model::blake2b_parts_prefix(parts@, index as nat),
                (h.state().0, h.state().1, h.state().2, h.state().3,
                    prefix@.len() + model::blake2b_parts_prefix(parts@, index as nat).len()), blocks),
        decreases parts.len() - index,
    ))]
    for index in 0..parts.len() {
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost processed = prefix@ + model::blake2b_parts_prefix(parts@, index as nat);
            let ghost middle = (h.state().0, h.state().1, h.state().2, h.state().3, processed.len());
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(model::blake2b_parts_prefix);
            model::blake2b_parts_prefix_bound(parts@, (index + 1) as nat, parts@.len());
        }
        h.update(parts[index]);
        #[cfg(verus_keep_ghost)]
        proof! {
            let next_state = (h.state().0, h.state().1, h.state().2, h.state().3, parts@[index as int]@.len());
            let next_blocks = choose|completed: nat| model::blake2b_update_semantic_at(
                model::blake2b_update_restart(middle), parts@[index as int]@, next_state, completed,
            );
            model::blake2b_update_semantic_compose(
                initial, processed, parts@[index as int]@, middle, next_state, blocks, next_blocks,
            );
            reveal(model::blake2b_parts_prefix);
            assert(processed + parts@[index as int]@
                =~= prefix@ + model::blake2b_parts_prefix(parts@, (index + 1) as nat));
            blocks = blocks + next_blocks;
        }
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        model::blake2b_update_semantic_finalize(
            initial, prefix@ + model::blake2b_parts_prefix(parts@, parts@.len()),
            (h.state().0, h.state().1, h.state().2, h.state().3,
                prefix@.len() + model::blake2b_parts_prefix(parts@, parts@.len()).len()), blocks,
        );
    }
    h.finalize()
}

/// Argon2's variable-length hash function H' (spec section 3.2), for
/// arbitrary `out_len`, built from BLAKE2b restricted to <=64-byte outputs.
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires 1 <= out_len <= u32::MAX as usize,
        out_len <= isize::MAX as usize,
        model::blake2b_parts_prefix(parts@, parts@.len()).len() + 4 <= u128::MAX as int,
    ensures result@ == long_model::h_prime(
        out_len as nat, model::blake2b_parts_prefix(parts@, parts@.len()),
    ), result@.len() == out_len,
))]
pub fn blake2b_long(out_len: usize, parts: &[&[u8]]) -> Vec<u8> {
    let len_le = h_prime_length(out_len as u32);

    if out_len <= 64 {
        let full = crate::wipe::Bytes(blake2b_prefixed(out_len, &len_le, parts));
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(long_model::h_prime);
        }
        let mut out = crate::wipe::ByteVec(Vec::with_capacity(out_len));
        out.0.extend_from_slice(&full.0[..out_len]);
        return out.into_inner();
    }

    let mut out = crate::wipe::ByteVec(Vec::with_capacity(out_len));

    let mut v = crate::wipe::Bytes(blake2b_prefixed(64, &len_le, parts));
    out.0.extend_from_slice(&v.0[..32]);
    #[cfg(verus_keep_ghost)]
    proof_decl! {
        let ghost seed = v.0@;
        let ghost mut completed = 1nat;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(long_model::chain);
        reveal(long_model::output_prefix);
        assert(long_model::output_prefix(seed, 1) =~= seed.take(32));
    }

    let mut remaining = out_len - 32;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            64 < out_len <= u32::MAX as usize,
            out_len <= isize::MAX as usize,
            model::blake2b_parts_prefix(parts@, parts@.len()).len() + 4 <= u128::MAX as int,
            seed.len() == 64,
            seed == model::blake2b_stream_digest(specs::blake2b_initial_h(64), 0u128,
                long_model::length_prefix(out_len as u32)
                    + model::blake2b_parts_prefix(parts@, parts@.len())),
            1 <= completed,
            32 < remaining <= out_len,
            out.0.len() as int == 32 * completed,
            out.0.len() as int + remaining as int == out_len as int,
            out.0@ == long_model::output_prefix(seed, completed),
            v.0@ == long_model::chain(seed, (completed - 1) as nat),
        decreases remaining,
    ))]
    while remaining > 64 {
        let input: &[u8] = &v.0;
        let single: [&[u8]; 1] = [input];
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(model::blake2b_parts_prefix);
            assert(model::blake2b_parts_prefix(single@, 0) == Seq::empty());
            assert(model::blake2b_parts_prefix(single@, 1) == input@);
            long_model::chain_next(seed, (completed - 1) as nat);
            long_model::output_prefix_extend(seed, completed);
        }
        let next = crate::wipe::Bytes(blake2b(64, &single));
        v = next;
        out.0.extend_from_slice(&v.0[..32]);
        remaining -= 32;
        #[cfg(verus_keep_ghost)]
        proof! {
            completed = completed + 1;
        }
    }
    let input: &[u8] = &v.0;
    let single: [&[u8]; 1] = [input];
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(model::blake2b_parts_prefix);
        assert(model::blake2b_parts_prefix(single@, 0) == Seq::empty());
        assert(model::blake2b_parts_prefix(single@, 1) == input@);
        assert((out_len as int + 31) / 32 - 2 == completed);
    }
    let last = crate::wipe::Bytes(blake2b(remaining, &single));
    out.0.extend_from_slice(&last.0[..remaining]);

    debug_assert!(out.0.len() == out_len);
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(long_model::h_prime);
    }
    out.into_inner()
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == long_model::length_prefix(length),
))]
pub(crate) fn h_prime_length(length: u32) -> [u8; 4] {
    [length as u8, (length >> 8) as u8, (length >> 16) as u8, (length >> 24) as u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7693 Appendix A test vector: BLAKE2b("abc") with default 64-byte output.
    #[test]
    fn blake2b_abc() {
        let digest = blake2b(64, &[b"abc"]);
        let expected: [u8; 64] = [
            0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12,
            0xF6, 0xE9, 0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F,
            0xDB, 0xFF, 0xA2, 0xD1, 0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52,
            0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95, 0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A,
            0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn blake2b_empty() {
        let digest = blake2b(64, &[b""]);
        let expected: [u8; 64] = [
            0x78, 0x6A, 0x02, 0xF7, 0x42, 0x01, 0x59, 0x03, 0xC6, 0xC6, 0xFD, 0x85, 0x25, 0x52,
            0xD2, 0x72, 0x91, 0x2F, 0x47, 0x40, 0xE1, 0x58, 0x47, 0x61, 0x8A, 0x86, 0xE2, 0x17,
            0xF7, 0x1F, 0x54, 0x19, 0xD2, 0x5E, 0x10, 0x31, 0xAF, 0xEE, 0x58, 0x53, 0x13, 0x89,
            0x64, 0x44, 0x93, 0x4E, 0xB0, 0x4B, 0x90, 0x3A, 0x68, 0x5B, 0x14, 0x48, 0xB7, 0x55,
            0xD5, 0x6F, 0x70, 0x1A, 0xFE, 0x9B, 0xE2, 0xCE,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn streaming_update_boundaries_and_partitions() {
        for input_len in [0usize, 1, 127, 128, 129, 255, 256, 257, 513] {
            let input: Vec<u8> = (0..input_len).map(|index| index as u8).collect();
            for out_len in [1usize, 32, 64] {
                let expected = blake2b(out_len, &[&input]);
                for split in 0..=input_len {
                    let mut hasher = Blake2b::new(out_len);
                    hasher.update(&input[..split]);
                    hasher.update(&[]);
                    hasher.update(&input[split..]);
                    hasher.update(&[]);
                    let compressed = input_len.saturating_sub(1) / BLOCK_BYTES * BLOCK_BYTES;
                    assert_eq!(hasher.t, compressed as u128);
                    assert_eq!(hasher.buf_len, input_len - compressed);
                    assert_eq!(hasher.finalize(), expected, "len={input_len}, split={split}");
                }
                let mut hasher = Blake2b::new(out_len);
                for byte in input.chunks(1) {
                    hasher.update(byte);
                }
                assert_eq!(hasher.finalize(), expected);
            }
        }
    }

    #[test]
    fn multipart_wrapper_matches_concatenation() {
        for input_len in [0usize, 1, 127, 128, 129, 256, 513] {
            let input: Vec<u8> = (0..input_len).map(|index| index as u8).collect();
            for chunk_len in [1usize, 31, 32, 63, 64, 127, 128, 129] {
                let mut parts: Vec<&[u8]> = input.chunks(chunk_len).collect();
                parts.insert(0, &[]);
                parts.push(&[]);
                for out_len in [1usize, 32, 64] {
                    assert_eq!(blake2b(out_len, &parts), blake2b(out_len, &[&input]));
                }
            }
        }
    }

    #[test]
    fn h_prime_matches_independent_boundary_vectors() {
        let vectors = [
            (1usize, "79"),
            (32, "6cfcbf5d43e547674bfbc009070570bcb84e272d359c1e9277e416d74cbbe1c6"),
            (64, "f32577a3172f56657d531faaa43077bb8c9726ada7bb04dd337ec5a65454abff241ad6b87a72440e5127c6f9caa70327f2a699096e52d163eb52d9cd99620593"),
            (65, "77baa447fe6f777c9bcb519545ce80badaf08ecb973fbb4ff45af7d8b569ec7caad65f72669d05153cdeaa563a162bb5ae4c42214551593816008dc560c5a65391"),
            (96, "41b5590d909a09f99c2c5475f782ba721397c7dc626736a3b5b0b369bab78af24a800ffd07bd9b94e073fe5451b20caf770b68afe0839842b4723550bdf083cf9e205e5304aaec1584f10008285f563252fcfcf207ca8c755d1652168b9024af"),
            (97, "c82ccb541fdbecd1ce8090f61f39905cbf4bc03cebd133a002c7babe4ea204fba111552004c5a5338c62d4c7561af5de2665d24d30de9407b9ba1a6ab372054d3e6fdd0c7aa46b48980189af43f3502d68d007a02b1c4efe04c13b9f39d932f335"),
            (128, "e03f682135fde8cb7caea3c8ad7c0a7e78efb026e119732d27b1eea7ba92335a7eb8825c755809add7833e7f75e7a5915bb1b3e70eca7b61bec34cd8c486f8005b05f94166103045f120f568fa1952f24e2a032a35d96e5a61fe520090178a4b60490d839f773b71f88589442d94bf5614c401e1a49b7d4d6e34782c0130e1c2"),
            (129, "81795998330577749c80da69a830b48e222555c721afd94d76dd0f9f2f6c6d18a441f42634e58d17da51d9979ae5638530dbe5db52b33bf8b3f4c3bfdd00287d055c3c4ac752f4996544c83253ee7a663a3c42b8e547d1f0a83bb34eb93aa12215687105cf925cd8d26b794b9ba4eefb3a1eea534a48be42894ddd5de35f354e4c"),
        ];
        for (out_len, expected) in vectors {
            let output = blake2b_long(out_len, &[b"abc"]);
            let actual: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(actual, expected, "out_len={out_len}");
            assert_eq!(output, blake2b_long(out_len, &[b"a", b"bc", b""]));
        }
    }

    #[test]
    fn h_prime_length_encoding_matches_little_endian() {
        for length in [0u32, 1, 64, 65, 0x0403_0201, u32::MAX] {
            assert_eq!(h_prime_length(length), length.to_le_bytes());
        }
    }
}
