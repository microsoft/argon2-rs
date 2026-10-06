//! Zero-dependency BLAKE2b (RFC 7693) implementation.
//!
//! Only the subset needed by Argon2 is exposed: a one-shot hash of up to
//! 64 bytes (`blake2b`), and the Argon2 variable-length hash `H'` built on
//! top of it (`blake2b_long`), as specified in section 3.2 of the Argon2
//! spec ("Variable-length hash function").

use crate::blake2b_tables::iv;

const BLOCK_BYTES: usize = 128;

/// Streaming BLAKE2b hasher (unkeyed), output length 1..=64 bytes.
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

impl Blake2b {
    pub fn new(out_len: usize) -> Self {
        assert!((1..=64).contains(&out_len), "blake2b output length must be 1..=64");
        let mut h = iv();
        // Parameter block for unkeyed, unsalted BLAKE2b: digest_length | key_length<<8 | fanout<<16 | depth<<24
        h[0] ^= 0x0101_0000 ^ (out_len as u64);
        Self { h, t: 0, buf: [0u8; BLOCK_BYTES], buf_len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        crate::blake2b_update::update(
            &mut self.h,
            &mut self.t,
            &mut self.buf,
            &mut self.buf_len,
            &mut data,
        );
    }

    pub fn finalize(self) -> [u8; 64] {
        crate::blake2b_buffer::finalize_state(&self.h, self.t, &self.buf, self.buf_len)
    }
}

/// One-shot BLAKE2b over `parts` (concatenated), with `out_len` in 1..=64.
pub fn blake2b(out_len: usize, parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Blake2b::new(out_len);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// Argon2's variable-length hash function H' (spec section 3.2), for
/// arbitrary `out_len`, built from BLAKE2b restricted to <=64-byte outputs.
pub fn blake2b_long(out_len: usize, parts: &[&[u8]]) -> Vec<u8> {
    let len_le = (out_len as u32).to_le_bytes();

    if out_len <= 64 {
        let mut h = Blake2b::new(out_len);
        h.update(&len_le);
        for p in parts {
            h.update(p);
        }
        let full = h.finalize();
        return full[..out_len].to_vec();
    }

    let mut out = Vec::with_capacity(out_len);

    let mut h = Blake2b::new(64);
    h.update(&len_le);
    for p in parts {
        h.update(p);
    }
    let mut v = h.finalize();
    out.extend_from_slice(&v[..32]);

    let mut remaining = out_len - 32;
    while remaining > 64 {
        v = blake2b(64, &[&v]);
        out.extend_from_slice(&v[..32]);
        remaining -= 32;
    }
    let last = blake2b(remaining, &[&v]);
    out.extend_from_slice(&last[..remaining]);

    debug_assert_eq!(out.len(), out_len);
    out
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
}
