//! Zero-dependency BLAKE2b (RFC 7693) implementation.
//!
//! Only the subset needed by Argon2 is exposed: a one-shot hash of up to
//! 64 bytes (`blake2b`), and the Argon2 variable-length hash `H'` built on
//! top of it (`blake2b_long`), as specified in section 3.2 of the Argon2
//! spec ("Variable-length hash function").

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

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
        let mut h = IV;
        // Parameter block for unkeyed, unsalted BLAKE2b: digest_length | key_length<<8 | fanout<<16 | depth<<24
        h[0] ^= 0x0101_0000 ^ (out_len as u64);
        Self { h, t: 0, buf: [0u8; BLOCK_BYTES], buf_len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buf_len == BLOCK_BYTES {
                self.t += BLOCK_BYTES as u128;
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
            let take = core::cmp::min(BLOCK_BYTES - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        self.t += self.buf_len as u128;
        for b in &mut self.buf[self.buf_len..] {
            *b = 0;
        }
        let block = self.buf;
        self.compress(&block, true);
        let mut out = [0u8; 64];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; BLOCK_BYTES], last: bool) {
        let mut m = [0u64; 16];
        for i in 0..16 {
            m[i] = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&IV);

        v[12] ^= (self.t & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        v[13] ^= ((self.t >> 64) & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        if last {
            v[14] = !v[14];
        }

        for round in 0..12 {
            let s = &SIGMA[round];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
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
}
