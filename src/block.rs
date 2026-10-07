//! The Argon2 1024-byte block type and its compression function `G`
//! (spec section 3.4 and Appendix A).

pub use crate::block_g_fill::fill_block;
#[cfg(verus_keep_ghost)]
use vstd::prelude::{verus_spec, verus_verify};

/// A single 1024-byte Argon2 memory block, stored as 128 64-bit words.
/// 64-byte aligned to avoid cache-line splits on the random-access reads
/// this memory-hard algorithm performs across the whole working set.
#[derive(Clone)]
#[repr(align(64))]
pub struct Block(pub [u64; 128]);

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Block {
    pub const SIZE_BYTES: usize = 1024;
    pub const SIZE_WORDS: usize = 128;
}

impl Block {
    pub fn zero() -> Self {
        Block([0u64; 128])
    }

    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SIZE_BYTES);
        let mut w = [0u64; 128];
        for (i, word) in w.iter_mut().enumerate() {
            *word = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        }
        Block(w)
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut out = [0u8; Self::SIZE_BYTES];
        for (i, word) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[inline]
    pub fn xor_with(&mut self, other: &Block) {
        for i in 0..128 {
            self.0[i] ^= other.0[i];
        }
    }

    #[inline]
    pub fn xor_with_slice(&mut self, other: &[u64]) {
        for i in 0..128 {
            self.0[i] ^= other[i];
        }
    }
}

/// Permutation P over 16 64-bit words (Appendix A): one column round
/// followed by one diagonal round of the modified Blake2b round function.
#[inline(always)]
#[cfg(test)]
fn permute(v: &mut [u64; 16]) {
    *v = crate::block_primitives::permute(*v);
}

/// Compression function `G(X, Y)` (spec section 3.4): `R = X xor Y`, apply
/// `P` rowwise then columnwise over the 8x8 matrix of 16-byte registers,
/// output `Z xor R`.
#[inline(always)]
pub fn compress(x: &[u64], y: &[u64], out: &mut [u64]) {
    let x: &[u64; 128] = x.try_into().unwrap();
    let y: &[u64; 128] = y.try_into().unwrap();
    fill_block(x, y, out.try_into().unwrap(), false);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_permutation_matches_reference() {
        fn blamka_reference(first: u64, second: u64) -> u64 {
            (first as u128 + second as u128 + 2 * (first as u32 as u128) * (second as u32 as u128))
                as u64
        }

        fn gb_reference(mut words: [u64; 4]) -> [u64; 4] {
            for (first_rotation, second_rotation) in [(32, 24), (16, 63)] {
                words[0] = blamka_reference(words[0], words[1]);
                words[3] = (words[3] ^ words[0]).rotate_right(first_rotation);
                words[2] = blamka_reference(words[2], words[3]);
                words[1] = (words[1] ^ words[2]).rotate_right(second_rotation);
            }
            words
        }

        fn check(input: [u64; 16]) {
            let mut expected = input;
            for [first, second, third, fourth] in [
                [0, 4, 8, 12],
                [1, 5, 9, 13],
                [2, 6, 10, 14],
                [3, 7, 11, 15],
                [0, 5, 10, 15],
                [1, 6, 11, 12],
                [2, 7, 8, 13],
                [3, 4, 9, 14],
            ] {
                let words = [expected[first], expected[second], expected[third], expected[fourth]];
                let mixed = gb_reference(words);
                let actual = crate::block_primitives::gb(words[0], words[1], words[2], words[3]);
                assert_eq!([actual.0, actual.1, actual.2, actual.3], mixed);
                assert_eq!(
                    crate::block_primitives::blamka(words[0], words[1]),
                    blamka_reference(words[0], words[1])
                );
                for (index, value) in [first, second, third, fourth].into_iter().zip(mixed) {
                    expected[index] = value;
                }
            }
            let mut actual = input;
            permute(&mut actual);
            assert_eq!(actual, expected);
        }

        for word in [0, 1, u32::MAX as u64, 1u64 << 32, 1u64 << 63, u64::MAX] {
            check([word; 16]);
        }
        for bit in 0..64 {
            for index in 0..16 {
                let mut input = [0; 16];
                input[index] = 1u64 << bit;
                check(input);
            }
        }
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..256 {
            check(core::array::from_fn(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            }));
        }
    }

    #[test]
    fn compress_is_deterministic_and_nontrivial() {
        let x = Block::zero();
        let mut y = Block::zero();
        y.0[0] = 1;
        let mut out1 = Block::zero();
        let mut out2 = Block::zero();
        compress(&x.0, &y.0, &mut out1.0);
        compress(&x.0, &y.0, &mut out2.0);
        assert_eq!(out1.0, out2.0);
        // G(0,0) should be the all-zero block (P(0) = 0), used as a sanity check.
        let zero = Block::zero();
        let mut out_zero = Block::zero();
        compress(&zero.0, &zero.0, &mut out_zero.0);
        assert_eq!(out_zero.0, [0u64; 128]);
        // Any nonzero input should not collapse back to zero.
        assert_ne!(out1.0, [0u64; 128]);
    }
}
