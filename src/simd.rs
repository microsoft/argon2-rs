//! x86 / x86-64 SIMD backends for the block-compression step, ported from the
//! reference implementation's `src/opt.c` and `src/blake2/blamka-round-opt.h`
//! (phc-winner-argon2).
//!
//! Two ideas from `opt.c` provide the speed-up over the scalar path:
//!
//! * the BlaMka rounds operate on 2 (SSE2/SSSE3) or 4 (AVX2) 64-bit lanes at
//!   once, and SSSE3/AVX2 do the byte-aligned rotations with one shuffle;
//! * the 1 KiB `state` is carried from one block to the next:
//!   after block `i` is written, `state` already holds it, so block `i + 1`
//!   never re-reads its predecessor from memory.
//!
//! Only the compression step lives here. Reference-block selection is the
//! shared [`walk_segment`], so these backends cannot change *which* blocks are
//! read. Output is checked bit-for-bit against the scalar path by the tests at
//! the bottom of this file and by the RFC 9106 KATs; the Verus proof in
//! `verus/lib.rs` verifies the scalar path only.
//!
//! This module contains `unsafe` for unaligned
//! 128/256-bit loads and stores through references to `[u64; 2]`/`[u64; 4]`
//! (always valid for the access), and calls into the `#[target_feature]`
//! entry points, each made only after runtime detection (SSE2 is baseline).
//! Explicit scratch owners wipe their storage on drop, but cannot guarantee
//! erasure of compiler-generated spills or register copies.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::block::Block;
use crate::core_impl::{walk_segment, Segment};
use crate::memory::Memory;

const W: usize = Block::SIZE_WORDS;

struct Vectors128<const N: usize>([__m128i; N]);

impl<const N: usize> Drop for Vectors128<N> {
    fn drop(&mut self) {
        // SAFETY: all-zero bits are valid for an integer vector; no CPU feature is needed.
        crate::wipe::fill(&mut self.0, unsafe { core::mem::zeroed::<__m128i>() });
    }
}

struct Vectors256<const N: usize>([__m256i; N]);

impl<const N: usize> Drop for Vectors256<N> {
    fn drop(&mut self) {
        // SAFETY: all-zero bits are valid for an integer vector; no CPU feature is needed.
        crate::wipe::fill(&mut self.0, unsafe { core::mem::zeroed::<__m256i>() });
    }
}

// ---------------------------------------------------------------------------
// 128-bit backends: `blamka-round-opt.h` without `__AVX2__`.
//
// The header has two spellings of the 128-bit round that differ only in the
// rotations and the diagonal shuffle: plain SSE2 (shifts, `punpck*qdq`) and
// SSSE3 (`pshufb`, `palignr`). Each lives in its own module below with its own
// `#[target_feature]` set, and `sse_backend!` stamps the shared round/fill code
// into both so an SSE2-only CPU can never execute an SSSE3 instruction.
// ---------------------------------------------------------------------------

macro_rules! sse_backend {
    ($feat:literal) => {
        use super::*;

        type State128 = [__m128i; W / 2];

        #[inline]
        #[target_feature(enable = $feat)]
        fn load128(w: &[u64; 2]) -> __m128i {
            // SAFETY: `w` is 16 readable bytes; `loadu` needs no alignment.
            unsafe { _mm_loadu_si128(w.as_ptr().cast()) }
        }

        #[inline]
        #[target_feature(enable = $feat)]
        fn store128(w: &mut [u64; 2], v: __m128i) {
            // SAFETY: `w` is 16 writable bytes; `storeu` needs no alignment.
            unsafe { _mm_storeu_si128(w.as_mut_ptr().cast(), v) }
        }

        /// `fBlaMka`: `x + y + 2 * lo32(x) * lo32(y)` on each 64-bit lane.
        #[inline]
        #[target_feature(enable = $feat)]
        fn blamka128(x: __m128i, y: __m128i) -> __m128i {
            let z = _mm_mul_epu32(x, y);
            _mm_add_epi64(_mm_add_epi64(x, y), _mm_add_epi64(z, z))
        }

        /// `G1` + `G2`, argument order `(A0, A1, B0, B1, C0, C1, D0, D1)`.
        #[inline]
        #[target_feature(enable = $feat)]
        fn g128(v: &mut [__m128i; 8]) {
            let [a0, a1, b0, b1, c0, c1, d0, d1] = v;
            *a0 = blamka128(*a0, *b0);
            *a1 = blamka128(*a1, *b1);
            *d0 = rotr32(_mm_xor_si128(*d0, *a0));
            *d1 = rotr32(_mm_xor_si128(*d1, *a1));
            *c0 = blamka128(*c0, *d0);
            *c1 = blamka128(*c1, *d1);
            *b0 = rotr24(_mm_xor_si128(*b0, *c0));
            *b1 = rotr24(_mm_xor_si128(*b1, *c1));

            *a0 = blamka128(*a0, *b0);
            *a1 = blamka128(*a1, *b1);
            *d0 = rotr16(_mm_xor_si128(*d0, *a0));
            *d1 = rotr16(_mm_xor_si128(*d1, *a1));
            *c0 = blamka128(*c0, *d0);
            *c1 = blamka128(*c1, *d1);
            *b0 = rotr63(_mm_xor_si128(*b0, *c0));
            *b1 = rotr63(_mm_xor_si128(*b1, *c1));
        }

        /// `BLAKE2_ROUND(A0, A1, B0, B1, C0, C1, D0, D1)`.
        #[inline]
        #[target_feature(enable = $feat)]
        fn round128(v: &mut [__m128i; 8]) {
            g128(v);
            diagonalize(v);
            g128(v);
            undiagonalize(v);
        }

        #[inline]
        #[target_feature(enable = $feat)]
        fn load_state(state: &mut State128, src: &[u64; W]) {
            for (s, w) in state.iter_mut().zip(src.as_chunks::<2>().0) {
                *s = load128(w);
            }
        }

        /// `opt.c` `fill_block`. On entry `state` holds the previous block; on
        /// exit it holds the block just written to `next`.
        #[inline]
        #[target_feature(enable = $feat)]
        fn fill_block(
            state: &mut State128,
            reference: &[u64; W],
            next: &mut [u64; W],
            with_xor: bool,
        ) {
            let r = reference.as_chunks::<2>().0;
            // `R = prev ^ ref` into `state`, and the value to XOR back in at the
            // end (`R`, or `R ^ next` for version 0x13 after pass 0) into `xy`,
            // in one loop as in the C. `from_fn` avoids zero-initializing `xy`.
            let xy = Vectors128::<{ W / 2 }>(if with_xor {
                let n = next.as_chunks::<2>().0;
                core::array::from_fn(|i| {
                    state[i] = _mm_xor_si128(state[i], load128(&r[i]));
                    _mm_xor_si128(state[i], load128(&n[i]))
                })
            } else {
                core::array::from_fn(|i| {
                    state[i] = _mm_xor_si128(state[i], load128(&r[i]));
                    state[i]
                })
            });
            // Rows: 16 contiguous words each.
            for i in 0..8 {
                let b = 8 * i;
                let mut r = Vectors128([
                    state[b],
                    state[b + 1],
                    state[b + 2],
                    state[b + 3],
                    state[b + 4],
                    state[b + 5],
                    state[b + 6],
                    state[b + 7],
                ]);
                round128(&mut r.0);
                state[b..b + 8].copy_from_slice(&r.0);
            }
            // Columns: words 2i, 2i+1, 2i+16, 2i+17, ..., 2i+112, 2i+113.
            for i in 0..8 {
                let mut r = Vectors128([
                    state[i],
                    state[8 + i],
                    state[16 + i],
                    state[24 + i],
                    state[32 + i],
                    state[40 + i],
                    state[48 + i],
                    state[56 + i],
                ]);
                round128(&mut r.0);
                for (k, v) in r.0.iter().enumerate() {
                    state[8 * k + i] = *v;
                }
            }
            for ((s, x), w) in state.iter_mut().zip(xy.0.iter()).zip(next.as_chunks_mut::<2>().0) {
                *s = _mm_xor_si128(*s, *x);
                store128(w, *s);
            }
        }

        #[target_feature(enable = $feat)]
        pub(super) fn fill_segment(memory: &mut Memory, seg: &Segment) {
            let mut state = Vectors128([_mm_setzero_si128(); W / 2]);
            walk_segment(memory, seg, |memory, prev, reference, curr, with_xor, first| {
                if first {
                    load_state(&mut state.0, memory.get(prev));
                }
                let (reference, next) = memory.read_write(reference, curr);
                fill_block(&mut state.0, reference, next, with_xor);
            });
        }

        /// One `G(prev, ref)` (XORed into `out` when `with_xor`), for tests.
        #[cfg(test)]
        #[target_feature(enable = $feat)]
        pub(super) fn fill_one(
            prev: &[u64; W],
            reference: &[u64; W],
            out: &mut [u64; W],
            with_xor: bool,
        ) {
            let mut state = Vectors128([_mm_setzero_si128(); W / 2]);
            load_state(&mut state.0, prev);
            fill_block(&mut state.0, reference, out, with_xor);
        }
    };
}

/// Plain SSE2: the x86-64 baseline. `pshufd` and `paddq` are SSE2, so they are
/// used for `rotr32`/`rotr63`; the other two rotations need shifts.
mod sse2 {
    sse_backend!("sse2");

    #[inline]
    #[target_feature(enable = "sse2")]
    fn rotr32(x: __m128i) -> __m128i {
        _mm_shuffle_epi32::<0b10_11_00_01>(x)
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn rotr24(x: __m128i) -> __m128i {
        _mm_xor_si128(_mm_srli_epi64::<24>(x), _mm_slli_epi64::<40>(x))
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn rotr16(x: __m128i) -> __m128i {
        _mm_xor_si128(_mm_srli_epi64::<16>(x), _mm_slli_epi64::<48>(x))
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn rotr63(x: __m128i) -> __m128i {
        _mm_xor_si128(_mm_srli_epi64::<63>(x), _mm_add_epi64(x, x))
    }

    /// SSE2 `DIAGONALIZE`.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn diagonalize(v: &mut [__m128i; 8]) {
        let [_, _, b0, b1, c0, c1, d0, d1] = v;
        let t0 = *d0;
        let t1 = *b0;
        core::mem::swap(c0, c1);
        *d0 = _mm_unpackhi_epi64(*d1, _mm_unpacklo_epi64(t0, t0));
        *d1 = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(*d1, *d1));
        *b0 = _mm_unpackhi_epi64(*b0, _mm_unpacklo_epi64(*b1, *b1));
        *b1 = _mm_unpackhi_epi64(*b1, _mm_unpacklo_epi64(t1, t1));
    }

    /// SSE2 `UNDIAGONALIZE`.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn undiagonalize(v: &mut [__m128i; 8]) {
        let [_, _, b0, b1, c0, c1, d0, d1] = v;
        core::mem::swap(c0, c1);
        let t0 = *b0;
        let t1 = *d0;
        *b0 = _mm_unpackhi_epi64(*b1, _mm_unpacklo_epi64(*b0, *b0));
        *b1 = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(*b1, *b1));
        *d0 = _mm_unpackhi_epi64(*d0, _mm_unpacklo_epi64(*d1, *d1));
        *d1 = _mm_unpackhi_epi64(*d1, _mm_unpacklo_epi64(t1, t1));
    }
}

/// SSSE3: byte-shuffle rotations (`pshufb`) and `palignr` diagonalization.
mod ssse3 {
    sse_backend!("sse2,ssse3");

    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    fn rotr32(x: __m128i) -> __m128i {
        _mm_shuffle_epi32::<0b10_11_00_01>(x)
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    fn rotr24(x: __m128i) -> __m128i {
        _mm_shuffle_epi8(x, _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10))
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    fn rotr16(x: __m128i) -> __m128i {
        _mm_shuffle_epi8(x, _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9))
    }

    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    fn rotr63(x: __m128i) -> __m128i {
        _mm_xor_si128(_mm_srli_epi64::<63>(x), _mm_add_epi64(x, x))
    }

    /// SSSE3 `DIAGONALIZE`.
    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    fn diagonalize(v: &mut [__m128i; 8]) {
        let [_, _, b0, b1, c0, c1, d0, d1] = v;
        let (t0, t1) = (_mm_alignr_epi8::<8>(*b1, *b0), _mm_alignr_epi8::<8>(*b0, *b1));
        *b0 = t0;
        *b1 = t1;
        core::mem::swap(c0, c1);
        let (t0, t1) = (_mm_alignr_epi8::<8>(*d1, *d0), _mm_alignr_epi8::<8>(*d0, *d1));
        *d0 = t1;
        *d1 = t0;
    }

    /// SSSE3 `UNDIAGONALIZE`.
    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    fn undiagonalize(v: &mut [__m128i; 8]) {
        let [_, _, b0, b1, c0, c1, d0, d1] = v;
        let (t0, t1) = (_mm_alignr_epi8::<8>(*b0, *b1), _mm_alignr_epi8::<8>(*b1, *b0));
        *b0 = t0;
        *b1 = t1;
        core::mem::swap(c0, c1);
        let (t0, t1) = (_mm_alignr_epi8::<8>(*d0, *d1), _mm_alignr_epi8::<8>(*d1, *d0));
        *d0 = t1;
        *d1 = t0;
    }
}

/// SSE2 segment fill. Checks for SSE2 itself on 32-bit x86 (it is baseline on
/// x86-64) and falls back to the scalar path.
pub(crate) fn fill_segment_sse2(memory: &mut Memory, seg: &Segment) {
    if std::is_x86_feature_detected!("sse2") {
        // SAFETY: SSE2 support was just confirmed.
        unsafe { sse2::fill_segment(memory, seg) }
    } else {
        crate::core_impl::fill_segment_scalar(memory, seg)
    }
}

/// SSSE3 segment fill. Checks for SSSE3 itself (cached by `std`) and falls
/// back to SSE2, so it is safe to call on any x86 CPU.
pub(crate) fn fill_segment_ssse3(memory: &mut Memory, seg: &Segment) {
    if std::is_x86_feature_detected!("ssse3") {
        // SAFETY: SSSE3 support was just confirmed; SSSE3 implies SSE2.
        unsafe { ssse3::fill_segment(memory, seg) }
    } else {
        fill_segment_sse2(memory, seg)
    }
}

// ---------------------------------------------------------------------------
// AVX2: `blamka-round-opt.h` with `__AVX2__`, `opt.c` AVX2 `fill_block`.
// ---------------------------------------------------------------------------
//
// Every helper carries `#[target_feature(enable = "avx2")]` so it can inline
// into `fill_segment_avx2`; LLVM will not inline a callee into a caller with
// a smaller feature set, and inlining is what keeps `state` in registers.

type State256 = [__m256i; W / 4];

#[inline]
#[target_feature(enable = "avx2")]
fn load256(w: &[u64; 4]) -> __m256i {
    // SAFETY: `w` is 32 readable bytes and `loadu` has no alignment requirement.
    unsafe { _mm256_loadu_si256(w.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn store256(w: &mut [u64; 4], v: __m256i) {
    // SAFETY: `w` is 32 writable bytes and `storeu` has no alignment requirement.
    unsafe { _mm256_storeu_si256(w.as_mut_ptr().cast(), v) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn rotr32_256(x: __m256i) -> __m256i {
    _mm256_shuffle_epi32::<0b10_11_00_01>(x)
}

#[inline]
#[target_feature(enable = "avx2")]
fn rotr24_256(x: __m256i) -> __m256i {
    let t = _mm256_setr_epi8(
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, //
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
    );
    _mm256_shuffle_epi8(x, t)
}

#[inline]
#[target_feature(enable = "avx2")]
fn rotr16_256(x: __m256i) -> __m256i {
    let t = _mm256_setr_epi8(
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, //
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
    );
    _mm256_shuffle_epi8(x, t)
}

#[inline]
#[target_feature(enable = "avx2")]
fn rotr63_256(x: __m256i) -> __m256i {
    _mm256_xor_si256(_mm256_srli_epi64::<63>(x), _mm256_add_epi64(x, x))
}

#[inline]
#[target_feature(enable = "avx2")]
fn blamka256(x: __m256i, y: __m256i) -> __m256i {
    let ml = _mm256_mul_epu32(x, y);
    let ml = _mm256_add_epi64(ml, ml);
    _mm256_add_epi64(x, _mm256_add_epi64(y, ml))
}

/// `G1_AVX2` + `G2_AVX2`, argument order `(A0, A1, B0, B1, C0, C1, D0, D1)`.
#[inline]
#[target_feature(enable = "avx2")]
fn g256(v: &mut [__m256i; 8]) {
    let [a0, a1, b0, b1, c0, c1, d0, d1] = v;
    *a0 = blamka256(*a0, *b0);
    *d0 = rotr32_256(_mm256_xor_si256(*d0, *a0));
    *c0 = blamka256(*c0, *d0);
    *b0 = rotr24_256(_mm256_xor_si256(*b0, *c0));
    *a1 = blamka256(*a1, *b1);
    *d1 = rotr32_256(_mm256_xor_si256(*d1, *a1));
    *c1 = blamka256(*c1, *d1);
    *b1 = rotr24_256(_mm256_xor_si256(*b1, *c1));

    *a0 = blamka256(*a0, *b0);
    *d0 = rotr16_256(_mm256_xor_si256(*d0, *a0));
    *c0 = blamka256(*c0, *d0);
    *b0 = rotr63_256(_mm256_xor_si256(*b0, *c0));
    *a1 = blamka256(*a1, *b1);
    *d1 = rotr16_256(_mm256_xor_si256(*d1, *a1));
    *c1 = blamka256(*c1, *d1);
    *b1 = rotr63_256(_mm256_xor_si256(*b1, *c1));
}

/// `DIAGONALIZE_1`: each register holds four columns of one 4x4 matrix, so the
/// diagonal step rotates lanes within a register (B by 1, C by 2, D by 3).
#[inline]
#[target_feature(enable = "avx2")]
fn diagonalize1(v: &mut [__m256i; 8]) {
    let [_, _, b0, b1, c0, c1, d0, d1] = v;
    *b0 = _mm256_permute4x64_epi64::<0b00_11_10_01>(*b0);
    *c0 = _mm256_permute4x64_epi64::<0b01_00_11_10>(*c0);
    *d0 = _mm256_permute4x64_epi64::<0b10_01_00_11>(*d0);
    *b1 = _mm256_permute4x64_epi64::<0b00_11_10_01>(*b1);
    *c1 = _mm256_permute4x64_epi64::<0b01_00_11_10>(*c1);
    *d1 = _mm256_permute4x64_epi64::<0b10_01_00_11>(*d1);
}

/// `UNDIAGONALIZE_1`: inverse of [`diagonalize1`].
#[inline]
#[target_feature(enable = "avx2")]
fn undiagonalize1(v: &mut [__m256i; 8]) {
    let [_, _, b0, b1, c0, c1, d0, d1] = v;
    *b0 = _mm256_permute4x64_epi64::<0b10_01_00_11>(*b0);
    *c0 = _mm256_permute4x64_epi64::<0b01_00_11_10>(*c0);
    *d0 = _mm256_permute4x64_epi64::<0b00_11_10_01>(*d0);
    *b1 = _mm256_permute4x64_epi64::<0b10_01_00_11>(*b1);
    *c1 = _mm256_permute4x64_epi64::<0b01_00_11_10>(*c1);
    *d1 = _mm256_permute4x64_epi64::<0b00_11_10_01>(*d1);
}

/// `DIAGONALIZE_2`: in the column pass a matrix's four columns are split
/// across the `*0`/`*1` register pair, so rotating them moves lanes between
/// registers.
#[inline]
#[target_feature(enable = "avx2")]
fn diagonalize2(v: &mut [__m256i; 8]) {
    let [_, _, b0, b1, c0, c1, d0, d1] = v;
    let t1 = _mm256_blend_epi32::<0xCC>(*b0, *b1);
    let t2 = _mm256_blend_epi32::<0x33>(*b0, *b1);
    *b1 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t1);
    *b0 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t2);
    core::mem::swap(c0, c1);
    let t1 = _mm256_blend_epi32::<0xCC>(*d0, *d1);
    let t2 = _mm256_blend_epi32::<0x33>(*d0, *d1);
    *d0 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t1);
    *d1 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t2);
}

/// `UNDIAGONALIZE_2`: inverse of [`diagonalize2`].
#[inline]
#[target_feature(enable = "avx2")]
fn undiagonalize2(v: &mut [__m256i; 8]) {
    let [_, _, b0, b1, c0, c1, d0, d1] = v;
    let t1 = _mm256_blend_epi32::<0xCC>(*b0, *b1);
    let t2 = _mm256_blend_epi32::<0x33>(*b0, *b1);
    *b0 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t1);
    *b1 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t2);
    core::mem::swap(c0, c1);
    let t1 = _mm256_blend_epi32::<0x33>(*d0, *d1);
    let t2 = _mm256_blend_epi32::<0xCC>(*d0, *d1);
    *d0 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t1);
    *d1 = _mm256_permute4x64_epi64::<0b10_11_00_01>(t2);
}

/// `BLAKE2_ROUND_1` (row pass) or `BLAKE2_ROUND_2` (column pass).
#[inline]
#[target_feature(enable = "avx2")]
fn round256<const COLUMN_PASS: bool>(v: &mut [__m256i; 8]) {
    g256(v);
    if COLUMN_PASS {
        diagonalize2(v)
    } else {
        diagonalize1(v)
    }
    g256(v);
    if COLUMN_PASS {
        undiagonalize2(v)
    } else {
        undiagonalize1(v)
    }
}

#[inline]
#[target_feature(enable = "avx2")]
fn load_state256(state: &mut State256, src: &[u64; W]) {
    for (s, w) in state.iter_mut().zip(src.as_chunks::<4>().0) {
        *s = load256(w);
    }
}

/// `opt.c` AVX2 `fill_block`; see the 128-bit `fill_block` for the shape.
#[inline]
#[target_feature(enable = "avx2")]
fn fill_block256(state: &mut State256, reference: &[u64; W], next: &mut [u64; W], with_xor: bool) {
    let r = reference.as_chunks::<4>().0;
    let xy = Vectors256::<{ W / 4 }>(if with_xor {
        let n = next.as_chunks::<4>().0;
        core::array::from_fn(|i| {
            state[i] = _mm256_xor_si256(state[i], load256(&r[i]));
            _mm256_xor_si256(state[i], load256(&n[i]))
        })
    } else {
        core::array::from_fn(|i| {
            state[i] = _mm256_xor_si256(state[i], load256(&r[i]));
            state[i]
        })
    });
    // Rows. `state[8i..8i+4]` is row 2i, `state[8i+4..8i+8]` is row 2i+1.
    for i in 0..4 {
        let b = 8 * i;
        let mut r = Vectors256([
            state[b],
            state[b + 4],
            state[b + 1],
            state[b + 5],
            state[b + 2],
            state[b + 6],
            state[b + 3],
            state[b + 7],
        ]);
        round256::<false>(&mut r.0);
        state[b] = r.0[0];
        state[b + 4] = r.0[1];
        state[b + 1] = r.0[2];
        state[b + 5] = r.0[3];
        state[b + 2] = r.0[4];
        state[b + 6] = r.0[5];
        state[b + 3] = r.0[6];
        state[b + 7] = r.0[7];
    }
    // Columns. Lanes 0-1 of `state[i]` and lanes 0-1 of `state[4 + i]` are one
    // column group; lanes 2-3 are the next.
    for i in 0..4 {
        let mut r = Vectors256([
            state[i],
            state[4 + i],
            state[8 + i],
            state[12 + i],
            state[16 + i],
            state[20 + i],
            state[24 + i],
            state[28 + i],
        ]);
        round256::<true>(&mut r.0);
        for (k, v) in r.0.iter().enumerate() {
            state[4 * k + i] = *v;
        }
    }
    for ((s, x), w) in state.iter_mut().zip(xy.0.iter()).zip(next.as_chunks_mut::<4>().0) {
        *s = _mm256_xor_si256(*s, *x);
        store256(w, *s);
    }
}

/// AVX2 segment fill. Checks for AVX2 itself (the result is cached by `std`)
/// and falls back to SSSE3/SSE2, so it is safe to call on any x86 CPU.
pub(crate) fn fill_segment_avx2(memory: &mut Memory, seg: &Segment) {
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 support was just confirmed.
        unsafe { fill_segment_avx2_unchecked(memory, seg) }
    } else {
        fill_segment_ssse3(memory, seg)
    }
}

/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
unsafe fn fill_segment_avx2_unchecked(memory: &mut Memory, seg: &Segment) {
    let mut state = Vectors256([_mm256_setzero_si256(); W / 4]);
    walk_segment(memory, seg, |memory, prev, reference, curr, with_xor, first| {
        if first {
            load_state256(&mut state.0, memory.get(prev));
        }
        let (reference, next) = memory.read_write(reference, curr);
        fill_block256(&mut state.0, reference, next, with_xor);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::compress;

    #[test]
    fn vector_owners_wipe_on_return_and_unwind() {
        for panic in [false, true] {
            if panic && !cfg!(panic = "unwind") {
                eprintln!("skipping unwinding case: this build aborts on panic");
                continue;
            }
            let (result, events) = crate::wipe::observe(|| {
                // SAFETY: all-zero integer vectors are valid on every target CPU.
                let _small = Vectors128::<8>(unsafe { core::mem::zeroed() });
                // SAFETY: the value is stored and wiped without executing AVX2 instructions.
                let _large = Vectors256::<8>(unsafe { core::mem::zeroed() });
                assert!(!panic, "exercise SIMD cleanup during unwinding");
            });
            assert_eq!(result.is_err(), panic);
            assert_eq!(events, [(8, 32), (8, 16)]);
        }
    }

    fn pseudo_random_block(seed: u64) -> [u64; W] {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        core::array::from_fn(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        })
    }

    fn scalar_fill(
        prev: &[u64; W],
        reference: &[u64; W],
        next: &[u64; W],
        with_xor: bool,
    ) -> [u64; W] {
        let mut out = [0u64; W];
        compress(prev, reference, &mut out);
        if with_xor {
            for k in 0..W {
                out[k] ^= next[k];
            }
        }
        out
    }

    fn check_128(fill: unsafe fn(&[u64; W], &[u64; W], &mut [u64; W], bool)) {
        for seed in 0..2048u64 {
            let (prev, reference, next) = (
                pseudo_random_block(3 * seed),
                pseudo_random_block(3 * seed + 1),
                pseudo_random_block(3 * seed + 2),
            );
            for with_xor in [false, true] {
                let mut out = next;
                // SAFETY: callers pass only backends this CPU supports.
                unsafe { fill(&prev, &reference, &mut out, with_xor) };
                assert_eq!(
                    out,
                    scalar_fill(&prev, &reference, &next, with_xor),
                    "seed {seed} xor {with_xor}"
                );
            }
        }
    }

    // Compare one compression per call against scalar over many random
    // blocks, both with and without the version-0x13 XOR.
    #[test]
    fn sse2_block_matches_scalar() {
        if !std::is_x86_feature_detected!("sse2") {
            eprintln!("skipping: CPU lacks SSE2");
            return;
        }
        check_128(sse2::fill_one);
    }

    #[test]
    fn ssse3_block_matches_scalar() {
        if !std::is_x86_feature_detected!("ssse3") {
            eprintln!("skipping: CPU lacks SSSE3");
            return;
        }
        check_128(ssse3::fill_one);
    }

    #[test]
    fn avx2_block_matches_scalar() {
        if !std::is_x86_feature_detected!("avx2") {
            eprintln!("skipping: CPU lacks AVX2");
            return;
        }
        #[target_feature(enable = "avx2")]
        fn fill(prev: &[u64; W], reference: &[u64; W], out: &mut [u64; W], with_xor: bool) {
            let mut state = [_mm256_setzero_si256(); W / 4];
            load_state256(&mut state, prev);
            fill_block256(&mut state, reference, out, with_xor);
        }
        for seed in 0..2048u64 {
            let (prev, reference, next) = (
                pseudo_random_block(3 * seed),
                pseudo_random_block(3 * seed + 1),
                pseudo_random_block(3 * seed + 2),
            );
            for with_xor in [false, true] {
                let mut out = next;
                // SAFETY: AVX2 support was checked above.
                unsafe { fill(&prev, &reference, &mut out, with_xor) };
                assert_eq!(
                    out,
                    scalar_fill(&prev, &reference, &next, with_xor),
                    "seed {seed} xor {with_xor}"
                );
            }
        }
    }
}
