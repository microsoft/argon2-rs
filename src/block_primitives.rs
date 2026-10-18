//! Scalar block primitives used by Argon2's 16-word permutation: BlaMka,
//! rotation, GB, and permutation P.
//!
//! These are the canonical executable bodies used by both ordinary Rust
//! builds and Verus. Verus checks these leaves under their contracts; it does
//! compose with the full scalar G/caller proof; SIMD kernels remain outside it.

#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[inline(always)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result == specs::blamka(x, y),
))]
pub fn blamka(x: u64, y: u64) -> u64 {
    let xl = x % 0x1_0000_0000;
    let yl = y % 0x1_0000_0000;
    x.wrapping_add(y).wrapping_add(2u64.wrapping_mul(xl).wrapping_mul(yl))
}

#[inline(always)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires 1 <= n <= 63,
    ensures result == specs::rotate(x, n),
))]
pub fn rotr64(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

#[inline(always)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result == specs::gb(a, b, c, d),
))]
pub fn gb(a: u64, b: u64, c: u64, d: u64) -> (u64, u64, u64, u64) {
    let a = blamka(a, b);
    let d = rotr64(d ^ a, 32);
    let c = blamka(c, d);
    let b = rotr64(b ^ c, 24);
    let a = blamka(a, b);
    let d = rotr64(d ^ a, 16);
    let c = blamka(c, d);
    let b = rotr64(b ^ c, 63);
    (a, b, c, d)
}

#[inline(always)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == specs::permute(v@),
))]
pub fn permute(v: &[u64; 16]) -> [u64; 16] {
    let (v0, v4, v8, v12) = gb(v[0], v[4], v[8], v[12]);
    let (v1, v5, v9, v13) = gb(v[1], v[5], v[9], v[13]);
    let (v2, v6, v10, v14) = gb(v[2], v[6], v[10], v[14]);
    let (v3, v7, v11, v15) = gb(v[3], v[7], v[11], v[15]);
    let (v0, v5, v10, v15) = gb(v0, v5, v10, v15);
    let (v1, v6, v11, v12) = gb(v1, v6, v11, v12);
    let (v2, v7, v8, v13) = gb(v2, v7, v8, v13);
    let (v3, v4, v9, v14) = gb(v3, v4, v9, v14);
    [v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15]
}
