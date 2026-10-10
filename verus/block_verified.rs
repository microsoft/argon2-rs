//! Verifies the canonical ordinary Rust scalar core directly from
//! `../src/block_primitives.rs`, using its ghost-only contracts and the
//! mathematical definitions in `spec.rs`. No executable copy is generated.
//!
//! The proof covers BlaMka, rotation for 1 <= n <= 63, GB, and permutation P.
//! It does not establish collision resistance or verify SIMD, BLAKE2b, or
//! fill_segment indexing.

use vstd::prelude::*;

#[path = "../specs/mod.rs"]
mod specs;
#[path = "../src/block_primitives.rs"]
mod block_primitives;
