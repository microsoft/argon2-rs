//! Compression backend selector shared by the core and scalar proof boundary.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A scalar or CPU-specific implementation of Argon2 block compression.
///
/// Backend variants are available only on architectures that support them.
/// This public type supports reproducible backend selection and controlled
/// benchmarks. Requests for an unavailable variant fall back to
/// [`Backend::Scalar`]. New variants may be added as additional kernels ship.
#[non_exhaustive]
pub enum Backend {
    /// Portable Rust; the code path the Verus proof models.
    Scalar,
    /// x86 SSE2 (baseline on every x86-64 CPU).
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Sse2,
    /// x86 SSSE3, for CPUs that have it but lack AVX2.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Ssse3,
    /// x86 AVX2, selected at runtime when the CPU supports it.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Avx2,
}
