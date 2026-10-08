//! Core Argon2 algorithm: H0 derivation, memory filling, and finalization
//! (Argon2 spec sections 3.2 and 3.3).

use crate::blake2b::blake2b_long;
use crate::block::Block;
pub use crate::core_backend::Backend;
use crate::memory::Memory;
use crate::{Algorithm, Error, Params, Version};

const SYNC_POINTS: u32 = 4;

impl Backend {
    /// The fastest backend this CPU can execute.
    pub fn detect() -> Backend {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                return Backend::Avx2;
            }
            if std::is_x86_feature_detected!("ssse3") {
                return Backend::Ssse3;
            }
            if std::is_x86_feature_detected!("sse2") {
                return Backend::Sse2;
            }
        }
        #[allow(unreachable_code)]
        Backend::Scalar
    }

    /// Whether this CPU can execute `self`.
    pub fn is_available(self) -> bool {
        match self {
            Backend::Scalar => true,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Backend::Sse2 => std::is_x86_feature_detected!("sse2"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Backend::Ssse3 => std::is_x86_feature_detected!("ssse3"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Backend::Avx2 => std::is_x86_feature_detected!("avx2"),
        }
    }
}

// Internal entry point with automatic CPU backend selection.
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn hash_into(
    algorithm: Algorithm,
    version: Version,
    params: &Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    hash_into_with_backend(
        Backend::detect(),
        algorithm,
        version,
        params,
        password,
        salt,
        secret,
        ad,
        out,
    )
}

/// [`hash_into`] with an explicit backend. Falls back to [`Backend::Scalar`]
/// if `backend` is not available on this CPU, so this is safe to call with
/// any value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hash_into_with_backend(
    backend: Backend,
    algorithm: Algorithm,
    version: Version,
    params: &Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    if backend == Backend::Scalar {
        return crate::core_scalar_caller::scalar_backend(
            backend, algorithm, version, params, password, salt, secret, ad, out,
        );
    }
    let h0 = crate::initial_hash::checked_h0(
        algorithm,
        version,
        params,
        password,
        salt,
        secret,
        ad,
        out.len(),
    )?;
    let backend = if backend.is_available() { backend } else { Backend::Scalar };

    let lanes = params.parallelism;
    let (mut memory, memory_blocks, lane_length, segment_length) =
        Memory::zeroed_initialized(&h0, params, salt.len(), out.len())?;

    {
        for pass in 0..params.iterations {
            for slice in 0..SYNC_POINTS {
                for lane in 0..lanes {
                    let seg = Segment {
                        algorithm,
                        version,
                        lanes,
                        lane_length,
                        segment_length,
                        memory_blocks,
                        total_passes: params.iterations,
                        pass,
                        lane,
                        slice,
                    };
                    match backend {
                        Backend::Scalar => fill_segment_scalar(&mut memory, &seg),
                        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                        Backend::Sse2 => crate::simd::fill_segment_sse2(&mut memory, &seg),
                        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                        Backend::Ssse3 => crate::simd::fill_segment_ssse3(&mut memory, &seg),
                        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                        Backend::Avx2 => crate::simd::fill_segment_avx2(&mut memory, &seg),
                    }
                }
            }
        }
    }

    let tag = if backend == Backend::Scalar {
        crate::core_final::scalar_tag(&memory, lanes, lane_length, out.len())
    } else {
        let mut final_block = Block::zero();
        for lane in 0..lanes {
            final_block.xor_with_slice(memory.get((lane * lane_length + lane_length - 1) as usize));
        }
        blake2b_long(out.len(), &[&final_block.to_bytes()])
    };

    out.copy_from_slice(&tag);
    Ok(())
}

pub(crate) use crate::core_segment::{fill_segment_scalar, walk_segment, Segment};
