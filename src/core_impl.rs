//! Core Argon2 algorithm: H0 derivation, memory filling, and finalization
//! (Argon2 spec sections 3.2 and 3.3).

use crate::blake2b::blake2b_long;
use crate::block::{compress, Block};
use crate::memory::Memory;
use crate::{Algorithm, Error, Params, Version};

const SYNC_POINTS: u32 = 4;
const ADDRESSES_IN_BLOCK: usize = Block::SIZE_WORDS; // 128

/// Which implementation of the block-compression step `fill_segment` uses.
/// Every backend produces bit-identical output; only speed differs. The
/// indexing logic (reference-block selection) is shared in `walk_segment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    // Final block: XOR of the last column of every lane. `final_block` is a
    // fresh local (not a view into `memory`), so no clone of the source
    // blocks is needed.
    let mut final_block = Block::zero();
    for lane in 0..lanes {
        final_block.xor_with_slice(memory.get((lane * lane_length + lane_length - 1) as usize));
    }

    let tag = blake2b_long(out.len(), &[&final_block.to_bytes()]);
    out.copy_from_slice(&tag);
    Ok(())
}

/// Everything that identifies one segment (one lane x one slice of one pass).
#[derive(Clone, Copy)]
pub(crate) struct Segment {
    pub algorithm: Algorithm,
    pub version: Version,
    pub lanes: u32,
    pub lane_length: u32,
    pub segment_length: u32,
    pub memory_blocks: u32,
    pub total_passes: u32,
    pub pass: u32,
    pub lane: u32,
    pub slice: u32,
}

pub(crate) fn fill_segment_scalar(memory: &mut Memory, seg: &Segment) {
    walk_segment(memory, seg, |memory, prev, reference, curr, with_xor, _first| {
        let (others, next) = memory.split_around(curr);
        crate::block::fill_block(others.get(prev), others.get(reference), next, with_xor);
    });
}

/// The segment loop of spec section 3.3: for every block in the segment,
/// derives `(prev, ref, curr)` block indices and hands them to `fill`, which
/// must write `G(memory[prev], memory[ref])` (XORed with the old
/// `memory[curr]` when `with_xor`) into `memory[curr]`.
///
/// This is the only implementation of the reference-block selection; every
/// backend shares it, so SIMD work cannot change which blocks are read.
/// `first` is true for the first block the segment computes, so a backend
/// that carries the previous block in registers knows when to load it.
/// `prev` is always the block written by the preceding `fill` call except
/// when `first` is true.
#[inline(always)]
pub(crate) fn walk_segment<F>(memory: &mut Memory, seg: &Segment, mut fill: F)
where
    F: FnMut(&mut Memory, usize, usize, usize, bool, bool),
{
    let Segment {
        algorithm,
        version,
        lanes,
        lane_length,
        segment_length,
        memory_blocks,
        total_passes,
        pass,
        lane,
        slice,
    } = *seg;
    let with_xor = crate::core_primitives::xor_on_pass(version as u32, pass);
    let data_independent =
        crate::core_primitives::uses_independent_addresses(algorithm as u32, pass, slice);

    let starting_index: u32 = if pass == 0 && slice == 0 { 2 } else { 0 };

    // Address-generation state for data-independent addressing.
    let mut input_block = Block::zero();
    let mut address_block = Block::zero();
    if data_independent {
        input_block.0[0] = pass as u64;
        input_block.0[1] = lane as u64;
        input_block.0[2] = slice as u64;
        input_block.0[3] = memory_blocks as u64;
        input_block.0[4] = total_passes as u64;
        input_block.0[5] = algorithm as u64;
        input_block.0[6] = 0;
        if starting_index == 2 {
            next_addresses(&mut input_block, &mut address_block);
        }
    }

    for i in starting_index..segment_length {
        let curr_index = slice * segment_length + i;
        let prev_index = crate::core_primitives::previous_index(curr_index, lane_length);
        let curr_pos = (lane * lane_length + curr_index) as usize;
        let prev_pos = (lane * lane_length + prev_index) as usize;

        let pseudo_rand: u64 = if data_independent {
            if (i as usize) % ADDRESSES_IN_BLOCK == 0 {
                next_addresses(&mut input_block, &mut address_block);
            }
            address_block.0[(i as usize) % ADDRESSES_IN_BLOCK]
        } else {
            memory.get(prev_pos)[0]
        };

        let mut ref_lane = ((pseudo_rand >> 32) as u32) % lanes;
        if pass == 0 && slice == 0 {
            ref_lane = lane;
        }
        let same_lane = ref_lane == lane;

        let ref_index =
            index_alpha(pass, slice, segment_length, lane_length, i, pseudo_rand as u32, same_lane);

        let ref_pos = (ref_lane * lane_length + ref_index) as usize;

        // `curr` differs from both `prev` and `ref` by the indexing rules, so
        // `fill` may read those two and write `curr`.
        debug_assert!(ref_pos != curr_pos && prev_pos != curr_pos);
        fill(memory, prev_pos, ref_pos, curr_pos, with_xor, i == starting_index);
    }
}

/// Regenerates the address block used for data-independent addressing:
/// `address_block <- G(zero, G(zero, input_block))`, incrementing the
/// segment-local counter first (spec section 3.3, "Getting two 32-bit
/// values").
fn next_addresses(input_block: &mut Block, address_block: &mut Block) -> u64 {
    input_block.0[6] += 1;
    let zero = Block::zero();
    let mut tmp = Block::zero();
    compress(&zero.0, &input_block.0, &mut tmp.0);
    compress(&zero.0, &tmp.0, &mut address_block.0);
    0
}

/// Maps `(J1, J2)` (folded into `pseudo_rand`) to a reference block index
/// within the lane (spec section 3.3, "Mapping J1, J2 to the reference
/// block index"), following the reference algorithm's `index_alpha`.
#[allow(clippy::too_many_arguments)]
fn index_alpha(
    pass: u32,
    slice: u32,
    segment_length: u32,
    lane_length: u32,
    index: u32,
    j1: u32,
    same_lane: bool,
) -> u32 {
    debug_assert_eq!(lane_length, 4 * segment_length);
    crate::core_primitives::index_alpha(pass, slice, segment_length, index, j1, same_lane)
}
