//! Owned working-memory arena and safe access to its Argon2 blocks.
//!
//! The arena is zero-initialized so every safe slice contains initialized
//! values, then volatile-zeroed on normal drop. This does not erase copies in
//! registers, caller storage, or stack temporaries, and drop does not run after
//! process abort or termination.

use crate::block::Block;
#[cfg(verus_keep_ghost)]
use crate::memory_initialization_model as model;
use crate::Error;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Owns the flat working-memory words (`memory_blocks * 128` `u64`s).
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) struct Memory(Vec<u64>);

#[cfg(verus_keep_ghost)]
verus! {
impl Memory {
    pub closed spec fn words(&self) -> Seq<u64> { self.0@ }
}
}

#[cfg_attr(verus_keep_ghost, cfg_eval)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Memory {
    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        ensures result matches Ok(memory) ==> (
            memory.words().len() == blocks as int * 128
            && forall|index: int| 0 <= index < memory.words().len() ==>
                memory.words()[index] == 0
        ),
    ))]
    pub(crate) fn zeroed(blocks: usize) -> Result<Self, Error> {
        let words = blocks.checked_mul(Block::SIZE_WORDS).ok_or(Error::MemoryAllocationFailed)?;
        let mut memory = Vec::new();
        memory.try_reserve_exact(words).map_err(|_| Error::MemoryAllocationFailed)?;
        memory.resize(words, 0);
        Ok(Memory(memory))
    }
}

#[cfg_attr(verus_keep_ghost, cfg_eval)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Memory {
    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        requires crate::specs::valid_params(lanes, memory_kib, 1),
            memory_kib as usize as u32 == memory_kib,
        ensures result matches Ok((memory, blocks, lane_length, segment_length)) ==> (
            blocks as int == crate::specs::memory_blocks(memory_kib, lanes)
            && lane_length as int == blocks as int / lanes as int
            && segment_length as int == lane_length as int / 4
            && memory.words() == model::initialized_prefix(
                Seq::new(blocks as nat * 128, |_index: int| 0u64),
                h0@, lane_length as nat, 2 * lanes as nat,
            )
        ),
    ))]
    pub(crate) fn zeroed_initialized(
        h0: &[u8; 64],
        memory_kib: u32,
        lanes: u32,
    ) -> Result<(Self, u32, u32, u32), Error> {
        let (blocks, lane_length, segment_length) =
            crate::core_primitives::memory_geometry(memory_kib, lanes);
        let mut memory = Memory::zeroed(blocks as usize)?;
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(memory.words() =~= Seq::new(
                blocks as nat * 128, |_index: int| 0u64,
            )) by {
                assert(memory.words().len() == blocks as int * 128);
                assert forall|index: int| 0 <= index < memory.words().len()
                    implies memory.words()[index] == Seq::new(
                        blocks as nat * 128, |_index: int| 0u64,
                    )[index] by {}
            }
        }
        memory.initialize(h0, lanes, lane_length);
        Ok((memory, blocks, lane_length, segment_length))
    }
}

#[cfg_attr(verus_keep_ghost, cfg_eval)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Memory {
    /// Initialize the first two blocks of every lane.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires lanes > 0, lane_length >= 2,
            lanes as int * lane_length as int <= u32::MAX as int,
            lanes as int * lane_length as int * 128 == old(self).words().len(),
        ensures final(self).words() == model::initialized_prefix(
            old(self).words(), h0@, lane_length as nat, 2 * lanes as nat),
    ))]
    pub(crate) fn initialize(&mut self, h0: &[u8; 64], lanes: u32, lane_length: u32) {
        crate::memory_initialization::initialize_words(&mut self.0, h0, lanes, lane_length);
    }
}

impl Memory {
    /// Block `i` of the flat working memory.
    #[inline(always)]
    pub(crate) fn get(&self, i: usize) -> &[u64; Block::SIZE_WORDS] {
        (&self.0[i * Block::SIZE_WORDS..(i + 1) * Block::SIZE_WORDS]).try_into().unwrap()
    }

    /// Block `r` for reading and block `c` for writing, at the same time.
    /// Panics if `r == c`; the indexing rules guarantee they differ.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline(always)]
    pub(crate) fn read_write(
        &mut self,
        r: usize,
        c: usize,
    ) -> (&[u64; Block::SIZE_WORDS], &mut [u64; Block::SIZE_WORDS]) {
        const W: usize = Block::SIZE_WORDS;
        assert_ne!(r, c);
        if r < c {
            let (lo, hi) = self.0.split_at_mut(c * W);
            ((&lo[r * W..(r + 1) * W]).try_into().unwrap(), (&mut hi[..W]).try_into().unwrap())
        } else {
            let (lo, hi) = self.0.split_at_mut(r * W);
            ((&hi[..W]).try_into().unwrap(), (&mut lo[c * W..(c + 1) * W]).try_into().unwrap())
        }
    }

    /// Block `c` for writing, plus read access to every other block.
    #[inline(always)]
    pub(crate) fn split_around(&mut self, c: usize) -> (Others<'_>, &mut [u64; Block::SIZE_WORDS]) {
        const W: usize = Block::SIZE_WORDS;
        let (lo, rest) = self.0.split_at_mut(c * W);
        let (curr, hi) = rest.split_at_mut(W);
        (Others { lo, hi, c }, curr.try_into().unwrap())
    }
}

/// Read access to every block except the one [`Memory::split_around`] lent
/// out for writing. Asking for that block panics.
pub(crate) struct Others<'a> {
    lo: &'a [u64],
    hi: &'a [u64],
    c: usize,
}

impl<'a> Others<'a> {
    #[inline(always)]
    pub(crate) fn get(&self, i: usize) -> &'a [u64; Block::SIZE_WORDS] {
        const W: usize = Block::SIZE_WORDS;
        let words = if i < self.c {
            &self.lo[i * W..(i + 1) * W]
        } else {
            &self.hi[(i - self.c - 1) * W..(i - self.c) * W]
        };
        words.try_into().unwrap()
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        crate::wipe::words(&mut self.0);
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;

    #[test]
    fn owned_initialize_matches_geometry_and_preserves_other_blocks() {
        let h0 = [0x5au8; 64];
        for lanes in 1..=4u32 {
            let (blocks, lane_length, _) =
                crate::core_primitives::memory_geometry(8 * lanes + 1, lanes);
            assert_eq!(blocks, lanes * lane_length);
            let mut arena = Memory::zeroed(blocks as usize).unwrap();
            assert_eq!(arena.0.len(), blocks as usize * 128);
            arena.initialize(&h0, lanes, lane_length);
            for lane in 0..lanes {
                for column in 0..lane_length {
                    let actual = arena.get((lane * lane_length + column) as usize);
                    if column < 2 {
                        assert_eq!(actual, &crate::memory_initialization::block(&h0, column, lane));
                    } else {
                        assert_eq!(actual, &[0u64; 128]);
                    }
                }
            }
        }
    }

    #[test]
    fn unrepresentable_arena_is_rejected_before_allocation() {
        assert!(matches!(Memory::zeroed(usize::MAX), Err(Error::MemoryAllocationFailed)));
        assert!(matches!(
            Memory::zeroed(usize::MAX / Block::SIZE_WORDS),
            Err(Error::MemoryAllocationFailed)
        ));
    }
}
