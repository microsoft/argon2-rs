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

pub open spec fn block_words(words: Seq<u64>, block: int) -> Seq<u64> {
    words.subrange(block * 128, (block + 1) * 128)
}

pub open spec fn write_block(words: Seq<u64>, block: int, replacement: Seq<u64>) -> Seq<u64> {
    write_block_prefix(words, block, replacement, 128)
}

pub open spec fn write_block_prefix(
    words: Seq<u64>, block: int, replacement: Seq<u64>, completed: int,
) -> Seq<u64> {
    Seq::new(words.len() as nat, |index: int|
        if block * 128 <= index < block * 128 + completed {
            replacement[index - block * 128]
        } else { words[index] })
}

#[verifier::opaque]
pub open spec fn fill_result(
    words: Seq<u64>, previous: int, reference: int, current: int, with_xor: bool,
) -> Seq<u64> {
    write_block(words, current, crate::specs::fill_block_result(
        block_words(words, previous), block_words(words, reference),
        block_words(words, current), with_xor))
}
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires (block as int + 1) * 128 <= words@.len(),
    ensures result@ == block_words(words@, block as int),
))]
fn read_owned_block(words: &Vec<u64>, block: usize) -> [u64; 128] {
    let _word_count = words.len();
    let base = block * 128;
    let mut result = [0u64; 128];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|index: int| 0 <= index < 128 ==>
                result@[index] == if index < offset as int {
                    words@[base as int + index]
                } else { 0u64 },
    ))]
    for offset in 0..128 {
        result[offset] = words[base + offset];
    }
    #[cfg(verus_keep_ghost)]
    proof! { assert(result@ =~= block_words(words@, block as int)); }
    result
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires (block as int + 1) * 128 <= old(words)@.len(),
    ensures final(words)@ == write_block(old(words)@, block as int, replacement@),
))]
fn write_owned_block(words: &mut Vec<u64>, block: usize, replacement: &[u64; 128]) {
    let _word_count = words.len();
    let base = block * 128;
    #[cfg(verus_keep_ghost)]
    proof_decl! { let ghost before = words@; }
    #[cfg(verus_keep_ghost)]
    proof! { assert(words@ =~= write_block_prefix(before, block as int, replacement@, 0)); }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant words@ == write_block_prefix(before, block as int, replacement@, offset as int),
    ))]
    for offset in 0..128 {
        words[base + offset] = replacement[offset];
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(words@ =~= write_block_prefix(before, block as int, replacement@, offset as int + 1));
        }
    }
}

#[cfg_attr(verus_keep_ghost, cfg_eval)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Memory {
    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        requires (block as int + 1) * 128 <= self.words().len(),
        ensures result@ == block_words(self.words(), block as int),
    ))]
    pub(crate) fn block_copy(&self, block: usize) -> [u64; 128] {
        read_owned_block(&self.0, block)
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        ensures result as int == self.words().len(),
    ))]
    pub(crate) fn word_count(&self) -> usize {
        self.0.len()
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        requires (block as int + 1) * 128 <= self.words().len(),
        ensures result == self.words()[block as int * 128],
    ))]
    pub(crate) fn first_word(&self, block: usize) -> u64 {
        let _word_count = self.0.len();
        self.0[block * 128]
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires (previous as int + 1) * 128 <= old(self).words().len(),
            (reference as int + 1) * 128 <= old(self).words().len(),
            (current as int + 1) * 128 <= old(self).words().len(),
        ensures final(self).words() == fill_result(old(self).words(), previous as int,
            reference as int, current as int, with_xor),
            final(self).words().len() == old(self).words().len(),
    ))]
    pub(crate) fn fill_current(
        &mut self,
        previous: usize,
        reference: usize,
        current: usize,
        with_xor: bool,
    ) {
        let prev = read_owned_block(&self.0, previous);
        let reference = read_owned_block(&self.0, reference);
        let mut next = read_owned_block(&self.0, current);
        crate::block_g_fill::fill_block(&prev, &reference, &mut next, with_xor);
        write_owned_block(&mut self.0, current, &next);
        #[cfg(verus_keep_ghost)]
        proof! { reveal(fill_result); }
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
        ensures result matches Ok((memory, blocks, lane_length, segment_length)) ==> (
            blocks as int == crate::specs::memory_blocks(params.memory_kib, params.parallelism)
            && lane_length as int == blocks as int / params.parallelism as int
            && segment_length as int == lane_length as int / 4
            && memory.words() == model::initialized_prefix(
                Seq::new(blocks as nat * 128, |_index: int| 0u64),
                h0@, lane_length as nat, 2 * params.parallelism as nat,
            )
        ),
    ))]
    pub(crate) fn zeroed_initialized(
        h0: &[u8; 64],
        params: &crate::Params,
        salt_len: usize,
        tag_len: usize,
    ) -> Result<(Self, u32, u32, u32), Error> {
        params.validate(salt_len, tag_len)?;
        if params.memory_kib as usize as u32 != params.memory_kib {
            return Err(Error::MemoryAllocationFailed);
        }
        let lanes = params.parallelism;
        let (blocks, lane_length, segment_length) =
            crate::core_primitives::memory_geometry(params.memory_kib, lanes);
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
    #[cfg(test)]
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
#[cfg(test)]
pub(crate) struct Others<'a> {
    lo: &'a [u64],
    hi: &'a [u64],
    c: usize,
}

#[cfg(test)]
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
    fn scalar_fill_preserves_other_blocks() {
        for with_xor in [false, true] {
            for (previous, reference, current) in [(0, 1, 2), (2, 0, 1), (1, 1, 0)] {
                let words: Vec<u64> = (0..4 * 128)
                    .map(|index| (index as u64).wrapping_mul(0x9e3779b97f4a7c15))
                    .collect();
                let mut memory = Memory(words.clone());
                let mut reference_memory = Memory(words.clone());
                let (others, next) = reference_memory.split_around(current);
                crate::block_g_fill::fill_block(
                    others.get(previous),
                    others.get(reference),
                    next,
                    with_xor,
                );
                memory.fill_current(previous, reference, current, with_xor);
                assert_eq!(memory.0, reference_memory.0);
                assert_eq!(&memory.0[..current * 128], &words[..current * 128]);
                assert_eq!(&memory.0[(current + 1) * 128..], &words[(current + 1) * 128..]);
            }
        }
    }

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
