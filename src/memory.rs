//! Owned working-memory arena and safe access to its Argon2 blocks.
//!
//! The arena is zero-initialized so every safe slice contains initialized
//! values, then volatile-zeroed on normal drop. This does not erase copies in
//! registers, caller storage, or stack temporaries, and drop does not run after
//! process abort or termination.

use crate::block::Block;
use crate::Error;

/// Owns the flat working-memory words (`memory_blocks * 128` `u64`s).
pub(crate) struct Memory(Vec<u64>);

impl Memory {
    pub(crate) fn zeroed(blocks: usize) -> Result<Self, Error> {
        let words = blocks.checked_mul(Block::SIZE_WORDS).ok_or(Error::MemoryAllocationFailed)?;
        let mut memory = Vec::new();
        memory.try_reserve_exact(words).map_err(|_| Error::MemoryAllocationFailed)?;
        memory.resize(words, 0);
        Ok(Memory(memory))
    }

    /// Block `i` of the flat working memory.
    #[inline(always)]
    pub(crate) fn get(&self, i: usize) -> &[u64; Block::SIZE_WORDS] {
        (&self.0[i * Block::SIZE_WORDS..(i + 1) * Block::SIZE_WORDS]).try_into().unwrap()
    }

    #[inline(always)]
    pub(crate) fn slot(&mut self, i: usize) -> &mut [u64; Block::SIZE_WORDS] {
        (&mut self.0[i * Block::SIZE_WORDS..(i + 1) * Block::SIZE_WORDS]).try_into().unwrap()
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
    fn unrepresentable_arena_is_rejected_before_allocation() {
        assert!(matches!(Memory::zeroed(usize::MAX), Err(Error::MemoryAllocationFailed)));
        assert!(matches!(
            Memory::zeroed(usize::MAX / Block::SIZE_WORDS),
            Err(Error::MemoryAllocationFailed)
        ));
    }
}
