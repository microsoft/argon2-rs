use crate::core_primitives;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The Argon2 variant, selecting the reference-block indexing strategy
/// (spec section 3, "type y of Argon2").
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Algorithm {
    /// Data-dependent addressing. Faster, but vulnerable to side-channel
    /// (cache-timing) attacks. Do not select it for new password storage;
    /// use only where data-dependent addressing fits the threat model.
    Argon2d = 0,
    /// Data-independent addressing. Use when required by an existing protocol
    /// or threat model; prefer Argon2id for new password storage.
    Argon2i = 1,
    /// Hybrid: data-independent for the first half of the first pass,
    /// data-dependent afterwards. The generally recommended default.
    Argon2id = 2,
}

/// The Argon2 version byte (spec section 3.1).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Version {
    /// Original PHC submission version. Kept only for compatibility with
    /// legacy hashes; do not use for new hashes.
    V0x10 = 0x10,
    /// Current version: passes after the first XOR the newly computed
    /// block with the block's old contents, closing a tradeoff-attack gap
    /// present in V0x10. Use this for all new hashes.
    V0x13 = 0x13,
}

/// Tunable Argon2 parameters (spec section 3.1, "Secondary inputs").
///
/// Valid values require `parallelism` in `1..=2^24-1`, `memory_kib >= 8 *
/// parallelism`, and `iterations >= 1`. Effective memory is rounded down to a
/// multiple of `4 * parallelism` blocks.
/// These are algorithm bounds, not safe application budgets. Cap memory,
/// passes and concurrent requests before accepting untrusted configurations.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Degree of parallelism `p`, in `1..=2^24-1` lanes.
    /// Lanes are processed sequentially; this does not create worker threads.
    pub parallelism: u32,
    /// Requested memory size `m` in KiB, at least `8 * parallelism`.
    pub memory_kib: u32,
    /// Number of passes over memory `t`, at least 1.
    pub iterations: u32,
}

#[cfg_attr(verus_keep_ghost, cfg_eval)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Params {
    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        ensures result.is_ok() == (
            specs::valid_params(self.parallelism, self.memory_kib, self.iterations)
            && 8 <= salt_len <= u32::MAX as usize
            && 4 <= tag_len <= u32::MAX as usize
            && tag_len <= isize::MAX as usize),
    ))]
    pub(crate) fn validate(&self, salt_len: usize, tag_len: usize) -> Result<(), Error> {
        if !core_primitives::valid_params(self.parallelism, self.memory_kib, self.iterations) {
            if self.parallelism == 0 || self.parallelism > 0x00ff_ffff {
                return Err(Error::InvalidParallelism);
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                assert(8 * self.parallelism as int <= u32::MAX as int);
            }
            if self.memory_kib < 8 * self.parallelism {
                return Err(Error::MemoryTooSmall);
            }
            return Err(Error::InvalidIterations);
        }
        if salt_len > u32::MAX as usize || tag_len > u32::MAX as usize {
            return Err(Error::InputTooLong);
        }
        if tag_len > isize::MAX as usize {
            return Err(Error::InputTooLong);
        }
        if salt_len < 8 {
            return Err(Error::SaltTooShort);
        }
        if tag_len < 4 {
            return Err(Error::TagTooShort);
        }
        Ok(())
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// An error returned when parameters, input lengths, or allocation are invalid.
pub enum Error {
    /// Parallelism is zero or greater than `2^24 - 1`.
    InvalidParallelism,
    /// Requested memory is less than 8 KiB per lane.
    MemoryTooSmall,
    /// The number of passes is zero.
    InvalidIterations,
    /// The salt contains fewer than 8 bytes.
    SaltTooShort,
    /// The output tag buffer contains fewer than 4 bytes.
    TagTooShort,
    /// An input or output length cannot be represented by the algorithm's
    /// length fields or by the platform's allocation size type.
    InputTooLong,
    /// The working-memory size is unrepresentable or fallible allocation
    /// returned an error. This does not guarantee recovery from every OOM.
    MemoryAllocationFailed,
}

impl ::core::fmt::Display for Error {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        let msg = match self {
            Error::InvalidParallelism => "parallelism must be in 1..=2^24-1",
            Error::MemoryTooSmall => "memory_kib must be >= 8 * parallelism",
            Error::InvalidIterations => "iterations must be >= 1",
            Error::SaltTooShort => "salt must be >= 8 bytes",
            Error::TagTooShort => "output tag must be >= 4 bytes",
            Error::InputTooLong => "input and output lengths must fit in u32",
            Error::MemoryAllocationFailed => "working-memory allocation failed",
        };
        f.write_str(msg)
    }
}

impl ::std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_preserves_error_priority() {
        for (params, expected) in [
            (Params { parallelism: 0, memory_kib: 0, iterations: 0 }, Error::InvalidParallelism),
            (
                Params { parallelism: 1 << 24, memory_kib: u32::MAX, iterations: 0 },
                Error::InvalidParallelism,
            ),
            (Params { parallelism: 2, memory_kib: 15, iterations: 0 }, Error::MemoryTooSmall),
            (Params { parallelism: 1, memory_kib: 8, iterations: 0 }, Error::InvalidIterations),
        ] {
            assert_eq!(params.validate(0, 0), Err(expected));
        }
        let params = Params { parallelism: 1, memory_kib: 8, iterations: 1 };
        assert_eq!(params.validate(7, 3), Err(Error::SaltTooShort));
        assert_eq!(params.validate(8, 3), Err(Error::TagTooShort));
        assert_eq!(params.validate(8, 4), Ok(()));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(params.validate(u32::MAX as usize + 1, 0), Err(Error::InputTooLong));
    }
}
