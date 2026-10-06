//! `argon2-verus`: a dependency-free Rust implementation of the
//! Argon2 password hashing function as specified in
//! ["Argon2: the memory-hard function for password hashing and other
//! applications"](https://www.cryptolux.org/index.php/Argon2) (v1.2.1,
//! the PHC winner submission) and RFC 9106.
//!
//! See `README.md` for the security rationale, verification status, and
//! test methodology (known-answer tests plus same-source Verus proofs of
//! scalar primitives, complete block G, and one BLAKE2b block transition).
//!
//! BLAKE2b and the Argon2 core are implemented locally. SIMD backends share
//! reference indexing, and selected scalar/indexing functions have same-source
//! Verus contracts. This is not an end-to-end correctness or timing proof.

#![deny(unsafe_code)]

mod blake2b;
mod blake2b_buffer;
mod blake2b_compress;
mod blake2b_tables;
mod blake2b_update;
mod block;
mod block_g;
mod block_g_column;
mod block_g_columns;
mod block_g_fill;
mod block_primitives;
mod core_impl;
mod core_primitives;
mod memory;
#[allow(unsafe_code)]
mod wipe;
// SIMD and volatile wiping are the only handwritten unsafe boundaries.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod simd;

pub use block::Block;
pub use core_impl::Backend;

/// The Argon2 variant, selecting the reference-block indexing strategy
/// (spec section 3, "type y of Argon2").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Algorithm {
    /// Data-dependent addressing. Faster, but vulnerable to side-channel
    /// (cache-timing) attacks; suitable for cryptocurrencies/backends only.
    Argon2d = 0,
    /// Data-independent addressing. Recommended for password hashing.
    Argon2i = 1,
    /// Hybrid: data-independent for the first half of the first pass,
    /// data-dependent afterwards. The generally recommended default.
    Argon2id = 2,
}

/// The Argon2 version byte (spec section 3.1).
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
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Degree of parallelism `p`, 1..=2^24-1.
    pub parallelism: u32,
    /// Memory size `m` in kibibytes, must be >= 8*p.
    pub memory_kib: u32,
    /// Number of passes over memory `t`, >= 1.
    pub iterations: u32,
}

impl Params {
    pub const RECOMMENDED: Params = Params { parallelism: 4, memory_kib: 19 * 1024, iterations: 2 };

    fn validate(&self, salt_len: usize, tag_len: usize) -> Result<(), Error> {
        if !core_primitives::valid_params(self.parallelism, self.memory_kib, self.iterations) {
            if self.parallelism == 0 || self.parallelism > (1 << 24) - 1 {
                return Err(Error::InvalidParallelism);
            }
            if self.memory_kib < 8 * self.parallelism {
                return Err(Error::MemoryTooSmall);
            }
            return Err(Error::InvalidIterations);
        }
        if salt_len > u32::MAX as usize || tag_len > u32::MAX as usize {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidParallelism,
    MemoryTooSmall,
    InvalidIterations,
    SaltTooShort,
    TagTooShort,
    InputTooLong,
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

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A configured Argon2 hasher with automatic or explicitly selected backend.
///
/// ```
/// use argon2_verus::{Algorithm, Argon2, Params, Version};
/// let params = Params { parallelism: 1, memory_kib: 8, iterations: 1 };
/// let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
/// let mut tag = [0u8; 32];
/// hasher.hash_password_into(b"password", b"saltsalt", &mut tag).unwrap();
/// ```
/// The small parameters above keep the example fast; select deployment costs
/// and generate a random salt for stored passwords.
pub struct Argon2 {
    algorithm: Algorithm,
    version: Version,
    params: Params,
    backend: Option<Backend>,
}

impl Default for Argon2 {
    fn default() -> Self {
        Self::new(Algorithm::Argon2id, Version::V0x13, Params::RECOMMENDED)
    }
}

impl Argon2 {
    pub fn new(algorithm: Algorithm, version: Version, params: Params) -> Self {
        Self { algorithm, version, params, backend: None }
    }

    /// Forces a specific compression backend instead of runtime detection.
    /// Every backend produces identical output; this exists for testing and
    /// benchmarking. An unavailable backend falls back to [`Backend::Scalar`].
    pub fn with_backend(mut self, backend: Backend) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Hashes `password` with `salt`, writing the resulting tag into `out`.
    /// `out.len()` determines the output tag length (must be >= 4 bytes).
    pub fn hash_password_into(
        &self,
        password: &[u8],
        salt: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        self.hash_password_into_with_secret(password, salt, &[], &[], out)
    }

    /// Like [`Self::hash_password_into`], with the optional `secret` (key)
    /// and `associated_data` primary/secondary inputs from spec section 3.1.
    pub fn hash_password_into_with_secret(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated_data: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        core_impl::hash_into_with_backend(
            self.backend.unwrap_or_else(Backend::detect),
            self.algorithm,
            self.version,
            &self.params,
            password,
            salt,
            secret,
            associated_data,
            out,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_salt_sensitive() {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params { parallelism: 1, memory_kib: 8, iterations: 1 },
        );
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        argon2.hash_password_into(b"password", b"saltsalt", &mut out1).unwrap();
        argon2.hash_password_into(b"password", b"saltsalt", &mut out2).unwrap();
        assert_eq!(out1, out2);

        let mut out3 = [0u8; 32];
        argon2.hash_password_into(b"password", b"different", &mut out3).unwrap();
        assert_ne!(out1, out3);
    }

    #[test]
    fn rejects_short_salt() {
        let argon2 = Argon2::default();
        let mut out = [0u8; 32];
        let err = argon2.hash_password_into(b"password", b"short", &mut out).unwrap_err();
        assert_eq!(err, Error::SaltTooShort);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn rejects_lengths_that_cannot_be_encoded_in_h0() {
        let too_long = u32::MAX as usize + 1;
        assert_eq!(Params::RECOMMENDED.validate(too_long, 32), Err(Error::InputTooLong));
        assert_eq!(Params::RECOMMENDED.validate(16, too_long), Err(Error::InputTooLong));
    }
}
