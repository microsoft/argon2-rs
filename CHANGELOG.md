# Changelog

## 0.1.0 - Unreleased

- Reference-compatible Argon2d, Argon2i and Argon2id, versions 0x10 and 0x13.
- Local BLAKE2b and variable-length hash implementation; no production crates.
- Runtime SSE2, SSSE3 and AVX2 dispatch with a portable scalar path.
- Same-source Verus contracts for scalar and indexing/geometry leaves.
- Same-source Verus proofs for complete scalar block G and one BLAKE2b
	compression-block state transition, plus buffer append/flush/update-step and
	finalization helpers; the repeated streaming loop and full Argon2 remain
	outside the proof scope.
- RFC 9106 known-answer, backend-agreement, boundary and resource tests.
- Streamed initial hashing and volatile wiping of owned arena/BLAKE2b storage.