# Changelog

## 0.1.0 - Unreleased

- Reference-compatible Argon2d, Argon2i and Argon2id, versions 0x10 and 0x13.
- Local BLAKE2b and variable-length hash implementation; no production crates.
- Runtime SSE2, SSSE3 and AVX2 dispatch with a portable scalar path.
- Same-source Verus contracts for scalar and indexing/geometry leaves.
- Same-source Verus proofs for complete scalar block G and one BLAKE2b
	compression-block state transition, plus buffer append/flush/update-step and
	finalization helpers; full Argon2 remains outside the proof scope.
- Proved positive streaming update-step progress and byte-count conservation;
	proved the production offset-update loop against a finite model-step trace
	using opaque transitions and pointwise edge lemmas. Removed diagnostic repro
	files.
- Proved production streaming continuation against a block-oriented digest model,
	binary partition composition/independence, and unkeyed BLAKE2b initialization.
	H-prime and hash composition remain unproved.
- Proved real public BLAKE2b methods and arbitrary finite multipart/prefixed
	composition through ghost-only closed state views, preserving private fields
	and production cleanup. Isolated an unresolved H-prime singleton-loop VC
	outside production and supported gates.
- RFC 9106 known-answer, backend-agreement, boundary and resource tests.
- Streamed initial hashing and volatile wiping of owned arena/BLAKE2b storage.