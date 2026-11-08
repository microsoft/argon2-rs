# Changelog

## 0.1.0 - Unreleased

### Hashing API

- Argon2d, Argon2i and Argon2id, versions `0x10` and `0x13`, with raw output
  tags and optional secret/associated-data inputs.
- Local BLAKE2b and H-prime implementations; no runtime or development crates.
- Runtime SSE2, SSSE3 and AVX2 dispatch, with a portable scalar path.
- Rust 1.88 minimum; standard library required. Lanes run sequentially.
- Parameter/length validation and checked working-memory sizing. Applications
  remain responsible for resource budgets, random salts, stored hash encoding
  and constant-time tag comparison.

### Formal assurance

- Same-source Verus proof of the complete forced-scalar successful-return path:
  parameter checks, H0, initialization, compression, addressing, traversal,
  final reduction, H-prime and output copy.
- Successful return implies equality with the whole-hash model, including
  legacy version behavior. RFC/model fidelity remains an independent review
  obligation; RFC 9106 specifies version `0x13`.
- Consolidated, pinned Cargo-Verus package with 209 verified obligations,
  explicit scalar-loop termination measures, RFC traceability, and separation
  of canonical semantics from internal proof helpers.
- Simplified proof-only code without changing runtime behavior or public
  specifications. The runtime package has no Verus dependency.
- SIMD, automatic dispatch, public wrappers/FFI, allocator implementation,
  zeroization, timing and cryptographic strength remain outside the theorem.

### Secret lifetime and validation

- In-place BLAKE2b updates and volatile drop-time wiping of owned working
  memory, explicit scalar/SIMD scratch, H0 and internal tags, including panic
  unwinding. Compiler copies, registers, caller-owned buffers and abort cleanup
  remain outside the erasure guarantee.
- RFC 9106 known-answer tests, independent pinned-reference vectors for both
  versions and output-length boundaries, backend agreement, streaming,
  parameter, resource and cleanup regression tests.
- CI for Linux, Windows, macOS, the minimum Rust version, ARM64 compilation,
  package contents, reference-vector regeneration and formal verification.
- Dependency-audit enforcement with cargo-vet; no first-party security
  certification is implied by the empty runtime dependency graph.
