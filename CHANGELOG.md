# Changelog

## 0.1.0 - Unreleased

- Simplified proof-only code: removed unused helpers/imports and redundant
  assertions/reveals, factored completed-update lemma contracts, and shared
  multipart/trace-extension proofs. Executable code, executable contracts,
  loop specifications and canonical RFC definitions are unchanged.
- Consolidated same-source proofs into a pinned upstream Cargo-Verus package
  and CI gate; vstd includes merged upstream PR #3094. Removed scalar-loop
  termination opt-outs, separated canonical RFC semantics from proof-only
  relations, added RFC traceability and checked notation/full-pass equivalences.
- Removed by-value BLAKE2b streaming state/buffer copies and added volatile
  drop-time wiping for explicit scalar/SIMD scratch, H0, initialization,
  finalization and internal tag owners, including panic unwinding. Compiler
  copies, registers, caller-owned inputs/output and abort remain outside the
  erasure guarantee. Updated same-source functional contracts and cleanup tests.
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
	Hash composition remains unproved.
- Proved real public BLAKE2b methods and arbitrary finite multipart/prefixed
	composition through ghost-only closed state views, preserving private fields
	and production cleanup.
- Proved both H-prime branches against an RFC ceil-based digest-chain model,
	including little-endian length encoding, exact output length and loop termination.
	Added independent hashlib boundary vectors; allocation failure recovery,
	zeroization and returned Argon2-tag composition remain outside the proof.
- Agreed first returned-tag target: forced scalar, version 0x13, all three
	algorithms and accepted/representable successful inputs, excluding legacy/SIMD.
- Proved the production H0 raw-field header/input serialization and BLAKE2b
	composition; preserved original requested memory and added independent H0 vectors.
	Arena initialization, full hash callers and traversal remain unproved.
- Proved canonical parameter validation and enum/Params checked-H0 adaptation;
	preserved public re-exports/defaults and wired the hash entry through this boundary.
	Added error-priority and adapter-mapping regressions; full tag theorem is incomplete.
- RFC 9106 known-answer, backend-agreement, boundary and resource tests.
- Streamed initial hashing and volatile wiping of owned arena/BLAKE2b storage.
- Proved lane seed/H-prime(1024)/little-endian block generation and real nested
	flat-arena initialization with in-bounds writes and untouched-word preservation.
	Wired the owning arena to the helper without changing allocation/Drop policy;
	owning wrapper/caller and full traversal/tag proofs remain incomplete.
- Proved the successful `Memory::zeroed` result shape (exact word length and
	zero contents) using the vstd `try_reserve_exact` content-preservation
	specification (initially proposed locally; now upstream in merged PR #3094).
	The allocator implementation and guaranteed
	allocation success remain unproved; custom-allocator review and full caller/tag
	composition are still pending. Allocation/Drop policy is unchanged.
- Proved actual owning initialization through a closed ghost word view and exact
	geometry identity; caller/traversal composition remains incomplete.
- Proved a same-source memory-construction helper that validates parameters,
	salt/tag lengths and native-size representability, then composes geometry,
	successful zeroed allocation and first-two-block initialization; wired the core
	to call it. The full hash body and traversal remain unproved.
- Proved the production split segment-position selectors: predecessor/current
	positions are in-bounds and distinct before the data-dependent read; the
	reference position is in-bounds and differs from current afterward. Wired the
	walker in this order.
- Proved the real data-independent address-block helper's counter increment and
	two scalar G transitions compose to the address-block model, assuming the
	counter is below `u64::MAX`. The walker now uses this helper; address-block
	scheduling and the encompassing traversal proof remain open.
- Proved exact address-input field encoding and zero counter/tail in a
	same-source constructor used by the segment walker.
- Proved initial and per-index independent-address scheduling, destination
	independence and the successor counter invariant. The real walker uses these
	helpers; the encompassing segment-loop invariant remains unproved.
- Proved the real scalar arena update through gather/G/scatter with an exact
	destination-block frame. The scalar callback uses this verified path; borrowed
	conversion helpers are retained only as a test oracle. Performance impact of
	the owned block copies has not been benchmarked.
- Strengthened the production segment selectors to prove exact predecessor and
	reference-position model agreement in addition to bounds and exclusion.
- Proved the real shared segment walker and scalar adapter against an exact
	segment-prefix arena model, including callback contracts, both addressing
	modes, counter schedule and bounds. Outer traversal/tag composition remains
	open; scalar composition step 4.2 is complete.
- Proved the scalar lane/slice/pass helpers against exact traversal-prefix
	arena semantics and routed scalar execution through them. Full caller/tag
	composition remains open; scalar composition step 4.3 is complete.
- Proved final lane-tail XOR and little-endian serialization of the resulting
	128-word block, composed it with the proved H-prime API into `scalar_tag`,
	and routed scalar finalization through this helper. Caller discharge remains
	open; scalar composition step 4.4 is complete.
- Proved the accepted-input scalar caller through output copy: successful return
	implies exact whole-hash model tag equality. The production forced-Scalar
	branch delegates to this helper; allocator implementation and RFC/model
	fidelity remain separate trust boundaries. Scalar composition step 4.5 is
	complete for the forced-scalar caller.