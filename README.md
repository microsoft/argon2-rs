# argon2-verus

A dependency-free Rust implementation of the algorithms and byte-level behavior
of the [reference Argon2 implementation](https://github.com/P-H-C/phc-winner-argon2),
the password hash that won the Password Hashing Competition (PHC).

The crate combines runtime-dispatched SIMD with same-source
[Verus](https://github.com/verus-lang/verus) verification of selected scalar and
indexing functions. BLAKE2b and the Argon2 core are implemented locally.

## Why This Crate

- **No production dependencies:** the hashing core, BLAKE2b, and CPU dispatch
  form one inspectable codebase, with no external cryptographic crate graph.
- **SIMD without a different algorithm:** SSE2, SSSE3, and AVX2 accelerate block
  compression while preserving the reference result; other targets use scalar.
- **Mathematical contracts on real code:** Verus checks selected executable
  functions compiled by ordinary Rust, not a manually maintained runtime copy.
- **Explicit boundaries:** the project documents what is proved, tested, or
  outside its guarantees, rather than claiming complete cryptographic proof.

Supports Argon2d, Argon2i, and Argon2id; current version `0x13` and legacy
version `0x10`; optional secret and associated-data inputs; and scalar,
SSE2, SSSE3, and AVX2 backends. The implementation targets the
[Argon2 v1.2.1 specification](https://www.cryptolux.org/images/0/0d/Argon2.pdf)
and [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).

## Usage

Version 0.1.0 has not yet been published to crates.io. Once released, add it as:

```toml
[dependencies]
argon2-verus = "0.1"
```

```rust
use argon2_verus::{Algorithm, Argon2, Params, Version};

fn main() -> Result<(), argon2_verus::Error> {
    let params = Params {
    parallelism: 4,
    memory_kib: 64 * 1024,
    iterations: 3,
    };
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut tag = [0u8; 32];
    hasher.hash_password_into(b"example password", b"example salt 123", &mut tag)?;
    Ok(())
}
```

The fixed salt above is for demonstration only. Generate a fresh random salt
for each stored password, and retain the algorithm, version, parameters, salt,
and tag. The API returns raw tag bytes; it does not provide PHC string encoding,
salt generation, or a password/tag comparison API. Use a constant-time
comparison implementation when verifying stored tags.

Until the registry release exists, use a local path dependency with the same
package name. The example uses RFC 9106's second recommended Argon2id profile:
64 MiB, three passes, four lanes, and a 32-byte tag. Lanes are processed
sequentially in this implementation; `parallelism` does not spawn worker threads.
Tune costs for your deployment and threat model. `Argon2::default()` uses
Argon2id `0x13` with 19 MiB, two passes, and four lanes; these are also not an
RFC 9106 recommended profile. Memory is measured in KiB and rounded down to a
multiple of `4 * parallelism` blocks. Requires Rust 1.88 or newer.
The crate uses `std`; its feature names
do not imply `no_std` support.

## Security Boundaries

- **Addressing and timing:** Argon2i uses data-independent memory addressing;
  Argon2d uses data-dependent addressing; Argon2id uses independent addressing
  for the first half of pass zero, then dependent addressing. There is no
  blanket constant-time guarantee or machine-code timing proof.
- **Secret lifetime:** working memory and the BLAKE2b owned buffer/state are
  overwritten with volatile stores on normal `Drop`, so these writes cannot
  be discarded as dead stores. H0 fields are streamed without a plaintext heap
  concatenation. This does not cover every temporary, register or buffer
  copy, and does not erase caller-owned passwords, salts, secrets, or tags.
  Cleanup cannot be relied on after process abort or termination.
- **Resource limits:** valid parameters can still exhaust memory or consume
  excessive CPU time. Enforce application-level memory, iteration, and
  concurrency caps before hashing, especially for attacker-controlled inputs.
  The crate does not supply that policy; a returned `Result` is not a promise
  that every allocation failure is recoverable.
- **Unsafe boundaries:** the crate root denies unsafe code except in
  [src/simd.rs](src/simd.rs) and [src/wipe.rs](src/wipe.rs). SIMD raw
  loads/stores and CPU-feature calls have
  safety obligations: live correctly sized references, in-bounds accesses,
  valid store destinations, and appropriate runtime dispatch. Unaligned
  `loadu`/`storeu` operations remove alignment requirements, not size or bounds
  requirements. The wipe helper's two volatile stores also require live,
  exclusively borrowed elements. Differential tests are evidence, not a proof
  of these kernels or the wipe helper.

## Same-Source Verification

The same-source layout keeps executable leaves in ordinary Rust source.
Cargo compiles the integrated leaves; Verus imports the exact same files
and discharges their contracts. `cfg_attr(verus_keep_ghost, verus_spec(...))`
attaches ghost-only contracts, while ghost imports and proof blocks are absent
from normal Cargo builds. There is no generated executable copy or exporter
required for the production path.

| Source | Checked contract scope |
| --- | --- |
| [src/block_primitives.rs](src/block_primitives.rs) | BlaMka modular arithmetic, rotation for `1 <= n <= 63`, GB, and permutation P agree with their mathematical definitions; no panic under their preconditions. |
| [src/block_g.rs](src/block_g.rs) | The production row-wise pass applies P to each of the eight 16-word rows, as specified. |
| [src/block_g_column.rs](src/block_g_column.rs) and [src/block_g_columns.rs](src/block_g_columns.rs) | One-column gather/P/scatter and the production loop over all eight columns satisfy their contracts. |
| [src/block_g_fill.rs](src/block_g_fill.rs) | The production scalar G transition over a flat 128-word block, including row/column passes and both XOR stages, matches its sequence model. |
| [src/blake2b_compress.rs](src/blake2b_compress.rs), [src/blake2b_tables.rs](src/blake2b_tables.rs), and [src/blake2b_buffer.rs](src/blake2b_buffer.rs) | One block-to-state transition, RFC tables/unkeyed initialization, buffer append/flush, update step, and final-block transition. |
| [src/blake2b_update.rs](src/blake2b_update.rs), [proofs/blake2b_update.rs](proofs/blake2b_update.rs) | The production loop establishes block-prefix semantics and a modeled final digest; binary partition composition proves digest independence for any two-part split under the semantic contracts. |
| [src/blake2b.rs](src/blake2b.rs), [proofs/blake2b_long.rs](proofs/blake2b_long.rs) | Real public methods, multipart/prefixed wrappers and both H-prime branches match their encoded models under output/capacity/byte-count preconditions. H-prime output length, bounds and termination are checked; closed ghost views preserve private fields. |
| [src/initial_hash.rs](src/initial_hash.rs), [proofs/initial_hash.rs](proofs/initial_hash.rs) | Exact H0 serialization, real enum/Params adapter and checked accepted-input-to-H0 composition; not the full hash caller/traversal theorem. |
| [src/parameters.rs](src/parameters.rs) | Canonical public input types and validation acceptance predicate, with guarded arithmetic checked and public root re-exports preserved. |
| [src/memory_initialization.rs](src/memory_initialization.rs), [proofs/memory_initialization.rs](proofs/memory_initialization.rs) | Exact lane seed, H-prime block, little-endian decoding, in-bounds flat writes and nested first-two-block initialization under geometry/word-slice preconditions; owning arena/allocation/full caller proof excluded. |
| [src/memory.rs](src/memory.rs) | `Memory::zeroed_initialized` validates parameters and salt/tag lengths, checks native-size representability, then composes geometry, exact zeroed allocation shape, and first-two-block initialization without caller preconditions. It relies on a local, unmerged vstd `try_reserve_exact` specification; allocator implementation, general accessors, and the full hash caller remain unproved. |
| [src/core_primitives.rs](src/core_primitives.rs) | Parameter predicate, rounded memory geometry, previous index, addressing/XOR decisions, reference-area size, index-alpha mapping and exact split segment-position selectors satisfy their contracts. |
| [src/core_segment.rs](src/core_segment.rs) | The real shared walker and scalar adapter agree with the exact segment-prefix arena model under valid geometry and exact arena size; outer traversal remains unproved. |
| [proofs/geometry.rs](proofs/geometry.rs) | Supporting geometry, division, product, and indexing bounds. |

Proof roots include [verus/shared.rs](verus/shared.rs),
[verus/block_verified.rs](verus/block_verified.rs),
[verus/block_g_rows_verified.rs](verus/block_g_rows_verified.rs),
[verus/block_g_column_verified.rs](verus/block_g_column_verified.rs),
[verus/block_g_columns_verified.rs](verus/block_g_columns_verified.rs),
[verus/block_g_fill_verified.rs](verus/block_g_fill_verified.rs),
[verus/blake2b_compress_verified.rs](verus/blake2b_compress_verified.rs), and
[verus/blake2b_tables_verified.rs](verus/blake2b_tables_verified.rs). The latest
`--no-cheating --rlimit 30` gate reports, respectively: **62**, **8**, **11**, **11**, **13**,
**21**, **18**, and **8 verified obligations**, all with zero errors.
The BLAKE2b buffer root additionally reports **23 verified, 0 errors** for
append, full-buffer flush/update step, padding, final-block serialization,
and positive step progress/byte-count conservation. The shared progress lemma
adds one obligation to every root; this does not expand their hash-level scope.
The new same-source [verus/blake2b_update_verified.rs](verus/blake2b_update_verified.rs)
root reports **41 verified, 0 errors** for the production repeated update loop,
block-stream digest semantics and binary partition-composition lemmas.
The initialization helper adds two obligations to roots importing the tables.
The parts-prefix model adds two checks to streaming roots. The new
[verus/blake2b_api_verified.rs](verus/blake2b_api_verified.rs) root reports
**55 verified, 0 errors** for the real public methods, multipart/prefixed wrappers,
H-prime and its model lemmas.
The new [verus/initial_hash_verified.rs](verus/initial_hash_verified.rs) root reports
**120 verified, 0 errors** for H0 and its checked parameter adapter/boundary.
[verus/parameters_verified.rs](verus/parameters_verified.rs) reports **63 verified, 0 errors**
for parameter validation plus imported core/geometry lemmas.
The new [verus/memory_initialization_verified.rs](verus/memory_initialization_verified.rs)
root reports **69 verified, 0 errors** for lane-block generation and flat initialization.
[verus/memory_owner_verified.rs](verus/memory_owner_verified.rs) reports
**155 verified, 0 errors** with the local Verus/vstd review build, for the
geometry/allocation/initialization composition helper, the successful-result
shape of `Memory::zeroed`, the real owning initializer, and imported helpers.
The strict application gate passes; its trusted vstd base now
includes the unmerged `try_reserve_exact` content-preservation specification.
There are 11 executable leaf functions; the check count includes proof helpers.
Counts are verifier
checks, not coverage percentages. Mathematical definitions live in
[specs/mod.rs](specs/mod.rs).

This is not an end-to-end Argon2 proof. Scalar leaves are compiled into the
Cargo library, as are the parameter, geometry, predecessor, addressing-mode,
and reference-index leaves.
Compiling or calling a verified leaf does not establish
that every caller satisfies its preconditions. BLAKE2b proof slices cover one
block transition, buffer/update-step/finalize helpers, and the repeated update
loop against a finite trace and a block-oriented digest model, with binary
partition independence under the semantic contracts. The public constructor and
multipart/prefixed wrappers are now checked for arbitrary finite part lists with
output lengths 1..=64 and representable total byte counts. H-prime is checked for
output lengths 1..=u32::MAX within isize::MAX byte capacity and a representable
total input count including the four-byte length prefix. This is conditional on
successful normal allocation/execution, not a recoverable-allocation theorem.
H0 serialization, enum/Params mapping and the selected accepted-input boundary
are proved. The real flat initialization loops are proved under exact arena-size
and geometry preconditions, preserving untouched slots. `Memory::zeroed_initialized`
now validates parameters/salt/tag and native-size representability internally,
then composes geometry, allocation and initialization; the core calls it.
The helper has no caller preconditions. The address-block helpers now prove exact
input encoding, zero counter/tail, counter increment, two scalar G transitions,
initial scheduling at index 0/2 and per-index regeneration/word selection.
The real scalar segment loop now proves exact arena equality with its
`segment_prefix` model, under valid segment geometry and exact arena size.
It covers both addressing modes, counter scheduling and the scalar callback;
the segment root reports **170 verified, 0 errors**. Outer pass/slice/lane
traversal and the full hash caller remain unverified. The scalar callback uses proved gather/G/scatter:
it updates exactly one block and preserves all other words. Owned block copies
avoid unsupported borrowed slice-to-array conversion; their performance impact
has not been benchmarked. General borrowed accessors remain unverified.
The constructor's successful-result shape and initializer are checked,
and geometry proves exact block product and lane_length>=8. The `try_reserve_exact` mapping is a trusted vstd specification in
a separate local review worktree, not an allocator implementation proof or an
upstream-approved release. No application-local assumption was added. The agreed
returned-tag target is forced scalar, version 0x13,
Argon2d/i/id with accepted/representable inputs and normal successful execution;
automatic detection, SIMD and legacy 0x10 are excluded from this first theorem.
The original plan's scalar composition step 4.2 (one segment) is complete;
steps 4.3 (outer traversal), 4.4 (finalization) and 4.5 (returned-tag/API)
remain open. Hash traversal and the returned-tag theorem are not proved. Drop/wiping are unchanged; zeroization is
not part of these functional proofs. The full hash loop,
caller invariants, SIMD equivalence and memory safety, permutation bijectivity,
cryptographic security, timing, and zeroization are not established
by these proofs. Specification fidelity to the RFC remains a separate human
obligation. Verus/vstd, the SMT solver, Rust compiler, and their translation
semantics are trusted tooling; Verus is not a production dependency.

See [verus/README.md](verus/README.md) for commands and trust boundaries.

## Testing

[tests/kat.rs](tests/kat.rs) checks all three RFC 9106 Section 5 known-answer
vectors byte-for-byte, including secret and associated data, at version `0x13`
with `m=32 KiB`, `t=3`, `p=4`. Each runs on every backend available on the test
CPU. Whole-hash differential tests compare backends across 108 combinations
covering all variants, both versions, one to four lanes, rounded memory sizes,
and empty, ordinary, and long passwords. Backend agreement is not an independent
reference oracle, and the RFC vectors do not cover legacy version `0x10`.

Unit tests cover BLAKE2b vectors, block-compression properties, API behavior,
and SIMD/scalar agreement on 2,048 pseudo-random block triples per supported
kernel, with and without XOR. Run from the crate root:

```sh
cargo test --test kat
cargo test --doc
cargo test --release
```

For 32-bit x86, add `--target i686-unknown-linux-gnu` with the target toolchain
and linker installed. CI is configured for Linux, Windows, and macOS and separately
checks portable ARM64 compilation. A build-only job is not an ARM64 runtime test,
and SIMD tests run only for instruction sets available to each runner.

Reference-C differential fuzzing has been run in a separate native harness;
the last recorded short run completed 4,335 executions in 301 seconds without
divergence. That harness is not shipped in this crate, and its native ASan run
does not establish full Rust instrumentation or exhaustive coverage. The
reproducible tests shipped here are the KAT, unit, and backend tests above.

## Performance

Runtime dispatch selects AVX2, then SSSE3, then SSE2, then scalar on x86/x86-64;
other architectures use scalar. SIMD BlaMka rounds and register-resident state
follow the reference C implementation's optimization approach.

The kernels retain vector state across block processing to reduce repeated
reads of the predecessor block. The compiler chooses physical registers and
spills; a register-resident design is not a guarantee of zero spills.

Forcing a backend with `with_backend()` makes controlled comparisons possible.
Measure optimized builds with representative parameters on the actual target
hardware. SIMD capability, memory cost, allocator behavior, and CPU load affect
results; this README does not promise a universal speedup. The crate uses a
normal initialized allocation, without platform-specific huge-page requests.

## Attribution And Security Reporting

This crate implements the Argon2 algorithms specified in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
and BLAKE2b as specified in [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html).
It is a Rust port of the [P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
reference implementation. The reference-derived portions use that source
package's CC0 1.0 option. The original authors, source link, and license-choice
notice are recorded in [NOTICE](NOTICE). This crate is separately distributed
under the MIT License; see [LICENSE-MIT](LICENSE-MIT). It is not affiliated
with or endorsed by the reference project's authors.

Report suspected security defects privately as described in
[SECURITY.md](SECURITY.md), not in a public issue.

## License

This crate is licensed under the MIT License. The complete license text is in
[LICENSE-MIT](LICENSE-MIT). The `0.1.0` package is prepared for crates.io, but
has not yet been published.
