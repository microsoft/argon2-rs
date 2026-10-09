# argon2-rs

A dependency-free Rust implementation of the algorithms and byte-level behavior
of the [reference Argon2 implementation](https://github.com/P-H-C/phc-winner-argon2),
the password hash that won the Password Hashing Competition (PHC).

**The scalar implementation has a machine-checked functional-correctness
theorem.** [Verus](https://github.com/verus-lang/verus) checks the production 
Rust code against separately written mathematical specifications. 
For API-accepted inputs and parameters, if the forced-scalar caller returns `Ok(())`, 
its output equals the tag computed by the whole-hash model derived from the Argon2 
specification. The caller proof  passes 200 verification obligations; 
all 19 same-source proof roots pass at `--no-cheating --rlimit 30`.

This proves that the checked scalar caller agrees with that mathematical model.
Thus, the crate combines runtime-dispatched SIMD with same-source
[Verus](https://github.com/verus-lang/verus) verification of scalar Argon2,
from H0 through the successful returned result (aka tag). BLAKE2b and the Argon2 core are
implemented locally; the SIMD paths are not covered by that theorem.

It does not by itself prove that the model perfectly captures the RFC; that
still needs independent review. The theorem also excludes SIMD and automatic
backend selection.

## Attribution And Security Reporting

This crate implements the Argon2 algorithms specified in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
and BLAKE2b as specified in [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html).
It is a Rust port of the [P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
reference implementation. The reference-derived portions use that source
package's CC0 1.0 option. The original authors, source link, and license-choice
notice are recorded in [NOTICE](NOTICE). This crate is separately distributed
under the MIT License; see [LICENSE](LICENSE). It is not affiliated
with or endorsed by the reference project's authors.

Report suspected security defects privately as described in
[SECURITY.md](SECURITY.md), not in a public issue.

## Why This Crate

- **No production dependencies:** the hashing core, BLAKE2b, and CPU dispatch
  form one inspectable codebase, with no external cryptographic crate graph.
- **SIMD without a different algorithm:** SSE2, SSSE3, and AVX2 accelerate block
  compression while preserving the reference result; other targets use scalar.
- **Mathematical contracts on real code:** [Verus](https://github.com/verus-lang/verus) 
checks selected executable functions compiled by ordinary Rust, 
not a manually maintained runtime copy.
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

The example uses RFC 9106's second recommended Argon2id profile:
64 MiB, three passes, four lanes, and a 32-byte tag. Lanes are processed
sequentially in this implementation; `parallelism` does not spawn worker threads.
Tune costs for your deployment and threat model. `Argon2::default()` uses
Argon2id `0x13` with 19 MiB, two passes, and four lanes; these are also not an
RFC 9106 recommended profile. Memory is measured in KiB and rounded down to a
multiple of `4 * parallelism` blocks. Requires Rust 1.88 or newer.
The crate uses `std`; its feature names do not imply `no_std` support.

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
  loads/stores and CPU-feature calls have safety obligations: live correctly 
  sized references, in-bounds accesses, valid store destinations, 
  and appropriate runtime dispatch. Unaligned `loadu`/`storeu` operations 
  remove alignment requirements, not size or bounds requirements. The wipe helper's two volatile stores also require live, exclusively borrowed elements. 
  Differential tests are evidence, not a proof of these kernels or the wipe helper.

## Mathematical proofs

The work follows the staged plan. Stages 1 and 2 built reusable primitive proofs; 
Stage 4 composes them in the order required by the hash.

| Original stage | Status | Result / remaining boundary |
| --- | --- | --- |
| **1. Prove scalar G** | Complete | The production row pass, column pass and full 128-word G transition, including both XOR modes, are proved without application-local assumptions. |
| **2. Prove BLAKE2b and H-prime** | Complete for the implemented models | Compression, buffering, update/finalize, multipart composition and both H-prime branches are proved under explicit size/capacity preconditions. Independent review that these models faithfully encode RFC 7693/9106 remains separate. |
| **3. Compose the scalar hash** | Complete for the stated successful-return theorem | Steps 3.1–3.5 below compose to `Ok(()) => output == model tag` for forced scalar, Argon2d/i/id, version `0x13`, and accepted/representable inputs. Allocation failure may return `Err`. |

The composition is sequential: each row establishes the state and contract
needed by the next one.

| Stage 3 step | Proof chain | Status and root |
| --- | --- | --- |
| **3.1 H0 and initial memory** | Validate parameters and lengths → serialize the requested parameters into H0 → derive lane seeds and first blocks → create the owned arena with exact geometry. | Complete. H0, validation, initialization and owner roots report 120/0, 63/0, 69/0 and 156/0. The owner result relies on the disclosed local vstd allocation-shape specification. |
| **3.2 Addressing and one segment** | Encode address input → prove counter and 128-word scheduling → prove exact predecessor/reference indices and exclusions → gather source blocks, apply G, and update only the current block → prove the segment's final arena. | Complete. Address, shared-selector and segment roots report 30/0, 62/0 and 180/0. The segment model covers independent and dependent addressing. |
| **3.3 Pass, slice and lane traversal** | Compose segment transitions in lane order → compose four slices → compose all passes, preserving the exact arena prefix at each loop boundary. | Complete. Included in the segment/traversal root (180/0), with final arena equality against `traversal_prefix`. |
| **3.4 Final block and tag derivation** | XOR each lane's last block → serialize 128 words little-endian → apply the already-proved H-prime function. | Complete. The finalization root reports 166/0 and proves the `scalar_tag` model. |
| **3.5 Caller and successful returned tag** | Compose checked H0 → successful owner construction → traversal → scalar tag → output copy; discharge helper preconditions inside the caller. | Complete for the forced-scalar caller. The caller root reports 200/0: `Ok(())` implies exact output equality with the whole-hash model. Public wrapper backend selection and SIMD are outside this theorem. |

Counts are verifier obligations, not coverage percentages; roots overlap and
import shared helpers. The theorem proves functional agreement with the encoded
model, not independent RFC fidelity, cryptographic security, constant time or
zeroization. The vstd contracts and Rust/Verus toolchain are part of the trusted
base. Edge security approval, supported-platform CI, extended
fuzzing, sandboxed/cross-architecture performance and rollout sign-off remain
separate release gates.

We write Verus ghost contracts as attributes on the Rust functions they
describe. Verus checks each contract against that function's production body;
Cargo builds the same function with the ghost contract erased. Keeping the
contract beside the code it describes avoids a separate implementation that
could drift.

| Source | Checked contract scope |
| --- | --- |
| [src/block_primitives.rs](src/block_primitives.rs) | BlaMka modular arithmetic, rotation for `1 <= n <= 63`, GB, and permutation P agree with their mathematical definitions; no panic under their preconditions. |
| [src/block_g.rs](src/block_g.rs) | The production row-wise pass applies P to each of the eight 16-word rows, as specified. |
| [src/block_g_column.rs](src/block_g_column.rs) and [src/block_g_columns.rs](src/block_g_columns.rs) | One-column gather/P/scatter and the production loop over all eight columns satisfy their contracts. |
| [src/block_g_fill.rs](src/block_g_fill.rs) | The production scalar G transition over a flat 128-word block, including row/column passes and both XOR stages, matches its sequence model. |
| [src/blake2b_compress.rs](src/blake2b_compress.rs), [src/blake2b_tables.rs](src/blake2b_tables.rs), and [src/blake2b_buffer.rs](src/blake2b_buffer.rs) | One block-to-state transition, RFC tables/unkeyed initialization, buffer append/flush, update step, and final-block transition. |
| [src/blake2b_update.rs](src/blake2b_update.rs), [proofs/blake2b_update.rs](proofs/blake2b_update.rs) | The production loop establishes block-prefix semantics and a modeled final digest; binary partition composition proves digest independence for any two-part split under the semantic contracts. |
| [src/blake2b.rs](src/blake2b.rs), [proofs/blake2b_long.rs](proofs/blake2b_long.rs) | Real public methods, multipart/prefixed wrappers and both H-prime branches match their encoded models under output/capacity/byte-count preconditions. H-prime output length, bounds and termination are checked; closed ghost views preserve private fields. |
| [src/initial_hash.rs](src/initial_hash.rs), [proofs/initial_hash.rs](proofs/initial_hash.rs) | Exact H0 serialization, real enum/Params adapter and checked accepted-input-to-H0 composition. |
| [src/parameters.rs](src/parameters.rs) | Canonical public input types and validation acceptance predicate, with guarded arithmetic checked and public root re-exports preserved. |
| [src/memory_initialization.rs](src/memory_initialization.rs), [proofs/memory_initialization.rs](proofs/memory_initialization.rs) | Exact lane seed, H-prime block, little-endian decoding, in-bounds flat writes and nested first-two-block initialization under geometry/word-slice preconditions; owning arena/allocation/full caller proof excluded. |
| [src/memory.rs](src/memory.rs) | `Memory::zeroed_initialized` validates parameters and salt/tag lengths, checks native-size representability, then composes geometry, successful zeroed allocation shape, and first-two-block initialization without caller preconditions. It uses vstd's `try_reserve_exact` contract; general borrowed accessors remain outside the proof. |
| [src/core_primitives.rs](src/core_primitives.rs) | Parameter predicate, rounded memory geometry, previous index, addressing/XOR decisions, reference-area size, index-alpha mapping and exact split segment-position selectors satisfy their contracts. |
| [src/core_segment.rs](src/core_segment.rs) | The real shared walker and scalar adapter agree with the exact segment-prefix arena model; scalar lane/slice/pass traversal agrees with `traversal_prefix`. |
| [src/core_final.rs](src/core_final.rs) | The real final lane-tail XOR, little-endian 128-word serialization, and H-prime application compose to the exact tag model under representable arena geometry. |
| [src/core_scalar_caller.rs](src/core_scalar_caller.rs) | The real checked H0, successful arena initialization, scalar traversal, final reduction, serialization, H-prime and output copy compose: `Ok(())` implies exact tag equality for accepted inputs. |
| [proofs/geometry.rs](proofs/geometry.rs) | Supporting geometry, division, product, and indexing bounds. |

From the crate root, set `VERUS` to the verifier executable:

```sh
VERUS=/path/to/verus
"$VERUS" verus/shared.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/block_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/block_g_rows_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/block_g_column_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/block_g_columns_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/block_g_fill_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/blake2b_compress_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/blake2b_tables_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/blake2b_buffer_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/blake2b_update_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/blake2b_api_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/initial_hash_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/parameters_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/memory_initialization_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/memory_owner_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/core_address_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/core_segment_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/core_final_verified.rs --crate-type lib --no-cheating --rlimit 30
"$VERUS" verus/core_scalar_caller_verified.rs --crate-type lib --no-cheating --rlimit 30
```

Proof roots include:
- with **62 verified obligations, zero errors** for the combined primitive/indexing
root [verus/shared.rs](verus/shared.rs), including helpers for 11 executable leaves,
- **8/0** for the scalar-only root [verus/block_verified.rs](verus/block_verified.rs),
- **11/0** for the row helper [verus/block_g_rows_verified.rs](verus/block_g_rows_verified.rs),
- **11/0** for one column [verus/block_g_column_verified.rs](verus/block_g_column_verified.rs),
- **13/0** for the outer column loop [verus/block_g_columns_verified.rs](verus/block_g_columns_verified.rs),
- **21/0** for full scalar G [verus/block_g_fill_verified.rs](verus/block_g_fill_verified.rs),
- One BLAKE2b block-to-state transition reports **18/0** [verus/blake2b_compress_verified.rs](verus/blake2b_compress_verified.rs), and
- tables/unkeyed initialization **8/0** [verus/blake2b_tables_verified.rs](verus/blake2b_tables_verified.rs).
- The BLAKE2b buffer root [verus/blake2b_buffer_verified.rs](verus/blake2b_buffer_verified.rs) additionally reports **23 verified, 0 errors** for append, full-buffer flush/update step, padding, final-block serialization,
and positive step progress/byte-count conservation. The shared progress lemma
adds one obligation to every root; this does not expand their hash-level scope.
- [verus/blake2b_update_verified.rs](verus/blake2b_update_verified.rs) root reports 
**41 verified, 0 errors** for the production repeated update loop,
block-stream digest semantics and binary partition-composition lemmas.
The initialization helper adds two obligations to roots importing the tables.
The parts-prefix model adds two checks to streaming roots.
- [verus/blake2b_api_verified.rs](verus/blake2b_api_verified.rs) root reports
**55 verified, 0 errors** for the public methods, multipart/prefixed wrappers, H-prime and its model lemmas.
- [verus/initial_hash_verified.rs](verus/initial_hash_verified.rs) root reports
**120 verified, 0 errors** for H0 and its checked parameter adapter/boundary.
[verus/parameters_verified.rs](verus/parameters_verified.rs) reports **63 verified, 0 errors**
for parameter validation plus imported core/geometry lemmas.
- [verus/memory_initialization_verified.rs](verus/memory_initialization_verified.rs)
root reports **69 verified, 0 errors** for lane-block generation and flat initialization.
- [verus/memory_owner_verified.rs](verus/memory_owner_verified.rs) reports
**156 verified, 0 errors** with the local Verus/vstd review build, for the
geometry/allocation/initialization composition helper, the successful-result
shape of `Memory::zeroed`, the real owning initializer, and imported helpers.

The shared primitive root covers 11 executable leaf functions; its count also
includes proof helpers. Across all roots, counts are verifier obligations, not
coverage percentages. Mathematical definitions live in
[specs/mod.rs](specs/mod.rs).

This includes an end-to-end functional theorem for the forced-scalar caller,
but not for automatic backend selection or SIMD. Scalar leaves are compiled
into the Cargo library, as are the parameter, geometry, predecessor,
addressing-mode, and reference-index leaves.

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
It covers both addressing modes, counter scheduling and the scalar callback.
The same root also proves lane/slice/pass traversal against `traversal_prefix`
and reports **180 verified, 0 errors**.

The final reduction/serialization/H-prime root reports **166 verified, 0 errors**:
it proves the lane-tail XOR, little-endian 128-word encoding and resulting
`scalar_tag` against the H-prime model.

The whole scalar caller root reports **200 verified, 0 errors** and proves
`hash_into_scalar`: for accepted inputs, `Ok(())` implies that `out` equals the
whole-hash model for the same Argon2d/i/id inputs and parameters. The production
`Backend::Scalar` branch delegates to this helper. This does not guarantee `Ok`;
allocation failure may return `Err`.

The scalar callback uses proved gather/G/scatter:
it updates exactly one block and preserves all other words. Owned block copies
avoid unsupported borrowed slice-to-array conversion; their performance impact
has not been benchmarked. General borrowed accessors remain unverified.
The constructor's successful-result shape and initializer are checked,
and geometry proves exact block product and lane_length>=8. The owner proof uses
vstd's `try_reserve_exact` contract to establish the successful vector shape;
the allocator's runtime implementation remains part of the trusted base. No
application-local assumption was added. The agreed
returned-tag target is forced scalar, version 0x13,
Argon2d/i/id with accepted/representable inputs and normal successful execution;
automatic detection, SIMD and legacy 0x10 are excluded from this first theorem.
The original plan's scalar composition steps 3.2 (one segment), 3.3 (outer
traversal), 3.4 (final reduction/serialization/H-prime), and 3.5 (returned tag
on successful forced-scalar execution) are complete. Public wrapper selection,
automatic backend selection and SIMD equivalence remain outside this theorem.
Drop/wiping are unchanged; zeroization is
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
## License

This crate is licensed under the MIT License. The complete license text is in
[LICENSE-MIT](LICENSE-MIT). The `0.1.0` package is prepared for crates.io, but
has not yet been published.
