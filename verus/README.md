# Same-Source Verus Proofs

The verifier reads canonical ordinary Rust executable leaves directly. Cargo
compiles integrated leaves from the same bodies, without ghost-only contracts
and proof blocks. This same-source layout requires no executable export step.

| Proof root | Imported executable source | Scope |
| --- | --- | --- |
| [shared.rs](shared.rs) | [../src/core_primitives.rs](../src/core_primitives.rs), [../src/block_primitives.rs](../src/block_primitives.rs) | All 11 scalar and core executable leaves; supporting lemmas in [../proofs/geometry.rs](../proofs/geometry.rs). |
| [block_verified.rs](block_verified.rs) | [../src/block_primitives.rs](../src/block_primitives.rs) | `blamka`, `rotr64`, `gb`, `permute`. |
| [block_g_rows_verified.rs](block_g_rows_verified.rs) | [../src/block_g.rs](../src/block_g.rs), [../src/block_primitives.rs](../src/block_primitives.rs) | The production row-wise permutation pass over the eight 16-word rows. |
| [block_g_column_verified.rs](block_g_column_verified.rs) | [../src/block_g_column.rs](../src/block_g_column.rs), [../src/block_primitives.rs](../src/block_primitives.rs) | Gather, permute, and scatter one selected 16-word column. |
| [block_g_columns_verified.rs](block_g_columns_verified.rs) | [../src/block_g_columns.rs](../src/block_g_columns.rs) | The production loop applying the one-column helper to all eight columns. |
| [block_g_fill_verified.rs](block_g_fill_verified.rs) | [../src/block_g_fill.rs](../src/block_g_fill.rs), row/column helpers | Full scalar 128-word G composition: input XOR, row P, column P, optional old-destination XOR, and output XOR. |
| [blake2b_compress_verified.rs](blake2b_compress_verified.rs) | [../src/blake2b_compress.rs](../src/blake2b_compress.rs), [../src/blake2b_tables.rs](../src/blake2b_tables.rs) | One BLAKE2b 128-byte block-to-chaining-state transition, including little-endian decode, IV/counter/final flag, 12 rounds, and state fold. |
| [blake2b_tables_verified.rs](blake2b_tables_verified.rs) | [../src/blake2b_tables.rs](../src/blake2b_tables.rs) | Production IV/SIGMA and unkeyed digest-length initialization agree with the model. |
| [blake2b_buffer_verified.rs](blake2b_buffer_verified.rs) | [../src/blake2b_buffer.rs](../src/blake2b_buffer.rs), compression helpers | Buffer append, full-buffer flush/update step, final padding, and digest serialization. |
| [blake2b_update_verified.rs](blake2b_update_verified.rs) | [../src/blake2b_update.rs](../src/blake2b_update.rs), [../proofs/blake2b_update.rs](../proofs/blake2b_update.rs), buffer helpers | Production update establishes block-prefix semantics and a modeled final digest; binary partition composition and digest independence are proved. |
| [blake2b_api_verified.rs](blake2b_api_verified.rs) | [../src/blake2b.rs](../src/blake2b.rs), [../proofs/blake2b_long.rs](../proofs/blake2b_long.rs), streaming model/helpers | Real public methods, arbitrary multipart/prefixed wrappers, and both H-prime branches agree with their models; lengths, bounds and loop termination are checked under explicit preconditions. |
| [initial_hash_verified.rs](initial_hash_verified.rs) | [../src/initial_hash.rs](../src/initial_hash.rs), [../src/parameters.rs](../src/parameters.rs), [../proofs/initial_hash.rs](../proofs/initial_hash.rs), BLAKE2b helpers | Raw H0 serialization, real enum/Params mapping and checked accepted-input-to-H0 composition; not arena/traversal or the full hash caller. |
| [parameters_verified.rs](parameters_verified.rs) | [../src/parameters.rs](../src/parameters.rs), core/geometry helpers | Parameter/salt/tag validation returns Ok exactly for its accepted domain; guarded arithmetic is checked. |
| [memory_initialization_verified.rs](memory_initialization_verified.rs) | [../src/memory_initialization.rs](../src/memory_initialization.rs), [../proofs/memory_initialization.rs](../proofs/memory_initialization.rs), H-prime helpers | Exact H0/LE32 column/lane seed, H-prime(1024) decoding, in-bounds flat placement and real nested initialization loops; allocation/Memory wrapper/caller discharge excluded. |
| [memory_owner_verified.rs](memory_owner_verified.rs) | [../src/memory.rs](../src/memory.rs), geometry/initialization/G/BLAKE2b helpers | Successful `Memory::zeroed` returns exact-length zero words; real owning initialize is checked through a closed ghost view. Depends on the local trusted vstd `try_reserve_exact` content-preservation spec; allocator implementation/general accessors/full caller remain outside the proof. |

Definitions reside in [../specs/mod.rs](../specs/mod.rs), imported as `specs`
by both roots. Contracts use `cfg_attr(verus_keep_ghost, verus_spec(...))`;
ghost imports and helper invocations use `cfg(verus_keep_ghost)`. There is
only one canonical body for each executable leaf.

## Running

Obtain a compatible [Verus release or source build](https://github.com/verus-lang/verus)
and its matching vstd, Rust toolchain, and Z3 solver. The original local baseline
uses Verus `0.2026.09.23.4d4a480` with its `1.98.1` toolchain and Z3 `4.16.0`.
Use the solver version pinned by your Verus build; substituting versions can
cause parser failures rather than a meaningful verification result.

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
```

The matching source revision is
`4d4a4800490d53abe7433ed89b33ae855efce59e` in the Verus repository.
If a compatible binary release is unavailable, build that revision following
its BUILD.md with the pinned Rust toolchain and matching Z3, then set `VERUS`
to the resulting executable. Do not infer a downloadable release URL from the
version string alone. Build Verus in a separate checkout and shell so its Cargo
wrapper does not replace the ordinary toolchain used for this crate.
The original `4d4a480` vstd lacks `Vec::try_reserve_exact`, so it cannot verify
the annotated constructor. The current constructor result was checked with a
separate local Verus source worktree at `89f8d65` and its rebuilt vstd
(`0.2026.10.07.89f8d65.dirty`), which contains the proposed mapping. That mapping
is unmerged and trusted; a passing `--no-cheating` application gate does not
prove the allocator implementation.
The current strict gate reports **34**, **8**, **11**, **11**, **13**, **21**,
**18**, and **8 verified, 0 errors**, respectively, for the combined, scalar,
row, one-column, eight-column, full-G, BLAKE2b-block, and BLAKE2b-table roots.
The BLAKE2b buffer/update-step/finalize root reports **23 verified, 0 errors**.
The production update/streaming-composition root reports **41 verified, 0 errors**.
The public multipart/prefixed API and H-prime root reports **55 verified, 0 errors**.
The checked H0/parameter-adapter root reports **92 verified, 0 errors**.
The parameter-validation root reports **35 verified, 0 errors**. These roots
import existing core/geometry proofs and overlap; counts are not new coverage totals.
The seed/block/flat-arena initialization root reports **69 verified, 0 errors**.
The real owner/constructor root reports **121 verified, 0 errors** including
imported G/core/BLAKE2b helpers, with the local vstd mapping. It proves the
constructor's exact length and zero contents on `Ok`, not allocation success or
allocator correctness. The geometry identity assertion adds one check
to importing roots; these are overlapping obligations, not coverage totals.
The parts-prefix definition and bound lemma add two obligations to roots importing
the streaming proof module. The API root additionally uses ghost-only `cfg_eval`
to expand nested contracts before `verus_verify`; ordinary Rust erases those attrs.
The initialization helper adds two obligations to each root importing the tables.
The shared step-progress lemma adds one obligation to every root, not new G
or whole-hash coverage.
Counts are verifier obligations, not function or coverage counts.
Require a successful exit and a positive verification summary with zero errors
for each root. Compile-only output or expansion output is not proof evidence.

Run ordinary Cargo separately:

```sh
cargo test --test kat
cargo test --doc
```

Do not set `verus_keep_ghost` for normal Cargo builds. If building Verus from
source, keep its activated build shell separate: activation can replace the
ordinary Cargo command with Verus's build wrapper.

## Returned-Tag Target

The agreed first hash-level target is `Backend::Scalar`, `Version::V0x13`, and
all three algorithms: Argon2d, Argon2i and Argon2id. Automatic detection and SIMD
are excluded; the public theorem must identify a forced scalar call, not assume
the default public API selected scalar. Legacy `0x10` is a separate extension.

The input domain is the existing API-accepted parameters and lengths: parallelism
1..=2^24-1, memory_kib >= 8 * parallelism, iterations >= 1, salt length 8..=u32::MAX,
tag length 4..=u32::MAX, and password/secret/associated-data lengths <= u32::MAX.
Arena sizes and output capacity must be representable on the target platform,
including the H-prime byte-Vec isize::MAX bound. The claim is conditional on
normal successful allocation/execution: a successful scalar call returns the tag
specified by the encoded Argon2 model, whose RFC fidelity must undergo independent review.
H0 must use the original requested memory_kib; only arena geometry is rounded.

This is an agreed **target, not a discharged theorem**. Allocation/owning arena and caller contracts,
scalar pass/slice/lane traversal, finalization and public caller contracts still
require composition. Allocation-failure/error recovery, zeroization, timing,
cryptographic strength, SIMD and version 0x10 are outside this first target.

## Checked Slices

The checks establish agreement with the encoded mathematical definitions and
arithmetic/bounds safety under each function's preconditions. Rotation requires
`1 <= n <= 63`; geometry and indexing require valid parameters and positions.
The row pass, one-column helper, eight-column loop, and complete scalar G
composition are verified as separate, composing slices. BLAKE2b roots prove
one block-to-chaining-state transition, RFC tables, buffer append/flush, one
update step, and final-block padding/serialization. The production repeated
`update` loop now proves termination, arithmetic/bounds safety, byte accounting,
and existence of a finite trace of model update steps. It also establishes a
block-prefix semantic invariant: chaining state after all non-final full blocks,
the exact active pending bytes, and retention of the final full block. Finalizing
the resulting state agrees with a block-oriented digest model, using cumulative
byte counters and the final-block flag. Binary composition proves digest equality
for any two-part split, including empty parts, under the semantic contracts.
The initial chaining helper proves the RFC unkeyed parameter word for output
lengths 1 through 64. Its preconditions require
a valid buffer length and a total byte count representable in `u128`.
The whole model transition and indexed edge predicate are opaque; one-step
validity and pointwise prefix/final-edge lemmas control unfolding. The helper
uses `spinoff_prover` to isolate solver context, without changing the resource
limit or adding assumptions. The old diagnostic repro files have been removed.
Proven G remains unchanged.

These results are conditional on the encoded block model and caller preconditions.
The public constructor/update/finalize methods use a ghost-only closed state view,
preserving private fields. The real multipart wrapper and private prefixed helper
prove model agreement for arbitrary finite lists of parts: output parameter 1..=64
and total message length representable in `u128`. No trusted bodies or assumptions
were added. Production Drop/wiping remain unchanged and outside the checked
zeroization scope. Model fidelity still requires independent human review.
Boundary and partition tests are regression evidence, not the binary theorem's proof.
H-prime now agrees with the RFC-oriented length-prefix/digest-chain model for both
short and long branches. The model uses `ceil(T / 32) - 2` for long-output rounds;
the executable invariant proves that relation, exact output length and termination.
Explicit singleton slice bindings and prefix base-case facts resolved the prior VC.
The helper encodes four little-endian bytes directly; supported Vec copying and
a boolean debug assertion avoid adding assumed specifications for unsupported std
functions. No assumptions or increased limits were introduced.

H-prime requires `1 <= out_len <= u32::MAX`, `out_len <= isize::MAX` for the byte
Vec, and `4 + concat(parts).len() <= u128::MAX`. Claims are conditional on normal
successful allocation/execution in the standard collection model, not allocation
failure recovery or zeroization. Independent hashlib vectors use the RFC ceil-based
formula at output lengths 1, 32, 64, 65, 96, 97, 128 and 129 for message `abc`;
they are regression evidence, not independent review of the whole specification.
The theorem domain above is agreed; the H0 adapter and selected validation boundary
are now checked. The flat initialization loop is checked too. Remaining are full
hash/owning-arena caller contracts, allocation semantics,
scalar traversal/finalization and API composition.
A termination or resource
limit blocker at `--rlimit 30` requires a minimal reproducer and decomposition
analysis, not assumptions or a larger limit. Every proved slice must pass the
standalone `--no-cheating` gate and Cargo tests before synchronization into Edge.
The theorem about the successfully returned Argon2 tag remains incomplete until
H-prime, initialization/finalization, and hash traversal are composed and checked.

Core leaves and G are integrated into the hash path. Neither same-source
compilation nor leaf verification proves all hash-loop callers meet these
preconditions. The raw-field H0 helper now agrees with its ordered RFC message
and digest model: header words are p, tag length, requested m, t, version and type,
followed by password/salt/secret/ad length and contents. Each input length must fit
u32. The production adapter passes original memory_kib; independent hashlib tests
cover all algorithm IDs and requested m=35, while existing geometry tests also pass.
The real enum/Params adapter is now checked against explicit model algorithm/version
codes, tag length and unrounded memory. `Params::validate` proves its acceptance
predicate; `checked_h0` returns Ok exactly for valid parameters and bounded input
lengths, with an H0 digest matching the model. The production hash entry delegates
to this checked boundary. Canonical public types live in parameters.rs with their
existing root re-exports; the standalone recommended default remains unchanged.
Error precedence has regression tests, not a separate formal priority theorem.
These do not prove the entire hash function's callers, allocations or traversal.
The production flat initializer now proves the exact 72-byte seed
`H0 || LE32(column) || LE32(lane)`, H-prime(1024), little-endian 128-word decoding,
and first-two-block placement for every lane, preserving other words via its
prefix-write model. Both loops have decreases and checked native index arithmetic.
It requires lanes>0, lane_length>=2, total blocks <=u32::MAX, and exact mutable
word-slice length `128 * lanes * lane_length`. The real Memory/hash path delegates
to this helper; the orphan private slot accessor was removed. The separate owning
root imports and proves the actual Memory::initialize body with a closed ghost
word view under the same exact size/geometry conditions. Geometry additionally
proves blocks=lanes*lane_length and lane_length>=8 for valid inputs.

The successful-result shape of `Memory::zeroed` is now checked: `Ok` contains
exactly `128 * blocks` zero words. This uses the proposed `Vec::try_reserve_exact`
content-preservation mapping in a separate local vstd worktree, alongside the
existing trusted `Vec::new`/`resize` contracts. These are library assumptions,
not proofs of allocator implementation or guaranteed allocation success. The
constructor proof also makes the unchanged `Block::SIZE_WORDS` constants visible
to Verus. General accessors, Drop, recoverable allocation failure, and the full
geometry/allocation-to-caller chain remain outside the proof. No local application
`assume_specification`, trusted allocator body, reserve-policy change, or larger
limit was added. The candidate remains unmerged and requires custom-allocator
review and upstream approval. Remaining caller/allocation contracts and the
full Argon2 hash loop, SIMD memory safety/equivalence,
cryptographic security, machine-code timing, and zeroization are outside the
checked scope. Specification fidelity is a human obligation independent of
successful discharge. Verus/vstd, the solver, compiler, and translation semantics
remain trusted tooling, not verified components.

No exporter invocation is required. See [../README.md](../README.md) for
API, security, and testing boundaries. Ordinary GitHub Cargo checks do not run
Verus; the strict proof command above is a separate release gate.
