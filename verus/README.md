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

Definitions reside in [../specs/mod.rs](../specs/mod.rs), imported as `specs`
by both roots. Contracts use `cfg_attr(verus_keep_ghost, verus_spec(...))`;
ghost imports and helper invocations use `cfg(verus_keep_ghost)`. There is
only one canonical body for each executable leaf.

## Running

Obtain a compatible [Verus release or source build](https://github.com/verus-lang/verus)
and its matching vstd, Rust toolchain, and Z3 solver. The known local baseline
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
```

The matching source revision is
`4d4a4800490d53abe7433ed89b33ae855efce59e` in the Verus repository.
If a compatible binary release is unavailable, build that revision following
its BUILD.md with the pinned Rust toolchain and matching Z3, then set `VERUS`
to the resulting executable. Do not infer a downloadable release URL from the
version string alone. Build Verus in a separate checkout and shell so its Cargo
wrapper does not replace the ordinary toolchain used for this crate.
The current strict gate reports **33**, **8**, **11**, **11**, **13**, **21**,
**18**, and **8 verified, 0 errors**, respectively, for the combined, scalar,
row, one-column, eight-column, full-G, BLAKE2b-block, and BLAKE2b-table roots.
The BLAKE2b buffer/update-step/finalize root reports **23 verified, 0 errors**.
The production update/streaming-composition root reports **41 verified, 0 errors**.
The public multipart/prefixed API and H-prime root reports **55 verified, 0 errors**.
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

## Guarantees And Limits

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
The remaining order is an explicit theorem-domain
decision, and only then scalar hash-level composition. A termination or resource
limit blocker at `--rlimit 30` requires a minimal reproducer and decomposition
analysis, not assumptions or a larger limit. Every proved slice must pass the
standalone `--no-cheating` gate and Cargo tests before synchronization into Edge.
The theorem about the successfully returned Argon2 tag remains incomplete until
H-prime, initialization/finalization, and hash traversal are composed and checked.

Core leaves and G are integrated into the hash path. Neither same-source
compilation nor leaf verification proves all hash-loop callers meet these
preconditions. H0 composition, the
full Argon2 hash loop, SIMD memory safety/equivalence,
cryptographic security, machine-code timing, and zeroization are outside the
checked scope. Specification fidelity is a human obligation independent of
successful discharge. Verus/vstd, the solver, compiler, and translation semantics
remain trusted tooling, not verified components.

No exporter invocation is required. See [../README.md](../README.md) for
API, security, and testing boundaries. Ordinary GitHub Cargo checks do not run
Verus; the strict proof command above is a separate release gate.
