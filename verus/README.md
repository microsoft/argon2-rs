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
```

The matching source revision is
`4d4a4800490d53abe7433ed89b33ae855efce59e` in the Verus repository.
If a compatible binary release is unavailable, build that revision following
its BUILD.md with the pinned Rust toolchain and matching Z3, then set `VERUS`
to the resulting executable. Do not infer a downloadable release URL from the
version string alone. Build Verus in a separate checkout and shell so its Cargo
wrapper does not replace the ordinary toolchain used for this crate.
The current strict baseline is **29 verified, 0 errors** for the combined root,
including proof helpers, **4 verified, 0 errors** for the scalar root,
**5 verified, 0 errors** for the row-wise G helper root, and **7 verified, 0
errors** for the single-column helper root.
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
They do not establish permutation bijectivity, the eight-column orchestration,
or full compression G correctness. The row-wise pass and one-column helper are
verified as separate slices; the outer column loop remains unproved.

Core leaves are integrated into the hash path. Neither same-source
compilation nor leaf verification proves all hash-loop callers meet these
preconditions. BLAKE2b, the full hash loop, SIMD memory safety/equivalence,
cryptographic security, machine-code timing, and zeroization are outside the
checked scope. Specification fidelity is a human obligation independent of
successful discharge. Verus/vstd, the solver, compiler, and translation semantics
remain trusted tooling, not verified components.

No exporter invocation is required. See [../README.md](../README.md) for
API, security, and testing boundaries. Ordinary GitHub Cargo checks do not run
Verus; the strict proof command above is a separate release gate.
