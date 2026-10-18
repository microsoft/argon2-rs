# Same-source Cargo-Verus verification

This non-publishable proof package imports the actual scalar implementation
through [lib.rs](lib.rs). It replaces the 19 overlapping standalone roots.
The runtime crate remains dependency-free and retains Rust 1.88 support.
Edge uses the identical proof package without changing its GN/CXX build.
Cargo excludes nested packages from the runtime crate archive. Run these
verification commands from a repository checkout, not the crates.io archive.
The archive retains the annotated runtime source, specs and proof helpers.

## Pinned upstream toolchain

Use Verus commit `1888846b29c587f56d2a4c482e4b75ecd86f8543`, with its matching
Rust 1.99.1, vstd and Z3 4.16.0. [Cargo.toml](Cargo.toml) pins vstd to that
same upstream commit; [Cargo.lock](Cargo.lock) pins its dependencies.
[rust-toolchain.toml](rust-toolchain.toml) applies only inside this package.

The `Vec::try_reserve_exact` specification was merged upstream in
[Verus PR #3094](https://github.com/verus-lang/verus/pull/3094). No local
vstd patch is required. Like other standard-library specifications, the
allocation contract is still a trusted boundary; it does not verify the
allocator implementation or guarantee successful allocation.

Follow the pinned upstream [build instructions](https://github.com/verus-lang/verus/blob/1888846b29c587f56d2a4c482e4b75ecd86f8543/BUILD.md).
For a source build, from its `source` directory:

```sh
./tools/get-z3.sh
cargo build --release
cargo run --release -p cargo-verus -- build --release --manifest-path vstd/Cargo.toml
```

Put that build's `target-verus/release` directory on `PATH`, so both `verus`
and `cargo-verus` come from the pinned build. Do not replace the ordinary
project Rust toolchain with the verifier's toolchain.

## Commands

From the standalone or Edge Argon2 component root:

```sh
cargo verus verify --manifest-path verus/Cargo.toml --locked
```

From this `verus` directory, simply use `cargo verus verify --locked`.
The explicit manifest layout is intentional: ordinary `cargo build/test`
must not acquire a verification dependency or a higher MSRV.
The BLAKE2b `g_values` proof retains the established solver budget of 30
through a local verifier attribute; other proofs use the command's budget.
This lets the plain Cargo command succeed without a global resource flag.

Strict acceptance:

```sh
cargo verus verify --manifest-path verus/Cargo.toml --locked \
  --fwd-verus-args-to roots -- --no-cheating --rlimit 30
```

Targeted iteration:

```sh
cargo verus focus --manifest-path verus/Cargo.toml --locked \
  --fwd-verus-args-to roots -- --verify-module block_g_fill
```

Forward module filters only to the selected root, not vstd. A targeted
run is not the full acceptance gate. This upstream version rejects partial
selectors under `verify`; `cargo verus focus` isolates partial
results in a separate target directory; run unrestricted `verify` afterward.
Require successful exit and a positive verification summary. Cargo can
reuse cached verification, so use a fresh `--target-dir` for clean-gate or
controlled negative checks.

The standalone [compatibility launcher](../tools/verify.sh) delegates to
Cargo; it no longer enumerates or independently maintains proof roots.

## Coverage and audit boundary

The consolidated root includes the union of executable modules and proof
helpers imported by the old roots:

- BlaMka, GB/P, complete row/column passes and scalar block G.
- BLAKE2b compression, constants, buffering, streaming/multipart composition
  and both H-prime output-length cases.
- Parameter checking, H0, memory geometry and first-block initialization.
- Owned memory construction and scalar block updates.
- Address generation, reference selection and segment/slice/lane/pass traversal.
- Final reduction, serialization and the scalar caller's successful output.

`hash_into_scalar` proves that `Ok(())` implies equality with
`scalar_tag_model` for accepted inputs. The type/version model also preserves
legacy `0x10` behavior; RFC 9106 itself specifies `0x13`.

All formerly opted-out scalar loops have explicit decreasing measures.
There are no `exec_allows_no_decreases_clause` annotations in the maintained
source or proof package. Termination is not a latency bound or allocation
success guarantee.

The [human audit map](../specs/README.md) identifies canonical RFC definitions,
semantic dependencies still colocated with production, and internal helpers.
Partial-update relations live in [proofs/specs.rs](../proofs/specs.rs).
Complete-pass and notation-equivalence lemmas connect them to the canonical
model without weakening runtime contracts.

The current consolidated application result is **212 verified, 0 errors**.
This includes new named constants and equivalence obligations, not new
SIMD/FFI coverage. The pinned vstd build reports **2060 verified, 0 errors**.
Counts overlap across historical roots and are not coverage percentages.

SIMD, automatic backend selection, public wrappers, CXX/FFI, allocator
implementation, destructors/zeroization, timing and application admission
controls remain outside the theorem. RFC/model fidelity requires independent
human review even when all verification succeeds.
