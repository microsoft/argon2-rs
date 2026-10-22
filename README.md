# argon2-rs

[![Rust checks](https://github.com/microsoft/argon2-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/microsoft/argon2-rs/actions/workflows/ci.yml)
[![Minimum Rust version](https://img.shields.io/badge/rustc-1.88%2B-blue.svg)](https://github.com/microsoft/argon2-rs/blob/main/Cargo.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/microsoft/argon2-rs/blob/main/LICENSE)

A dependency-free Rust implementation of the password hasher [Argon2 algorithm](https://github.com/P-H-C/phc-winner-argon2). It reproduces byte-level behavior of the reference C++ implementation that won the Password Hashing Competition (PHC).

It implements the existing Argon2 spec and contains an in-tree implementation of required BLAKE2b avoiding external dependencies; combines runtime-dispatched SIMD for performance with same-source [Verus](https://github.com/verus-lang/verus) verification of scalar Argon2, from H0 through the successful returned result (aka tag).

Proven machine-checked functional-correctness theorem stated as: for API-accepted inputs and parameters, if the forced-scalar caller is successful (aka returns `Ok(())`), its output equals the tag computed by the whole-hash model derived from the Argon2 specification.

The consolidated Cargo-Verus application proof passes 209 obligations with zero errors. SIMD paths are not covered by that theorem. See the [verification guide](verus/README.md) and [human audit map](specs/README.md).

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
the crate's `Params::DEFAULT`: Argon2id `0x13` with 19 MiB, two passes, and
four lanes. This is a convenience configuration, not security advice or an
RFC 9106 recommended profile. Memory is measured in KiB and rounded down to a
multiple of `4 * parallelism` blocks. Valid parameters require parallelism in
`1..=2^24-1`, memory of at least `8 * parallelism` KiB, and one or more passes.
Salt must be at least 8 bytes; tags must be at least 4 bytes. The input and tag
lengths must fit the algorithm's length fields and platform allocation limits.
Requires Rust 1.88 or newer and the standard library; `no_std` builds are not
supported.

## Security Boundaries

- **Addressing and timing:** Argon2i uses data-independent memory addressing;
  Argon2d uses data-dependent addressing; Argon2id uses independent addressing
  for the first half of pass zero, then dependent addressing. There is no
  blanket constant-time guarantee or machine-code timing proof.
- **Secret lifetime:** working memory, BLAKE2b owned buffer/state, and explicit
  secret-bearing byte, word and SIMD scratch owners are overwritten with
  volatile stores on `Drop`, including panic unwinding. Streaming BLAKE2b
  updates state in place; H0 fields are streamed without a plaintext heap
  concatenation. These wipes cannot be discarded as dead stores, but do not
  cover every compiler-generated copy, stack spill or register, and do not
  erase caller-owned passwords, salts, secrets, or returned tags. Cleanup
  cannot be relied on after process abort, `panic=abort` or termination.
  See the [temporary-lifetime review and remediation](SECURITY-REVIEW.md).
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
  remove alignment requirements, not size or bounds requirements. The wipe
  helper's volatile stores require live, exclusively borrowed elements.
  SIMD cleanup constructs all-zero integer vectors without requiring a
  particular runtime CPU feature.
  Differential tests are evidence, not a proof of these kernels or the wipe helper.

## Mathematical proofs

Run verification from this source checkout with the pinned upstream Verus
build described in [verus/README.md](verus/README.md):

```sh
cargo verus verify --manifest-path verus/Cargo.toml --locked
```

The separate, non-publishable proof package imports the same scalar source
files used by the production crate. It keeps Verus/vstd dependencies and the
verification Rust toolchain out of ordinary builds. The old 19 overlapping
roots are consolidated; targeted development uses `cargo verus focus` with
`--verify-module`, not
separate executable copies or a hand-maintained shell verification list.

The theorem composes parameter checks, H0, memory initialization, scalar G,
addressing, segment/slice/lane/pass traversal, final lane reduction, H-prime
and output copy. For accepted inputs, successful forced-scalar execution
returns the modeled tag. It does not guarantee successful allocation or
normal return. Legacy `0x10` behavior is retained, but RFC 9106 specifies
`0x13`; the distinction is explicit in the model audit map.

All formerly opted-out scalar loops have explicit decreasing measures.
Termination is not a bound on hashing time or an application resource policy.
The current consolidated application result is **209 verified, 0 errors**;
obligation counts are not coverage percentages and cannot be compared by
summing the overlapping historical roots.

Canonical definitions and exact RFC citations live in [specs/](specs/).
Internal partial-write, loop-prefix and streaming relations live in
[proofs/](proofs/). The [audit map](specs/README.md) also lists semantic
definitions still colocated with production: moving a helper does not make
it irrelevant if it defines the final result. Checked equivalence lemmas
connect full row/column passes and RFC word notation to the implementation.

The pinned upstream vstd includes the allocation contract merged in
[Verus PR #3094](https://github.com/verus-lang/verus/pull/3094); no local
patch is required. Standard-library contracts, compiler, solver and Verus
translation remain trusted. These functional proofs do not establish
allocator implementation/correctness, SIMD, runtime backend selection,
public-wrapper/FFI behavior, constant time, zeroization or cryptographic
strength. Independent review that the model faithfully expresses the RFCs
is still required.

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
checks portable ARM64 compilation, including test targets, with warnings treated
as errors. A build-only job is not an ARM64 runtime test,
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

`with_backend()` requests a backend for reproducible comparisons; if it is not
available on the current CPU, hashing falls back to scalar. Check
`Backend::is_available()` first when fallback is unacceptable. Measure optimized
builds with representative parameters on the actual target hardware. SIMD
capability, memory cost, allocator behavior, and CPU load affect results; this
README does not promise a universal speedup. The crate uses a
normal initialized allocation, without platform-specific huge-page requests.
## License

This crate is licensed under the MIT License. The complete license text is in
[LICENSE](LICENSE). The `0.1.0` package is prepared for crates.io, but
has not yet been published.