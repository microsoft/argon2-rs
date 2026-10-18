# Cryptographic review: temporary secret lifetime

## Scope and decision

The initial read-only review assessed `argon2-verus` 0.1.0 at commit
`331cfd99a425c8cff1c3f0db326b2d895301c70f`. The remediation described below is
an uncommitted change to that implementation.

| Requested check | Initial assessment |
| --- | --- |
| Secret-dependent mixing/BLAKE2b branches or instruction selection | No additional secret-content-dependent mixing schedule found. This is a qualified source-level assessment, not a universal binary timing guarantee. |
| Additional secret-dependent SIMD shuffles, loads or stores | No secret-derived shuffle controls or extra content-indexed lookups found. |
| Constant-time stored-tag comparison | Not established: this crate returns raw tags; no consuming authentication application was supplied. |
| Application memory, iteration and concurrency caps | Not established: algorithm-validity checks are not deployment admission controls. |
| Secret copies outside arena wiping | Confirmed: explicitly owned temporary buffers and optimized stack copies were outside the original wiping coverage. |

Argon2d and the data-dependent phases of Argon2id intentionally select
secret-derived reference addresses. The `r < c` branch in
[`Memory::read_write`](src/memory.rs) also depends on that selected address;
a literal claim of no secret-dependent branches would be incorrect.
BLAKE2b processing exposes input lengths. Neither qualification is a newly
discovered content-dependent mixing defect.

**Review disposition:** do not approve against all five criteria on the current
evidence. The remediation improves secret lifetime but cannot establish
application safety or complete machine-state erasure. Actual Crypto Board
acceptance depends on its criteria and the deployment threat model; this review
is not a certification or a reliable prediction of the board's decision.

## Confirmed finding

**Severity: LOW. Confidence: 10/10 for the existence of uncovered copies.**

This is a secret-lifetime hardening gap, not a demonstrated standalone
information-disclosure vulnerability. Exploitation requires a separate means
of reading process memory or saved register context while useful remnants
persist. No such disclosure primitive was established in this crate.

The original arena destructor and `Blake2b` destructor used volatile writes
and a compiler fence. They only covered their own storage. In particular:

- [`blake2b_update::update`](src/blake2b_update.rs) passed the chaining state
  and 128-byte buffer by value into `update_step`, then copied tuple results
  back. The buffer can contain password or optional-secret bytes.
- [`blake2b_compress`](src/blake2b_compress.rs) owned decoded message words,
  initial/round states and folded output arrays.
- [`blake2b_buffer::finalize_state`](src/blake2b_buffer.rs) owned padded input
  and final chaining-state copies.
- [`blake2b_long`](src/blake2b.rs) owned H-prime chain digests and partial
  output; initialization and finalization owned further derived buffers.
- Scalar block copying and mixing owned predecessor, reference, destination,
  XOR, row and column scratch arrays.
- SIMD compression owned persistent segment state, XOR scratch and gathered
  round arrays, in addition to compiler-generated spills.

Bounded inspection of the original optimized library found a `0x2c8`-byte
stack frame in BLAKE2b update, with buffer copies and no clearing before
return. AVX2 code also stored block state on the stack. This establishes
uncovered copies, not how long particular bytes remain after the full hash
returns.

## Required fix and implementation

Use in-place operations where copies are unnecessary, and attach cleanup to
ownership rather than placing wipes only at the end of successful functions.
End-of-function wipes alone miss `?` returns and panic unwinding.

### Shared cleanup owners

[`src/wipe.rs`](src/wipe.rs) defines non-`Copy`, non-`Clone` internal owners:

```rust
pub(crate) struct Bytes<const N: usize>(pub(crate) [u8; N]);
pub(crate) struct Words<const N: usize>(pub(crate) [u64; N]);
pub(crate) struct ByteVec(pub(crate) Vec<u8>);
```

Their destructors overwrite live storage through the existing volatile-write
and compiler-fence mechanism. `ByteVec::into_inner` transfers an intentionally
returned output allocation by swapping it out; the empty owner is then dropped.
It does not wipe caller-visible output before returning it.

### Changed code paths

| File | Necessary change implemented |
| --- | --- |
| [src/blake2b_update.rs](src/blake2b_update.rs), [src/blake2b_buffer.rs](src/blake2b_buffer.rs) | Change `update_step` to borrow and mutate `h`, `counter`, `buffer` and `buffered_len`; return only the consumed byte count. Eliminate the by-value streaming tuple. Protect padded input and final state with wiping owners. |
| [src/blake2b_compress.rs](src/blake2b_compress.rs) | Mutate chaining and round state in place. Protect decoded message and compression scratch with `Words`. Remove the separate round-state and folded-output copies. |
| [src/blake2b.rs](src/blake2b.rs) | Protect short digest, H-prime chain values, last digest and partially assembled output. Replacing a chain owner drops and wipes the old owner. |
| [src/block_g_fill.rs](src/block_g_fill.rs) | Protect both full-block XOR/permutation scratch arrays. |
| [src/block_g.rs](src/block_g.rs), [src/block_g_column.rs](src/block_g_column.rs), [src/block_primitives.rs](src/block_primitives.rs) | Protect gathered and permuted row/column arrays; borrow the permutation input instead of copying it into a parameter. |
| [src/memory.rs](src/memory.rs) | Protect scalar predecessor, reference and destination copies until they have been consumed or written back. |
| [src/memory_initialization.rs](src/memory_initialization.rs) | Protect H0-derived seeds, H-prime byte vectors and decoded blocks before placement into the arena. |
| [src/core_scalar_caller.rs](src/core_scalar_caller.rs), [src/core_impl.rs](src/core_impl.rs) | Protect H0 across arena-allocation failure and protect internal tags until copied into caller output. Protect SIMD final serialization. |
| [src/core_final.rs](src/core_final.rs), [src/block.rs](src/block.rs) | Protect lane-tail copies, final reduction and serialized bytes; add wiping destruction to `Block`. |
| [src/simd.rs](src/simd.rs) | Add non-copying owners for 128-/256-bit vector arrays, mutate round arrays by reference and iterate XOR scratch by reference. Wipe explicit round, XOR and segment-state storage on drop. |
| [verus/](verus/) | Import the cleanup types into affected proof roots and update same-source contracts for in-place mutations and owner fields. Do not substitute a separate non-wiping executable for verification. |

The public hashing API, tag format, parameter policy, addressing, round
schedules and CPU dispatch are unchanged. Cleanup walks fixed-size scratch
or public-length buffers and does not branch on their contents.
Additional volatile writes have a performance cost; deployment cost tuning
should be repeated rather than assuming previous throughput is unchanged.

## Validation

Validation covers three distinct properties:

1. Existing RFC known-answer, BLAKE2b/H-prime, streaming-boundary, scalar/SIMD
   differential and parameter-contract tests check unchanged output behavior.
2. Cleanup tests check live-storage overwriting and observe completed wipe
   calls from owners on ordinary return, error return and panic unwinding.
   Whole-hash tests check that temporary cleanup is wired into each available
   backend. Tests do not read deallocated or already-dropped storage.
3. Same-source Verus checks revalidate functional contracts after ownership
   and in-place changes. `Drop`, volatile writes, compiler-generated copies,
   SIMD and machine-code timing remain outside those functional theorems.

Completed on x86-64 with Rust 1.93.0 and the existing local Verus/vstd review
build `0.2026.10.07.89f8d65.dirty`:

```sh
cargo test --offline --locked --release --lib --test kat --test spec_contract \
  -- --test-threads=1 --skip unrepresentable_arena_is_rejected_before_allocation
cargo test --offline --locked --doc
cargo clippy --offline --locked --all-targets -- -D warnings
cargo fmt --all -- --check
VERUS_BIN=/path/to/compatible/verus bash tools/verify.sh
git diff --check
```

- Release tests: **39 passed, 0 failed**. One allocation-size test was
  deliberately filtered out to avoid resource-exhaustion testing in a shared
  environment. All available scalar, SSE2, SSSE3 and AVX2 backends were tested.
- Doctests: **1 passed, 0 failed**.
- Clippy, formatting and patch-whitespace checks: passed.
- All **19 Verus roots**: passed with zero errors. The whole-scalar caller
  root reports **201 verified, 0 errors**. The local vstd allocation contract
  remains a disclosed trusted dependency, not an allocator proof.
- Bounded inspection of the optimized non-test library confirms that the
  BLAKE2b update stack allocation is now `0x38` rather than the original
  `0x2c8` bytes. Input bytes are copied directly into the borrowed buffer, not
  into the old by-value buffer tuple. Sampled byte/vector destructors retain
  zero stores, and the AVX2 path retains explicit scratch clearing stores.
  This is evidence of this build's remediation, not exhaustive spill or
  register analysis.

## Residual limits and approval requirements

- Wiping owners erase their designated live storage. Rust moves, returned
  arrays, register allocation, spills and optimizer transformations can still
  leave other copies. This change **does not guarantee that every password
  byte, derived block or register is erased**.
- Destructors run on normal scope exit and Rust panic unwinding, not process
  abort, `panic=abort`, forced termination or a second panic during unwinding.
- Caller-owned passwords, optional secrets and returned tags remain the
  caller's responsibility. Output is deliberately retained for use.
- Source review and sampled optimized disassembly do not prove constant-time
  behavior or complete erasure across all Rust versions, targets and CPUs.
  Reassess actual release binaries and hardware for stricter requirements.
- Review the real verification application: use a vetted constant-time
  comparison over the complete expected tag and audit decoding/error paths.
  Test `assert_eq!` calls are not production authentication comparisons.
- Enforce memory, iteration, input/output-size and concurrency budgets before
  accepting untrusted hashing work. Valid library parameters can request
  nearly 4 TiB of memory and up to 4,294,967,295 iterations; checked allocation
  is not a denial-of-service policy.

Therefore the explicit temporary-owner gap is remediated within the stated
scope, but comprehensive remnant elimination and application-inclusive
security approval remain unestablished.
