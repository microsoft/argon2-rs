# Cryptographic review: temporary secret lifetime

## Status and provenance

This is a historical engineering review and remediation record. An independent cryptographic audit is in progress, but it is not yet a Crypto Board approval. It must not be used to claim that the current release is certified.

- Initial source assessment:
  [`331cfd99a425c8cff1c3f0db326b2d895301c70f`](https://github.com/microsoft/argon2-rs/tree/331cfd99a425c8cff1c3f0db326b2d895301c70f).
- Temporary-owner/in-place-update remediation was committed in
  [`8bb088f8aea35f79e7432720ebabc2208259cc9a`](https://github.com/microsoft/argon2-rs/commit/8bb088f8aea35f79e7432720ebabc2208259cc9a).
  It is not an outstanding uncommitted fix.
- Subsequent proof restructuring and simplification changed the proof layout.
  The current theorem and reproduction guide are described in the
  [README](README.md#mathematical-proofs). Review the exact release revision;
  passing CI does not extend an old security review to new code automatically.

## Initial assessment

| Requested check | Source-level assessment at the initial revision |
| --- | --- |
| Secret-dependent mixing/BLAKE2b branches or instruction selection | No extra secret-content-dependent mixing schedule found; not a universal binary timing guarantee. |
| Additional secret-dependent SIMD shuffles, loads or stores | No secret-derived shuffle controls or extra content-indexed lookups found. |
| Constant-time stored-tag comparison | Not established: the crate returns raw tags and no consuming authentication application was supplied. |
| Application memory, iteration and concurrency caps | Not established: algorithm-validity checks are not deployment admission controls. |
| Secret copies outside arena wiping | Confirmed: explicit temporary buffers and sampled optimized stack copies were outside the original wiping coverage. |

Argon2d and the data-dependent phases of Argon2id intentionally select
secret-derived reference addresses. The initial revision's
[`Memory::read_write`](https://github.com/microsoft/argon2-rs/blob/331cfd99a425c8cff1c3f0db326b2d895301c70f/src/memory.rs)
also branched on that selected address. That historical function is not part
of the current source layout. BLAKE2b processing exposes input lengths.
Neither observation establishes an additional content-dependent mixing defect.

The original disposition was **insufficient evidence to approve all five
criteria**. The cleanup below addressed explicit temporary ownership, not
application safety or complete machine-state erasure. Board acceptance
depends on the board's criteria and deployment threat model.

## Finding and remediation

**Historical severity: LOW.** Uncovered copies were a secret-lifetime
hardening gap, not a demonstrated standalone information-disclosure
vulnerability. Exploitation would require a separate way to read process
memory or saved register context; no such primitive was established here.

The original arena and BLAKE2b destructors only covered their own storage.
By-value streaming state/buffer tuples, compression scratch, H-prime digests,
scalar block copies and SIMD round/segment state created additional copies.

The remediation:

- Changed BLAKE2b streaming and compression to mutate borrowed state in place.
- Added non-`Copy`, non-`Clone` byte, word and vector owners with volatile
  drop-time wiping in [src/wipe.rs](src/wipe.rs) and [src/simd.rs](src/simd.rs).
- Protected explicit H0, initialization/finalization, scalar/SIMD scratch,
  internal tags and partially constructed output.
- Kept caller-visible output intact; transferring an output allocation leaves
  an empty internal owner to drop.
- Updated the same-source functional contracts without substituting a
  non-wiping executable for verification.

The hashing API, output format, addressing, round schedules and dispatch
policy were preserved. Cleanup traverses fixed-size or public-length storage,
not secret-content-dependent schedules. Additional volatile writes have a
performance cost; retune deployment costs rather than assuming old throughput.

## Evidence and its limits

The historical validation record reported 39 runtime tests and one doctest,
with an allocation-size test excluded at that time. Those counts and that
exclusion are not the current release test inventory or instructions.
Current CI runs the full suite, including the allocation-size test.

Historical bounded inspection reported a BLAKE2b-update stack frame shrinking
from `0x2c8` to `0x38` bytes and sampled clearing stores in destructors/AVX2.
Complete reproducible compiler flags and binaries are not preserved in this
repository. Treat this as historical diagnostic evidence, not a portable
release-binary guarantee. Repeat binary inspection for the actual release
compiler/target when required by the threat model.

Current reproducible checks and release provenance are maintained in
[CONTRIBUTING.md](CONTRIBUTING.md):

1. RFC and independent reference-C vectors, backend agreement and boundary
   tests check functional behavior, not constant time.
2. Cleanup tests inspect live storage and observe wipe calls on normal/error
   returns and unwinding. They do not read freed memory or establish that all
   copies disappear.
3. Verus proves successful scalar output equality with a model. It does not
   prove `Drop`, volatile stores, SIMD, allocator implementation or timing.
4. A dependency appraisal or empty cargo-vet dependency graph is not a
   first-party security review.

## Residual limits and approval requirements

- Wiping owners erase designated live storage, not every move, returned-array
  copy, compiler spill, register or saved context.
- Destructors do not run after process abort, `panic=abort`, forced termination
  or a second panic during unwinding.
- Caller-owned passwords, secrets and tags remain the caller's responsibility.
- Source review and sampled disassembly do not prove constant time or complete
  erasure across compiler versions, targets and CPUs.
- Review the actual consuming application: use vetted constant-time tag
  comparison and audit decoding/error paths.
- Bound memory, passes, input/output lengths and concurrency. Algorithm-valid
  parameters can request nearly 4 TiB and 4,294,967,295 passes. Fallible
  allocation is not a denial-of-service policy.
- Independently review RFC/model fidelity and all unsafe/dispatch boundaries
  before making stronger cryptographic or deployment-safety claims.

The explicit temporary-owner gap was remediated within this scope.
Comprehensive remnant elimination, independent certification and
application-inclusive security approval remain unestablished.
