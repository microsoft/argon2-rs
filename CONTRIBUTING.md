# Contributing and releasing

Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Do not
include real credentials or secret inputs in issues, tests or reports.

## Development checks

The runtime crate requires Rust 1.88 and has no external crates. Run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo +1.88.0 test --locked --release
```

Install the selected toolchain/ARM64 target before the corresponding checks:

```sh
rustup toolchain install 1.88.0 --profile minimal
rustup target add aarch64-unknown-linux-gnu
RUSTFLAGS="-D warnings" cargo check --locked --all-targets --target aarch64-unknown-linux-gnu
```

Build-only ARM64 validation is not a runtime test. Exercise each supported SIMD
kernel on capable hardware. See [reference tests](tests/reference/README.md)
for the independent C oracle and deterministic regeneration command.

For semantic changes, update the canonical spec and its RFC/source citation,
review model fidelity, and run the complete proof gate using the pinned
[verification guide](https://github.com/microsoft/argon2-rs/blob/main/verus/README.md):

```sh
cargo verus verify --manifest-path verus/Cargo.toml --locked \
  --fwd-verus-args-to roots -- --no-cheating --rlimit 30
```

Use the guide at the same checkout revision. For fresh release evidence, add
`--target-dir target/verus-release-check` before `--fwd-verus-args-to` with a
previously unused directory. Require a positive verification summary, not just
a cached Cargo success. Do not weaken contracts, introduce trusted assumptions,
skip failing tests, or raise solver limits simply to make a change pass.
Proof-only cleanup must preserve executable behavior and public specifications.

## Appraisal and audit tools

These are different kinds of evidence, not interchangeable security seals.

### cargo-aprz

[cargo-aprz](https://github.com/microsoft/ox-tools/tree/main/crates/cargo-aprz)
collects published-crate/repository metrics and evaluates an appraisal policy.
It does not prove cryptographic correctness. Record the tool version, policy,
report date and data freshness with each report. New crates may be flagged for
limited age, downloads, release history or community evidence; those signals
cannot honestly be fixed with metadata or tests.

After publication and registry/docs indexing, an operator can use:

```sh
cargo aprz --version
cargo aprz crates argon2-verus@0.1.0 --ignore-cached \
  --json target/aprz-0.1.0.json --html target/aprz-0.1.0.html
```

These options were checked against cargo-aprz 1.0.0. Check the installed
version's help when upgrading; appraisal policies and metrics can change.
Its unmodified default policy labels scores of at least 70 as low risk,
subject to high-risk gates such as serious advisories. It awards points for
age (six months/one year), adoption and a stable `1.x` release. Do not bump
the version prematurely or manufacture activity/downloads to earn those points.

| Signal | Current evidence or remaining work |
|---|---|
| CI, Clippy, API documentation and examples | Maintained and checked in this repository. |
| Functional regression evidence | RFC vectors, 168 pinned-reference vectors, backend tests and scalar proofs; not a coverage percentage. |
| Measured runtime coverage | No published coverage measurement is claimed; measure it before reporting a percentage. |
| Unsafe code | Deliberate SIMD/wipe boundaries remain; reducing a metric must not hide or weaken these boundaries. |
| Ownership, adoption and release history | Verify owners after publication; maturity must develop through genuine maintenance and use. |
| External audits | Require actual reviewers, exact versions and a consumer trust decision. |

Review every finding and missing data source. Do not suppress advisories,
unsafe code, absent coverage, or immaturity merely to obtain a low-risk label.
Do not fabricate coverage or interpret proof-obligation counts as coverage.
External coverage services and authenticated API access require maintainer
approval; do not put tokens in repository files or command arguments.

Publishing accurate metadata, reproducible tests, useful rustdoc, supported
toolchains, security reporting and review evidence improves assessability.
No appraisal result for the unpublished crate is claimed here.

### cargo-vet

From a repository checkout, install the CI-pinned tool and run its dependency
gate (the audit store is not included in the runtime crate archive):

```sh
cargo install cargo-vet --version 0.10.3 --locked
cargo vet --locked
```

The repository's `supply-chain/` store has no fabricated audits, exemptions,
publisher trust entries or imported approvals. The first-party root is
explicitly marked `audit-as-crates-io = false`. With no runtime/dev dependencies,
a passing check only establishes that there are no third-party dependencies
in that graph requiring audits. It does **not** audit Argon2 itself.
The separate Verus package and tool-installation dependency graphs are outside
this gate; the verifier, solver, standard-library contracts and compiler remain
trusted tools/boundaries, not audited dependencies by implication.

For downstream adoption, an auditor must inspect the **published version's
exact source**, assess the applicable criteria, and record a genuine
version-specific audit in an audit store that the consumer explicitly trusts.
Only after that review should the auditor use `cargo vet certify`.
Never certify an unpublished or unreviewed version just to satisfy CI.
An exemption or trusted-publisher rule is not a completed source audit.

The built-in [safe-to-deploy criterion](https://mozilla.github.io/cargo-vet/built-in-criteria.html)
does not require a complete cryptographic logic review. For this crate, seek
additional expert review of RFC/model fidelity, scalar/SIMD behavior,
unsafe-load/store and CPU-dispatch preconditions, secret lifetime, and the
consuming application's comparison and resource policy. State target/compiler
coverage and residual limitations. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md)
for historical evidence, not an independent audit certificate.

See the official [first-party code](https://mozilla.github.io/cargo-vet/first-party-code.html)
and [recording audits](https://mozilla.github.io/cargo-vet/recording-audits.html)
guides. Each consumer decides which auditors and criteria to trust.

## Release checklist

Publication and repository visibility are separate approvals. Do not run
publishing, tagging or ownership-changing commands without release approval.

1. Confirm the crate name, publishing authorization, initial owner, intended
   organization/team co-owners and recovery arrangements. Check availability
   again immediately before publication; an absent registry entry is not a
   reservation. Never place registry credentials in source control.
2. Resolve findings from code, license/provenance and security review. The
   original port's precise upstream revision was not recorded; the pinned
   regression oracle in [NOTICE](NOTICE) must not be presented as that history.
   Recover provenance from original records if available; otherwise retain the
   explicit limitation and obtain the responsible maintainers' acceptance.
3. Keep the release marked `Unreleased` until approval. Then set the actual
   release date in [CHANGELOG.md](CHANGELOG.md), check the package version and
   documentation, and commit the reviewed release contents. Update the package
   test path in CI if the version changes.
4. Run all development checks, fresh full Verus verification, reference-vector
   regeneration, `cargo vet --locked`, and the platform CI matrix on that exact
   commit. Review any unavailable backend/target evidence explicitly.
5. From a clean tree, run `cargo package --list --locked` and
   `cargo publish --dry-run --locked`. Inspect the archive for expected source,
   tests, licenses and documentation and absence of secrets/local files.
   Test the unpacked artifact, not only the checkout:

   ```sh
   cd target/package/argon2-verus-0.1.0
   cargo test --locked --release
   RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
   ```

6. With explicit approval, tag the exact reviewed commit as `v0.1.0`, publish
   that clean tree, and create release notes linking the commit, CI evidence,
   proof guide and known limitations. Ensure the archive's
   `.cargo_vcs_info.json` identifies the same commit.
7. Verify registry owners using `cargo owner --list argon2-verus` and add only
   the approved co-owners. Verify docs.rs renders the release, links work, and
   a clean consumer can build the published version with Rust 1.88.
8. Run cargo-aprz against the published version after indexing. Arrange the
   independent, version-specific cargo-vet/cryptographic reviews above.
   Report outstanding findings rather than promising a risk score.

There is deliberately no automatic publish-on-push workflow. Credentials,
ownership, release approval, tags, publication, external audits and service
configuration are operator responsibilities, not outcomes of a local test run.
