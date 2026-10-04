# Security Reporting

Do not report suspected vulnerabilities in public issues or attach passwords,
tokens, private keys, or other sensitive data.

After private vulnerability reporting is enabled for the repository, use
[GitHub's private vulnerability report](https://github.com/optiklab/argon2-verus/security/advisories/new).
If that interface is unavailable, wait for a working private reporting channel;
do not post exploit details publicly. Enabling and testing this channel is a
pre-publication step in the release guide.

Include the package version or source revision, platform, CPU backend,
parameters, a minimal non-sensitive reproducer, and expected versus actual
behavior. Proof-contract defects, incorrect hashes, unsafe memory accesses,
unexpected side channels, and secret-lifetime defects are relevant reports.

## Guarantees

Selected scalar and indexing functions have same-source Verus contracts.
This is not an end-to-end Argon2, SIMD, timing, zeroization, or cryptographic
security proof. The specifications, compiler/verifier toolchain and caller
preconditions remain explicit trust boundaries.

Use Argon2id with deployment-appropriate parameters and a fresh random salt
for stored passwords. Validate resource limits before accepting attacker-chosen
parameters. Raw tags must be compared with an appropriate constant-time
comparison function supplied by the application.

Support and response-time commitments must be agreed before release; none are
promised by this preparation document.