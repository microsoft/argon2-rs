# Human audit map

Verus proves agreement with this model, not that the model is the RFC.
Review the definitions below against the linked documents. Comments on each
canonical function identify its RFC operation and section.

## Canonical definitions

| File / symbols | Meaning and reference |
| --- | --- |
| [mod.rs](mod.rs): `WORD_BITS`, moduli, mask, `trunc`, `rotate` | Fixed 64-bit words and low-32-bit truncation; [RFC 7693 section 2](https://www.rfc-editor.org/rfc/rfc7693.html#section-2), [RFC 9106 section 2](https://www.rfc-editor.org/rfc/rfc9106.html#section-2). The modulus literals are linked to `2^w` by checked equivalence lemmas. |
| [mod.rs](mod.rs): `blake2b_*` | IV/SIGMA, G, F, decoding, padding and unkeyed initialization; [RFC 7693 sections 2-3](https://www.rfc-editor.org/rfc/rfc7693.html#section-3). The model returns 64 serialized state bytes; the requested digest length controls initialization and caller truncation. |
| [digest.rs](digest.rs) | Recursive non-final compression and final digest, including empty input; [RFC 7693 section 3.3](https://www.rfc-editor.org/rfc/rfc7693.html#section-3.3). The initial-counter parameter also supports streaming composition. |
| [h_prime.rs](h_prime.rs) | LE32, V_i chain, 32-byte concatenation and both H-prime cases; [RFC 9106 section 3.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.3). |
| [initial_hash.rs](initial_hash.rs) | Enum/parameter mapping and H0 field encoding; [RFC 9106 section 3.2 step 1](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2). |
| [initialization.rs](initialization.rs) | Seeds, H-prime(1024), decoding and initial lane-block placement; [RFC 9106 section 3.2 steps 3-4](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2). |
| [mod.rs](mod.rs): `blamka`, `gb`, `permute`, row/column transforms, `fill_block_result` | P and G; [RFC 9106 sections 3.5-3.6](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.5). The optional old-block XOR belongs to section 3.2 step 6, not G itself. |
| [mod.rs](mod.rs): parameter/geometry/position/index functions | Requested versus rounded memory, valid positions and reference mapping; [RFC 9106 sections 3.1-3.4](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1). |

Some recursive functions remain in the canonical model: for example,
`blake2b_rounds_prefix`, `blake2b_nonfinal_blocks`, H-prime's `chain` and
`output_prefix`, and `initialized_prefix`. Their endpoints define the hash,
so they must be reviewed. Names containing "prefix" do not automatically
make a function irrelevant to RFC fidelity.

## Semantic dependencies still colocated with production

The following ghost definitions are also part of the human audit. Directory
placement does not exempt them from review:

| File / symbols | Meaning |
| --- | --- |
| [parameters.rs](../src/parameters.rs): `Algorithm`, `Version`, `Params` | API types used in the field mapping. |
| [core_address.rs](../src/core_address.rs): `address_input`, `zero_words`, `address_g`, `generated_address_block` | Independent-address generation, RFC 9106 section 3.4.1.2. |
| [core_segment.rs](../src/core_segment.rs): `Segment`, `valid`, `segment_start`, `independent`, `segment_random`, `segment_step`, `segment_prefix`, `slice_prefix`, `pass_prefix`, `traversal_prefix` | Scheduling and complete scalar arena transitions, RFC 9106 sections 3.2 and 3.4. Both addressing modes must be reviewed. |
| [core_primitives.rs](../src/core_primitives.rs): `uses_independent_addresses`, `xor_on_pass` | Addressing/XOR policy corresponding to ghost scheduling. Include algorithm/version/pass decisions in the audit. |
| [memory.rs](../src/memory.rs): `block_words`, `write_block`, `write_block_prefix`, `fill_result` | Flat-memory interpretation and placement used by the transition model. `write_block_prefix` is transitively semantic despite also supporting a loop invariant. |
| [core_final.rs](../src/core_final.rs): `final_xor`, `serialize_words` | Lane-tail reduction and LE64 serialization, RFC 9106 section 3.2 steps 7-8. |
| [core_scalar_caller.rs](../src/core_scalar_caller.rs): `scalar_tag_model` | Composition of H0, initialization, traversal, reduction and H-prime. This is the successful-return theorem's target. |

RFC 9106 specifies version `0x13`. Version `0x10` remains a compatibility
extension; check its version-dependent XOR policy against the historical
[Argon2 reference implementation](https://github.com/P-H-C/phc-winner-argon2).
Do not infer legacy-version certification from an RFC 9106 citation.

## Internal proof machinery

[proofs/specs.rs](../proofs/specs.rs) contains partial buffer/scatter/XOR
relations, loop-prefix transitions and progress/equivalence lemmas.
Other [proof files](../proofs/) hold streaming traces, arithmetic bounds and
composition lemmas. Canonical files do not import those modules.

Complete row/column semantics are defined directly in the canonical model.
`complete_rows` and `complete_columns` prove that the implementation's
eight-step loop relations equal them. `word_notation_equivalence` proves
the modulus/width, truncation and all-ones-XOR/complement identities.

These proof files still matter to proof soundness and verification
maintenance. "Internal" means they are not independent definitions of the
RFC algorithm, not that they are safe to ignore in every kind of audit.

## Limits

The theorem concerns forced-scalar successful returns under accepted input
and representability conditions. It does not prove allocation success,
allocator implementation, SIMD, runtime backend selection, CXX/FFI,
constant-time execution, zeroization or application resource limits.
Loop termination does not imply an acceptable time or memory budget.
