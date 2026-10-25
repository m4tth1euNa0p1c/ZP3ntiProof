# HORIZON — provisional M3 cryptographic design

Research version of October 17, 2026. This profile is distinct from the
existing zk-MCP wire format and from the RISC Zero proofs. Its demonstration
effect is `record_claim_authorization`, a simulated record of a decision. It
triggers no payment and demonstrates no legal right to compensation.

## 1. Verified question and trust boundaries

An expert attests a private amount `a`, a delegation authority a private limit
`c`. The holder wants to show that the amount respects a bound and does not
exceed the limit. The verifier sees the satisfied relation and the public
metadata, without seeing the values or their openings in the private modes.
The policy is public. The issuer remains responsible for the truth of the
fact: a correct proof over an erroneous expert assessment remains possible.

The authorities each construct or control the commitment to **their own
authoritative fact**. They do not blindly sign a point brought by the
requester. The exchange of openings with the holder requires a secure channel.
The laboratory uses fixtures and keys generated with system randomness; it
demonstrates neither acquisition of external facts nor hardware protection of
the keys.

The amount/limit roles have distinct authorized keys in a verifier registry.
Both attestations must target the same tenant, subject, currency, exponent,
version, period and holder key. The expected operation, case, audience and
policy come from the verifier, not from the proof.

## 2. Relation and exact integer bounds

Use the library's standard `PedersenGens::default()` generators:

```text
A = a·G + r_a·H               C = c·G + r_c·H
U = A − G                   D = C − A
u = a − 1                   d = c − a
u,d ∈ [0, 2^32 − 1]
U = u·G + r_a·H             D = d·G + (r_c − r_a)·H
```

The aggregated `RangeProof` argument covers the two **recomputed** commitments
`[A − G, C − A]`, in that order, with 32 bits per value. It follows that:

```text
1 ≤ a ≤ 2^32
a ≤ c ≤ a + 2^32 − 1 ≤ 2^33 − 1
```

This is not the relation `a,c < 2^32`. In particular `a = 2^32` is permitted.
The API uses `u64` and checked subtractions before conversion. The issuance
bounds must coincide exactly with this interpretation.

The [Ristretto group order](https://doc.dalek.rs/curve25519_dalek/scalar/index.html)
is `q = 2^252 + 27742317777372353535851937790883648493`. Our bound
`2^33 − 1 < q` excludes a wraparound modulo `q` in the integer sum `a+d`, under
the binding of the commitments and the bounds above. External openings are
canonical scalars; silently reducing an arbitrary encoding modulo `q` on
receipt would create multiple encodings, which must be prohibited.

The verifier constructs the derived commitments from the signed points. It
refuses any substitution of commitments, inversion of roles or change of
generators. The signature covers the original commitment and its metadata.
This composition uses an existing proof and the standard homomorphism of
commitments; it does not create a homemade cryptographic primitive.

## 3. Attestations, challenge and serialization

The typed schema carries, for each attestation: profile domain/version, role,
issuer identifier, tenant, case subject, `currency = EUR`, `exponent = 2`,
business version, holder public key, validity start/end and Ristretto
commitment. A strictly verified Ed25519 signature protects the complete
canonical encoding. Keys are chosen from the local registry; a key present in
the attestation does not elevate the issuer's rights. Since 25 October 2026
(H13) the registry may list revoked issuer keys (`revoked_public_keys_hex`,
absent in older registries) and two separate issuer adapters produce the
attestations from a JWS expert report and a signed delegation ledger line; see
[ISSUER_PROVENANCE_2026-10-25.md](ISSUER_PROVENANCE_2026-10-25.md).

The challenge contains at minimum tenant, client, audience, exact action,
operation, object, subject, policy identifier/version, trust epoch,
unpredictable nonce and deadlines. The presentation mode is also bound. The
application compares the whole against the challenge it issued. The
domain-separated, unambiguous bytes are common to the prover and the verifier;
input is bounded to 64 KiB, unknown fields are rejected, cryptographic sizes
are exact and integers are interpreted without floating point.

[Merlin transcripts](https://merlin.cool/use/passing.html) allow the
application domain and the public messages to be bound to the protocol. Use
distinct labels for the static relation, the session relation and the holder
signature. Never reuse proof randomness as a nonce or as a key.

## 4. Three comparable paths

| Mode | Private relation | Fresh authorization | Reuse |
|---|---|---|---|
| A — `challenge_bound` | RangeProof with attestations and complete challenge in the transcript | Holder signature over the presentation and the challenge | New proof for each challenge |
| B — `reusable` | Same RangeProof, transcript bound to the immutable attestations and the profile | Holder signature binding the complete proof/attestation hash and the complete challenge | Reusable static proof; authorization never reusable |
| Public — `disclosure` | Openings `(a,r_a,c,r_c)` disclosed; commitments and same bounds verified directly | Same key-possession and context check | Permitted only if the policy accepts disclosure |

Mode B demonstrates fresh control of the **holder key**, not fresh knowledge
of the secret values at each presentation. The static proof already established
knowledge of satisfying openings when it was created. This distinction is
acknowledged and testable.

Selector C is not a fourth primitive: it is a local policy that allows or
forbids these paths. If confidentiality is required, the public mode is
refused. If reuse is forbidden, B is refused. Unavailability of the proving
engine must never automatically lead to disclosure or simulation.

The fresh signature covers the hash of the immutable set, the mode, the proof
or the openings depending on the mode, as well as the entire challenge. It is
excluded from its own hash to avoid a circular definition. The signature of
both authorities is always verified over the exact bytes used.

## 5. Verified cache and mutable state

The first pass fully verifies signature, relation and context. An optional
cache may remember only the success of **the immutable relation**, under a key
covering the complete proof/attestation bytes, profile, parameters, verifier
version, policy and trust registry. A cache key is computed locally; the
client's `verified=true` declaration is never a trusted input.

At each presentation, re-verify the holder's fresh signature, the expected
challenge, policy, trust epoch, available revocations and temporal validity.
Deadlines are rechecked after any wait before dispatch, as is the start bound
`not_before_ms`: a clock rollback below the facts' validity must block. The
verified result carries the maximum of the start dates and the minimum of the
end dates of the challenge and the sources. A cache does not make old facts
current. The complete initial cost, hit rate, invalidations and memory
consumption must be counted; a hit must not be presented as a new complete
cryptographic verification.

The operational verifier durably retains nonces and reserved operations, with
atomic consumption and reconciliation of ambiguous errors. These properties
belong to storage and the target, not to Bulletproofs. The limit is **per
operation**; it means neither a remaining budget nor absence of double payment.
A consumable limit would require an authoritative ledger and an additional
atomic update.

## 6. Confidentiality and assumptions

Values and openings remain private in A/B with respect to the cryptographic
verifier. The prover and the issuers who process these values know them. The
original commitments, signatures, subject, issuers, periods, holder key, policy
and public context are visible. Reusing the same attestations allows
presentations to be correlated, even with a fresh proof: **no unlinkability is
promised**.

Modifying the signed points to rerandomize them would break their
authentication without an additional binding argument. The laboratory does not
make this extension. Repeated threshold questions can also reveal information
about a value; the policy must limit what it asks.

The discrete-logarithm assumption and the transcript/signature properties
remain necessary. Neither this elliptic profile nor Ed25519 is post-quantum.
The laboratory is not audited. It does not prove the security of the holder's
terminal, real-time global non-revocation, the truth of the expert data or
automatic regulatory compliance.

## 7. Acceptance criteria for the experiment

Tests must cover zero, amount equal to the limit, `2^32`, `2^32+1`, difference
`2^32−1`, difference `2^32`, negative subtraction, non-canonical scalar
encoding, invalid point, truncated proof and altered proof. Test separately the
authority and holder signatures, inverted roles, unknown registry, mixed
subject/currency/period, different audience or action, replaced nonce, obsolete
policy or epoch, expired challenge and forbidden disclosure. Any error before
authorization must produce zero external effects.

The prover and verifier processes may be separated; the private verifier
receives only public objects, proof and configuration. Verification outputs
contain neither values nor openings. The public mode is explicitly
identifiable to avoid including it in a confidentiality measurement.

Measure separately parameter generation, issuance, proof, fresh signature,
complete verification, cache hit, serialization and simulated effect. Keep raw
samples, CPU/threads, version/lockfile, RSS and total size on the wire. A proof
of two 32-bit ranges has an expected algebraic size of 672 bytes with this
library's format; this number excludes commitments, signatures, metadata and
JSON/hex encoding, which must actually be measured.

A future Vega/Spartan circuit would be relevant if the issuers cannot change
their documents, or if signatures and identities must remain private. It would
then be necessary to constrain hashing, signatures, parsing, joins, bounds and
session binding, then compare the complete statement. A successful RangeProof
test does not validate that future circuit and demonstrates no general gain
over Vega.
