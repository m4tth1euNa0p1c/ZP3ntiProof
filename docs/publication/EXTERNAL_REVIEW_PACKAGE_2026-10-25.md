# H15 — Package for an independent cryptographic review

Date: 25 October 2026. Status: **package assembled by the project; the review
itself has not taken place. H15 stays open until an independent reviewer,
unrelated to the authors and to the agents that reviewed this code, reports.**
Backlog entry `H15`. This document only tells a reviewer where everything is,
what the project claims, what it does not claim, and which objections remain
open with the experiment that would settle each.

## 1. What is submitted for review

| Item | Location | Notes |
| --- | --- | --- |
| Relation and bounds | [FORMAL_STATEMENT](../horizon/FORMAL_STATEMENT.md), [CRYPTOGRAPHIC_DESIGN](../horizon/CRYPTOGRAPHIC_DESIGN.md) | `0 ≤ a − 1 < 2^32`, `0 ≤ c − a < 2^32` over derived commitments `A − G`, `C − A`; the verifier derives both from the signed commitments |
| Manuscript | [whitepaper](../whitepaper/whitepaper.pdf), [circuit validation supplement](../whitepaper/circuit-validation.pdf), [validation record](../whitepaper/validation.json) | English rebuild of 24 October 2026; experimental version 1 |
| Reference implementation | `labs/horizon/proof/src/lib.rs` (relation, encodings, issuance, verification), `main.rs` (JSONL worker) | Rust 1.93, pinned `bulletproofs 5.0.0`, `curve25519-dalek 4.1.3`, `ed25519-dalek 2.2.0`, `merlin 3.0.0`, `rand 0.8.6`, `sha2 0.10.9` |
| Controller and adapters | `packages/horizon-demo/src/{store,tool,server,worker,target,issuers,types}.ts`, `packages/proofkit-sdk/src/index.ts` | Authorization state machine, remote target client, issuer adapters, SDK contract |
| Public fixture | `tests/fixtures/horizon/public-presentation.json`, `manifest.json` | A public presentation with its expected challenge, registry and policy; no witness, no private key |
| Adversarial test suites | `labs/horizon/proof/src/{tests,binding_tests,issuer_tests}.rs` (20 tests); `tests/horizon/{firewall,binding,remote-target,issuers,mcp,stdio-budget}.test.ts` (42 tests) and `tests/horizon/stats.test.mjs` (11 statistics tests), 53 in `npm run test:horizon` | Each dated document below lists its cases, codes and counters |
| Dated evidence | [VERIFIER_BINDING_TESTS](../horizon/VERIFIER_BINDING_TESTS_2026-10-25.md), [REMOTE_TARGET](../horizon/REMOTE_TARGET_2026-10-25.md), [ISSUER_PROVENANCE](../horizon/ISSUER_PROVENANCE_2026-10-25.md), [SECURITY_REVIEW](../horizon/SECURITY_REVIEW.md), [EXPERIMENT_LOG](../horizon/EXPERIMENT_LOG.md) | Includes mutation checks and the internal agent reviews with their findings |
| Threat models | [laboratory](../horizon/THREAT_MODEL.md), [production, NO-GO](PRODUCTION_THREAT_MODEL_2026-10-25.md) | |
| Claims register | [CLAIMS](CLAIMS.md) | What may and may not be said; P13 "post-quantum" is false for this profile |

## 2. Domains, encodings and parameters

| Element | Value | Where |
| --- | --- | --- |
| Profile identifier | `horizon-range-v1` (also the Merlin transcript label) | `lib.rs` `PROFILE`, `transcript` |
| Transcript messages | `evidence` ← `horizon/evidence-pair/v1` message; `mode` ← `challenge_bound` or `reusable`; `challenge` ← `horizon/challenge/v1` message (challenge-bound only) | `lib.rs` `transcript` |
| Message framing | `domain ‖ 0x00 ‖ serde_json(value)`, typed JSON in Rust declaration order, no maps, no floats, unknown fields rejected, 64 KiB bound | `lib.rs` `message` |
| Signature domains | `horizon/issuer-attestation/v1` over the attestation body (issuers); `horizon/holder-authorization/v1 ‖ 0x00 ‖ serde_json(digest)` where `digest` is the lowercase hex SHA-256 of `horizon/presentation/v1 ‖ 0x00 ‖ serde_json((profile, evidence, challenge, payload))`, that is a JSON-quoted hex string (holder) | `lib.rs` `signed`, `holder_message`, `check_signature`; mirrored byte-exact in `tests/horizon/binding.test.ts` |
| Controller domains | `horizon/audit/v1` (chained audit), `horizon/issuance-request/v1` (holder's issuance request), `horizon/delegation-ledger/v1` (ledger source) | `store.ts`, `issuers.ts` |
| Generators | `PedersenGens::default()`, `BulletproofGens::new(32, 2)`, fixed, process-wide, not selectable | `lib.rs` |
| Proof encoding | exactly 672 bytes, lowercase hex, canonical scalars; `(n, m) = (32, 2)` fixed; other 672-byte shapes refused algebraically | `lib.rs` `range_verify`; [binding tests §2](../horizon/VERIFIER_BINDING_TESTS_2026-10-25.md) |
| Points and scalars | Ristretto compressed, decompression required; scalars canonical; hex must be lowercase and of exact length | `lib.rs` `point`, `scalar`, `decode` |
| Keys | Ed25519, `verify_strict`, small-order keys refused (`WEAK_KEY`); registry keys verifier-local; revocation list canonical hex | `lib.rs` `key`, `verify` |
| Randomness | `OsRng` for blindings (`issue`, fixture), nonces (fixture), and the prover/verifier calls of the pinned Bulletproofs API | `lib.rs`; no RNG in the verifier's decision path other than the library's own |
| Worker I/O | one JSON line per request, 64 KiB bound, `deny_unknown_fields`, errors as `anyhow` context chains | `main.rs` |

Observation for the reviewer: the worker's JSON **output** sorts keys
alphabetically (`serde_json::Value`), while signatures and the transcript
cover the typed declaration order. The verifier re-serializes typed structs,
so interoperability holds; any independent holder or issuer implementation
must reproduce the declaration order (the TypeScript tests contain a
byte-exact mirror checked against the worker's deterministic signatures).

## 3. Assumptions the project makes

1. Discrete logarithm in the Ristretto group (Pedersen binding, Bulletproofs
   soundness); Fiat–Shamir in the Merlin transcript model; Ed25519 EUF-CMA.
   None is post-quantum.
2. The pinned upstream libraries implement what their documentation states;
   no local modification of `bulletproofs`, `curve25519-dalek`,
   `ed25519-dalek` or `merlin`.
3. Issuers sign only facts they validated; the proof covers the relation over
   what is attested, not the truth of the claim.
4. The verifier's registry, policy, clock, storage and binary are trusted;
   the agent, transport and presentations are hostile.
5. The holder knows both openings; this is not a multiparty computation.

## 4. What is explicitly not claimed

Post-quantum security; anonymity or unlinkability (commitments, holder key
and reused proofs are stable identifiers); side-channel or memory-erasure
guarantees; RNG quality beyond the operating system's; truth of attested
facts; any Vega comparison or record; production readiness (see the
production threat model); regulatory compliance.

## 5. Open objections and their falsification experiments

O1 to O2 and O4 to O13 come from the internal agent reviews of 17 and
25 October 2026 and from the limits sections of the dated documents; O3 is
raised by the package author. An internal review does not close any of them;
the reviewer is asked to confirm, refute or extend each.

| # | Objection | Current state | Experiment that would settle it |
| --- | --- | --- | --- |
| O1 | Soundness of the two-range relation depends on the fixed `(n, m)` and derived-commitment layout; a 672-byte proof of another shape passes the length gate and is refused only by the fixed `n = 32`, `m = 2` verification (Merlin domain separation and exactly two derived commitments) | Tested: `(64, 1)`, `(16, 4)`, `(8, 8)` refused ([binding tests](../horizon/VERIFIER_BINDING_TESTS_2026-10-25.md)) | Independent derivation that no `(n, m)` with `n·m = 64` and no generator subset yields an accepting transcript for a false statement |
| O2 | Refused bundles do not consume the nonce; no attempt counter | Documented design; capacity caps only | Decide whether a refusal must consume the nonce; test lock-out behaviour under concurrent refusals |
| O3 | Holder signature covers the JSON-quoted hex digest of the bundle, not the bundle bytes (`horizon/presentation/v1` digest, then `horizon/holder-authorization/v1`) | Second-preimage resistance of SHA-256 assumed; raised by the package author, not by a prior review | Confirm the two-level domain separation introduces no cross-protocol reuse |
| O4 | Source documents act as bearer documents for issuance (JWS report, ledger line) | Mitigated: holder proof of possession, single use per document, validity cap; residual recorded; single use is in memory per adapter instance (a restart re-opens every document) and a re-signed report with identical facts issues again ([issuer provenance](../horizon/ISSUER_PROVENANCE_2026-10-25.md)) | Issuance contract naming the holder, or authority-side request policy; durable single-use store; test with a stolen document across a restart |
| O5 | Unauthenticated sandbox target over plaintext HTTP: a forged `recorded` answer yields `COMPLETED` without a durable record; `bundle_hash` in the audit view | By design in the laboratory; H17 NO-GO ([remote target](../horizon/REMOTE_TARGET_2026-10-25.md)) | mTLS experiment of the production threat model, section 4 |
| O6 | Reconciliation semantics: `fenced ⇒ REJECTED` relies on the target's single-connection `BEGIN IMMEDIATE` transactions | The internal review found no second-effect path in the sandbox; multi-process target not exercised; the target's attempt counter can under-count when a failure occurs between commit and log | Two target processes on one SQLite file under contention; a real target contract |
| O7 | JSON parser differentials (`JSON.parse` last-duplicate-wins) and Node's non-strict Ed25519 verification on the issuer side | The project believes exploitation needs a second issuance of the same bytes, which in-memory single use refuses only within one adapter instance; this belief is untested | Fuzz the adapters with duplicate keys, BOM, unicode escapes; compare with a strict parser; test across an adapter restart |
| O8 | Metadata leakage and linkability | Documented, not mitigated | Formal leakage model per presentation mode |
| O9 | Clock trust: controller and target clocks, no authenticated time | Rollback test exists for the controller; target checks `expires_at_ms` by its own clock | Skew experiments; authenticated time source |
| O10 | Memory hygiene: openings and secrets not zeroized, no side-channel review | Not evaluated | Review of the pinned libraries' constant-time properties as used; zeroization audit |
| O11 | A consumed or refused business operation can be authorized again from a fresh or restored controller database; the target's idempotency key and version precondition are then the only barrier | Documented ([remote target](../horizon/REMOTE_TARGET_2026-10-25.md), [production threat model](PRODUCTION_THREAT_MODEL_2026-10-25.md) section 4) | Restore drill comparing the target's record set before serving; decide whether refused operations may be reissued |
| O12 | The audit chain can be rewritten entirely by the disk operator | Documented ([SECURITY_REVIEW](../horizon/SECURITY_REVIEW.md)); no external anchoring | WORM storage or external timestamping experiment |
| O13 | Issuer cross-role and cross-domain signatures (the amount authority signing a cap body, an authority signing under the holder domain) are covered by construction, not by a test, because the fixture discards issuer secrets | Documented ([binding tests](../horizon/VERIFIER_BINDING_TESTS_2026-10-25.md)) | Tests with issuer secrets held by the test, or an independent reading of `verify`'s per-role key selection |

## 6. How to run what is submitted

```sh
npm ci --ignore-scripts
node scripts/cargo.mjs test --manifest-path labs/horizon/Cargo.toml --locked
npm run horizon:build
npm run test:horizon
npm run test:proofkit
node scripts/horizon-fixture.mjs           # verifies the public fixture, no live authorization
npm run agent:check:full                   # fixed validation profile, report under .tools/agent-sessions/
```

Mutation checks (temporarily weakening a guard and observing which tests
fail) are described in each dated document; they are not automated.

## 7. What this package is not

Not a review, not an audit, not a statement that the objections are closed.
Agent reviews improved the package; they do not establish independence. The
reviewer's report, with its own commands and dated outputs, is the deliverable
that would change H15.
