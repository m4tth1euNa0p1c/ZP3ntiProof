# H13 — Issuer provenance adapters, versioned registry and revocation

Date: 25 October 2026. Status: **laboratory delivered with synthetic keys and
documents; no real issuer, KMS, MPC or audit (H15)**. Backlog entry `H13`.
Acceptance: versioned issuer roles and trust registry, verified commitments,
signatures, source omissions and revocation; zero effects on invalid inputs.

## 1. What changed

Until now both attestations were produced inside one laboratory function
(`Fixture::with_values`) that owned both authority keys and both blindings.
The authorities are now **two separate adapters**, each consuming a source
document in a real-world format, validating it against its own registered
source signer, and asking the Rust worker to issue the exact attestation
schema under the authority's own key. The holder receives the opening; the
verifier receives only the signed attestation.

| Component | File | Role |
| --- | --- | --- |
| Rust issuance | `labs/horizon/proof/src/lib.rs` `IssueRequest`, `Opening`, `Issued`, `issue` | Fresh blinding (OS RNG), Pedersen commitment to the validated fact, Ed25519 signature over the canonical body under `horizon/issuer-attestation/v1`. Refuses labels, time order, weak holder keys and values outside the role's domain (amount `1..=2^32`, cap `1..=2^33 - 1`). |
| Worker op | `labs/horizon/proof/src/main.rs` `Issue { request, issuer_secret_hex }` | One JSONL line; the issuer secret stays in the issuer's process. |
| Registry revocation | `lib.rs` `TrustRegistry.revoked_public_keys_hex` (`serde(default)`, omitted when empty), `verify` → `REVOKED_ISSUER_KEY` | Checked after `UNKNOWN_ISSUER`, before any signature. Registries written before the field keep parsing; the historical public fixture still verifies. |
| Expert adapter | `packages/horizon-demo/src/issuers.ts` `ExpertReportIssuer` | Source: JWS compact serialization (RFC 7515), `alg = EdDSA` (Ed25519), `typ = horizon-expert-report+json`, `kid` in the authority's allowlist of assessment systems and equal to the payload's `expert_system`. Payload: `case_id`, `tenant`, `assessed_amount_cents` (integer `1..2^32`), `currency = EUR`, `assessed_at_ms`, `expert_system`. Issues the `amount` role; attestation validity bounded to `maxValidityMs` after the assessment (default 30 days). |
| Delegation adapter | same file, `DelegationLedgerIssuer` | Source: one ledger record `case_id,tenant,cap_cents,valid_from_ms,valid_until_ms,approver` (exactly six unquoted ASCII columns, decimal integers) with a detached Ed25519 signature over `horizon/delegation-ledger/v1\0` + line by the ledger system key. Issues the `cap` role; the requested validity window must lie inside the delegation window. |
| Holder request | same file, `IssuanceRequest`, `issuanceRequestBytes` | Tenant, subject, holder key, window, plus the holder's Ed25519 signature over `horizon/issuance-request/v1\0` + canonical JSON of those fields (proof of possession of the named key). |
| Source spending | same file, `UsedSources` (per adapter instance) | Each source document (SHA-256 of the JWS or of the line) backs at most one issuance; a refused worker call does not release it. In-memory: a deployment needs a durable store. |
| Registry publication | same file, `publishRegistry`, `revokeIssuerKey` | Versioned by `epoch`; distinct authorities required; a source signer key cannot be an authority key; revocation lists the key and bumps the epoch (one-way). |
| Controller revocation | `store.ts` `revokeIssuerKey`, `revokedIssuerKeys`, table `revoked_issuer_keys`; `tool.ts`; `server.ts` `/api/revoke-key` (operator token) | The controller's own revocations are merged into the registry handed to the verifier, so a listed key is refused under new challenges too; the trust epoch moves so outstanding challenges are stale. Unlike `revoke()`, other authorities keep working. |

Both adapters check the source against the **holder's signed request**: same
case, same tenant, ordered validity window covered by the source (assessment
date before the window and bounded validity; delegation window containing it).
The two attestations must share the window, the holder key, tenant and subject
(`EVIDENCE_JOIN`), so the holder requests one window from both authorities.

## 2. Trust model and what is not claimed

- The authority is responsible for the truth of the fact it signs. The
  adapter checks provenance (a registered source signer), format, domain and
  consistency with the request; it does not establish that the assessment or
  the delegation is correct.
- Source signers (assessment system, ledger system) are distinct from the
  authority's attestation key; a source document alone never authorizes
  anything and a registered source key does not become an authority key.
- Openings (value and blinding) are returned to the caller of `issue` only.
  Tests assert that the public configuration contains neither `blinding` nor
  the amount.
- Synthetic keys, synthetic documents: they authenticate no real
  organization. No KMS, no hardware key, no MPC between authorities (ticket
  H13 keeps "evaluate MPC if no actor may know both witnesses" open: here the
  holder knows both openings, by design of the relation).
- Revocation is a verifier-side list plus an epoch bump; there is no online
  status protocol, no issuer-published revocation feed, no key rotation
  ceremony. A real deployment needs an operator procedure (H17).

## 3. Scenarios executed

Rust (`labs/horizon/proof/src/issuer_tests.rs`, 5 tests):

| Case | Result |
| --- | --- |
| Separately issued pairs at `(1, 1)`, `(125000, 250000)`, `(2^32, 2^33 - 1)` prove and verify; reusable path too; serialized evidence carries no blinding or amount | accepted |
| Issuance of amount `0`, `2^32 + 1`, `u64::MAX`; cap `0`, `2^33`; `2^32 + 1` accepted as cap, refused as amount | `VALUE_OUT_OF_DOMAIN` |
| Equal validity bounds; subject with a space; holder key `00…00`; non-hex issuer secret | `EVIDENCE_TIME`, `INVALID_LABEL`, `WEAK_KEY`, error |
| Two issuances of one fact: different blindings and commitments | asserted |
| Amount signed by an unregistered authority | `INVALID_SIGNATURE` |
| Registered cap authority issues the amount under its own name | `DISTINCT_AUTHORITIES_REQUIRED` |
| Registered expert key signs a cap body | `INVALID_SIGNATURE` |
| Both attestations consistently for `claim-002` | `SUBJECT_MISMATCH` |
| Amount for `claim-001`, cap for `claim-002` | `EVIDENCE_JOIN` (prover) |
| Attestations naming another holder | `HOLDER_KEY` (prover) |
| Expert key listed as revoked; cap key listed; unrelated key listed | `REVOKED_ISSUER_KEY`, `REVOKED_ISSUER_KEY`, accepted |
| Registry JSON without the field parses and re-serializes identically; populated list round-trips; historical fixture `tests/fixtures/horizon/public-presentation.json` parses | asserted |
| Revocation entry in uppercase hex; entry of 31 bytes | `NONCANONICAL_HEX`, `ENCODING_LENGTH` (never a silent non-match) |

TypeScript (`tests/horizon/issuers.test.ts`, 6 tests, local SQLite effects counted):

| Case | Result |
| --- | --- |
| JWS report + signed ledger line → two attestations (2 worker issuances), holder proves, SDK tool admits once, replay refused; public config without `blinding` or amount | `COMPLETED`, effects 1 |
| Expert adapter, 23 refusals: unregistered signer, unknown `kid`, `alg none`, `alg ES256`, other `typ`, extra header field, two parts, empty signature, non-base64url, tampered payload, other case, other tenant, assessment after validity, USD, zero, `2^32 + 1`, fractional, negative, string amount, missing field, extra field, ledger line as JWS, `expert_system ≠ kid`; request refusals: unordered window, validity above 30 days, altered signed fields, key the requester does not hold | exact `IssuerError` codes; 0 worker calls, 0 issuances |
| Expert adapter, residual by design: a stranger holding the signed report and their own key obtains one attestation to that key; the report is then spent for everyone (`SOURCE_ALREADY_USED`); a fresh report issues again; an authority cannot register itself as a source signer | 1 then 2 issuances |
| Delegation adapter, 17 refusals: five/seven columns, quoted field, trailing newline, other ledger key, tampered cap, cap `0`, cap `2^33`, signed/decimal cap, leading-zero timestamp, other case, other tenant, window starting after / ending before the request, empty approver, JWS as line, non-hex signature, altered signed request; then one issuance, the same line refused, source key equal to the authority key refused at construction | exact codes; 0 then 1 issuance |
| Registry with swapped roles → `UNKNOWN_ISSUER` at the verifier; same authority twice refused at publication; attestations issued to another holder (who signed their own request) submitted through the SDK → `REJECTED` by evidence pinning, and by the raw verifier → `INVALID_SIGNATURE` (holder signature) | effects 0 |
| Revocation: registry publication lists the key (epoch 2); the controller's `revokeIssuerKey` makes the verified bundle stale (`STALE_EPOCH`); a NEW challenge at epoch 2 is refused through the SDK because the adapter hands the list to the verifier (`REVOKED_ISSUER_KEY` raw); old bundle under the new registry → `TRUST_EPOCH_MISMATCH`; uppercase entry → `NONCANONICAL_HEX`; legacy registry still accepted | effects 0 |
| Revocation between the controller's decision to dispatch and the single remote attempt (injected during the target version read): refused inside the reservation transaction, nothing consumed | target attempts 0, effects 0 |

## 4. Regression detection (mutation check)

| Mutation | Tests failing |
| --- | --- |
| Expert adapter skips the report signature | expert adapter test |
| Ledger adapter ignores the delegation window | delegation adapter test |
| Expert adapter does not compare the case identity | expert adapter test |
| Verifier ignores the revocation list (Rust) | `revoked_issuer_key_is_refused_…` |

## 5. Commands executed on 2026-10-25

| Command | Result |
| --- | --- |
| `node scripts/cargo.mjs test --manifest-path labs/horizon/Cargo.toml --locked` | 20 lib tests + 4 campaign tests, exit 0 |
| `node scripts/cargo.mjs fmt … -- --check`, `clippy --all-targets --locked -- -D warnings` | exit 0 |
| `npm run horizon:build` | exit 0 |
| `node --import tsx --test tests/horizon/issuers.test.ts` | 6 passed (5 before the review, 6 after) |
| `npm run test:horizon` | 53 passed (47 before, + 6) |
| `npm run typecheck` | exit 0 |
| `npm run agent:check:full` | PASS twice, before and after the review fixes; final local report `.tools/agent-sessions/2026-10-25T00-03-18-537Z-5016.json` (UTC timestamp, ignored by Git) |

## 6. Limits and open points

- The `init` laboratory fixture (`scripts/horizon.mjs init`,
  `Fixture::generate`) still issues both attestations in one process; the
  adapters are exercised by the tests and available to a deployment, but the
  Compose demo does not run two issuer services.
- **Source documents are bearer documents.** Neither the JWS report nor the
  ledger line names the holder. The adapters now require the requester to
  prove possession of the key they name, bound each document to a single
  issuance (in-memory, per adapter instance) and cap the attestation validity
  after the assessment; but whoever holds a legitimate signed document and
  any key of their own still obtains that one attestation (tested and
  recorded as such). Closing this requires the source to name the holder, an
  authority-side policy on who may request for a case, or both; that is an
  issuance-contract decision for the real issuers (ticket H13 remains open).
- No report freshness beyond `assessed_at_ms` and the validity cap: a
  report carries no nonce or expiry of its own. Issuance de-duplication is
  by document bytes, so a re-signed report (new signature bytes, same facts)
  issues again; issuer-side policy outside this ticket.
- Revocation is pull-based. The controller applies a per-key revocation
  (`revokeIssuerKey`: key listed for the verifier, trust epoch moved) or a
  global one (`revoke()`); both invalidate every outstanding challenge. The
  configured registry file is pinned by the database's configuration hash, so
  revocations are applied through the controller, not by editing the file.
- JSON parsing of the JWS payload follows `JSON.parse` (last duplicate key
  wins), a parser differential with the signing system that the strict schema
  does not remove; Node's Ed25519 verification is not the "strict" variant
  used by the Rust verifier. Neither is exploitable without a second issuance
  of the same bytes, which de-duplication refuses.
- Issuer secrets are plain hex in the adapter's memory and in the worker
  request line; no KMS, no key rotation, no attestation of the issuing host.
- **Independent agent review (25 October 2026)** raised: source documents
  acting as bearer tokens (mitigated: proof of possession, single use,
  validity cap; residual documented above); per-key revocation unreachable
  from the controller because the adapter overrides the registry epoch and the
  configuration is pinned (fixed: `revokeIssuerKey`, list merged into the
  registry handed to the verifier, operator route `/api/revoke-key`);
  revocation-list entries not canonicalized (fixed: `NONCANONICAL_HEX`);
  `expert_system` not compared to `kid` (fixed); source signer equal to the
  authority key (fixed at construction); tests named for a scenario they did
  not exercise (fixed: raw `INVALID_SIGNATURE` for foreign evidence, exact
  `STALE_EPOCH`, revocation injected into a remote dispatch). The review is
  internal; no external audit (H15).
