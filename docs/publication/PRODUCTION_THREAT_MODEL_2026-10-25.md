# H17 — Production threat model: identities, transport, keys, backups, tenants

Date: 25 October 2026. Status: **requirements document; nothing below has
been exercised against a deployed system. Production verdict: NO-GO until
every "exercised" column reads yes with dated evidence.** Backlog entry
`H17` (`docs/development/TASKS.json`). Acceptance: document reviewed
mTLS/IAM/KMS/backup requirements, tenant isolation and production NO-GO until
exercised.

This document extends the laboratory [threat model](../horizon/THREAT_MODEL.md)
to the operating environment the laboratory does not have. It states what a
production deployment of the Horizon profile would need, maps each need to the
control that exists today, and names the experiment that would turn a
requirement into evidence. Provider capabilities are taken from the dated
[cloud comparison](CLOUD_COMPARISON.md) and its sources; no new provider claim
is made here. No regulatory obligation is asserted (see
[MARKET_DISCOVERY](../horizon/MARKET_DISCOVERY.md) for the texts and their
scope).

## 1. Actors, assets and the boundary that ZK does not move

| Actor | Holds | Must never hold |
| --- | --- | --- |
| Agent / prover (holder) | openings, holder key, prepared proof | any mutation credential, the verifier's registry, the controller database |
| Issuers (expert, delegation) | their own attestation key, their source signer allowlist | the other issuer's key, the holder key |
| Verifier / controller | registry, policy, challenge store, reservation database, target credential | openings, issuer secrets |
| Target (business system) | records, object versions, fences | the controller's reservation database |
| Operator | revocation / rotation / reconciliation routes, backups | the ability to forge a proof (it can, however, change rules: this is the trusted boundary) |

A valid proof moves no boundary: whoever controls the verifier's binary,
configuration, storage, clock or operating system decides. The
[threat model](../horizon/THREAT_MODEL.md) already states it; production adds
the people and systems that can reach those elements.

## 2. Requirements and current state

Legend of the "exercised" column: **no** = nothing in this repository has
tested it; **lab** = tested with synthetic keys, loopback transport and an
in-process or sandbox target, by the repository's own test suites (run locally
and, for the suites under `tests/horizon`, by GitHub Actions on each commit).
"lab" never means a deployed environment, real identities or real keys. Only
**no** and **lab** exist today.

### 2.1 Identities and access (IAM)

| Requirement | Why | Current control | Exercised |
| --- | --- | --- | --- |
| Separate runtime identities for prover, controller and target; the prover identity has no right on the controller database, the registry or the target | A compromised agent must not reach the mutation path | Two processes with two configuration files (`private.json`, `public.json`); Compose uses UID `1000` for both unless the operator sets `HORIZON_PROVER_UID`; no cloud identity | lab ([DEPLOYMENT](../horizon/DEPLOYMENT.md), Compose smoke test in CI without identity denial tests) |
| Issuer services deployed separately from holder and controller, each with its own identity and key | The adapters exist as code; the Compose demo does not run two issuer services ([H13 limits](../horizon/ISSUER_PROVENANCE_2026-10-25.md)) | None deployed | no |
| Operator routes behind an identity with individually attributable roles, not a shared secret | Revocation, rotation, key revocation and reconciliation change what gets authorized | 32-byte server-side token, fail closed when absent, constant-time compare, four routes (`/api/revoke`, `/api/rotate-policy`, `/api/reconcile`, `/api/revoke-key`) | lab ([operator tests](OPERATOR_VALIDATION_2026-10-17.json) for three routes; `tests/horizon/firewall.test.ts` for all four since 25 October 2026); shared secret is not banking IAM |
| Operator token lifecycle: generation, storage, rotation, distribution; not exposed through process environment to co-tenants | The token is the only barrier on the operator routes | `HORIZON_OPERATOR_TOKEN` environment variable or constructor option; no rotation | no |
| State view (`/api/state`) restricted to operators; audit chain events carry `bundle_hash` | With an unauthenticated target, a leaked `bundle_hash` lets a third party record a bundle the controller never sent ([H14 limits](../horizon/REMOTE_TARGET_2026-10-25.md)) | Operation rows expose `id`/`status` only; the audit view still carries `bundle_hash`; route not operator-gated | no |
| Deployment identity federated from CI with restricted issuer, audience and subject; no long-lived key | Supply-chain path to the verifier configuration | None; the `infra/` skeletons create identities without permissions | no |
| Evidence of real denials: the prover identity attempting the controller database, the target and the operator routes must be refused and logged | A policy file is not a denial | None | no |
| IAM revocation latency documented and distinct from `trust_epoch` | Identity permission caches can outlive an application revocation | `trust_epoch` bump on `revoke()` invalidates outstanding challenges locally | lab; cloud latency unknown |

### 2.2 Transport (mTLS) and network

| Requirement | Why | Current control | Exercised |
| --- | --- | --- | --- |
| Mutual TLS or an equivalent authenticated channel between controller and target, and between agent and controller | The controller trusts the transport for the target's answer: a forged `recorded` yields `COMPLETED` without a record ([H14 limits](../horizon/REMOTE_TARGET_2026-10-25.md)) | Plain HTTP on loopback; Compose relay without secrets on loopback only | lab (loopback), no TLS anywhere |
| Target reachable only from the controller identity | Anyone reaching the sandbox target can burn a business operation or fence it | Loopback binding by default; `HORIZON_BIND` can widen it | no |
| mTLS specifics: certificate authority ownership, client-certificate rotation and revocation (CRL/OCSP or short lifetimes), subject/SAN pinning of the target by the controller | A channel is only as authenticated as its certificate lifecycle | None | no |
| Egress of the prover and controller restricted to the named destinations; DNS and control-plane exceptions reviewed | An empty rule set is not closed; platform rules differ per provider | `infra/` skeletons describe explicit denials; nothing deployed or tested | no |
| Origins, CORS and CSP treated as browser hygiene, not authentication | Documented in the threat model | Fixed origin check, CSP, no-store | lab |

### 2.3 Keys (KMS / HSM)

| Requirement | Why | Current control | Exercised |
| --- | --- | --- | --- |
| Issuer attestation keys and the holder key held in a KMS or HSM compatible with Ed25519 (PureEdDSA over the exact canonical bytes), or a new versioned signature profile reviewed before adoption | Software keys in process memory and in JSONL request lines ([H13 limits](../horizon/ISSUER_PROVENANCE_2026-10-25.md)) | Holder secret as hex in `private.json`; issuer secrets as hex in the adapters' memory and in worker request lines; the cloud comparison records that the consulted Azure Key Vault table does not list Ed25519 and that the consulted GCP documentation lists it under software protection and not in the HSM table consulted | no KMS adapter exists |
| Key rotation procedure: new registry epoch, overlap window, revocation of the old key, re-issuance policy for attestations signed by it | Revocation today is a verifier-local list plus epoch bump; attestations under a revoked key are refused, nothing re-issues them | `revoked_public_keys_hex`, `revokeIssuerKey`, `REVOKED_ISSUER_KEY` | lab |
| Separation of duties: the identity that can rotate the registry is not the identity that runs the controller | Otherwise a controller compromise can re-root trust | None | no |
| Erasure of openings and secrets from memory with stated guarantees; side-channel review | Not evaluated ([threat model](../horizon/THREAT_MODEL.md)) | None | no |

### 2.4 Durability, backups and recovery

| Requirement | Why | Current control | Exercised |
| --- | --- | --- | --- |
| Controller database on storage whose durability guarantees are known, with tested restoration | Reservations and `UNKNOWN` states must survive the controller; a restored backup that is older than the target's records re-opens consumed operations | SQLite WAL, `synchronous=FULL`, configuration hash pinned in the database | lab (restart tests); no backup, no restore test |
| Restore procedure that reconciles every `RESERVED`/`UNKNOWN` operation against the target before serving | A restore is a restart with memory loss | `reconcileWith` fences at the recorded target; terminal states never rewritten | lab, in-process; no restore drill |
| Target database durability and version precondition semantics agreed with the target's operator | Idempotency and fences exist only in the sandbox target | Sandbox target contract | lab, synthetic target |
| Audit chain anchored outside the controller (WORM storage, external timestamping) | A disk operator can rewrite the whole chain | SHA-256 chained events in the same SQLite file | no |
| Durable single-issuance store for source documents on the issuer side | The per-document spending set is in memory per adapter instance ([H13 limits](../horizon/ISSUER_PROVENANCE_2026-10-25.md)); a restart re-opens every document | In-memory `UsedSources` | no |
| Encryption at rest and access control of the controller volume and of backups; backup integrity (hash) and encryption; high-availability model for a single-writer SQLite file | A copied database file is the whole authorization state; SQLite has one writer and no failover | None | no |
| RPO/RTO, retention and export defined by the data owner | Unknown; must not be invented | None | no |

### 2.5 Tenant isolation

| Requirement | Why | Current control | Exercised |
| --- | --- | --- | --- |
| One registry, policy and database per tenant; a database cannot acquire another tenant's configuration | Cross-tenant authorization | `config_binding` hash refuses a changed configuration on the same database; attestations and challenges bind the tenant | lab ([firewall tests](../../tests/horizon/firewall.test.ts)) |
| Multi-tenant deployment either as separate instances or with a reviewed shared-state schema | SQLite per instance does not demonstrate shared-state isolation | None | no |
| Metadata minimization and linkability review per tenant | Commitments, holder key and reused proofs are stable identifiers | Documented, not mitigated | no |

### 2.6 Operations

| Requirement | Why | Current control | Exercised |
| --- | --- | --- | --- |
| Monitoring of refusals, `UNKNOWN` counts, reconciliation outcomes and worker failures | `UNKNOWN` requires a human or a procedure | Audit table, state view | lab |
| Rate limits and abuse controls on challenge issuance and refusals | Refused bundles do not consume the nonce; no attempt counter ([SEC-1 observations](../horizon/VERIFIER_BINDING_TESTS_2026-10-25.md)) | Capacity caps (bodies, queue, challenges) | lab |
| Runbooks: revocation, rotation, reconciliation, restore, incident | Operators act on the trusted boundary | None | no |
| Trusted time: authenticated time source, drift bounds, skew policy between controller and target | Deadlines are checked by the controller clock and, since H14, by the target clock (410 `expired`); the laboratory threat model states "no secure clock" | Host clocks | no |
| Dependency and supply-chain review cadence; image digest pinning, signed images, software bill of materials | Pinned lockfiles, no automatic updates; `cargo audit` runs in CI; Compose images pinned by digest; no image signing or SBOM | [DEPENDENCY_REVIEW](DEPENDENCY_REVIEW.md), `.github/workflows/ci.yml` | lab for the review and the audit step; no for signing and SBOM |
| Logging: retention, access and personal-data review (linkable commitments, holder keys and reused proofs may be personal data) | Stated in the laboratory threat model, not mitigated | Audit table and worker stderr discarded | no |

## 3. Production verdict

**NO-GO.** Every row marked **no** is a blocking gap for a production
deployment of this profile, independently of the cryptography. The
laboratory evidence (**lab**) was obtained with synthetic keys, loopback
transport and an in-process or sandbox target, on developer machines and on
GitHub Actions runners; it demonstrates the protocol's behaviour, not the
environment's. The verdict follows from the tables (no row is exercised in a
deployed environment); the order below is a judgment about dependencies, not a
derivation:

1. Identities with observed denials (2.1), then authenticated transport
   between controller and target (2.2): without them H14's reconciliation
   trusts an unauthenticated answer, and the state view leaks what a third
   party needs.
2. Key custody and rotation (2.3), with a decision between an Ed25519-capable
   signing service and a new versioned signature profile.
3. Durability (2.4): durable single-issuance store, encrypted and
   integrity-checked backups, a restore drill that compares the target's
   record set before serving, on the real target contract.
4. Tenant deployment model and shared-state review (2.5), then operations
   (2.6) including trusted time and log retention.
5. External cryptographic audit (H15) remains required after all of the above.

## 4. Falsification experiments (not run)

| Experiment | Pass condition | Fail condition |
| --- | --- | --- |
| Prover identity attempts controller database, target `PUT`, operator routes | every attempt refused and logged | any success |
| Controller to target with mTLS; a non-authenticated endpoint answers the version read | `TARGET_UNAVAILABLE`, nothing consumed, no reservation | any reservation or attempt |
| Controller to target with mTLS; after reservation, a non-authenticated endpoint answers `recorded` to the single attempt | channel refused, operation stays `UNKNOWN`, no `COMPLETED` without a durable record at the authenticated target | `COMPLETED` without a record |
| KMS-held issuer key: sign the canonical attestation bytes, verify with the worker | byte-exact PureEdDSA signature accepted | pre-hashing or encoding mismatch |
| Rotate the expert key: new epoch, old key listed | outstanding challenges refused, new attestations accepted, old attestations refused | any authorization under the old key |
| Restore the controller database from a backup taken before three completed dispatches; the restored controller holds no row for them | before serving, the restore procedure imports or compares the target's record set and marks the three operations consumed; if it does not, the controller re-issues and redispatches them and the only barrier is the target's idempotency key: count target `PUT`s (+3 at most) and records (unchanged), outcomes `REJECTED` by `conflict` | any new target record, or a controller that serves without having compared the target's record set |
| Two tenants on separate instances; a bundle from tenant A presented to B | refused with zero effects | any effect |

## 5. Review

An internal read-only agent review on 25 October 2026 checked every factual
statement against the repository and raised: a restore experiment whose pass
condition named a mechanism that cannot fire (rewritten in section 4); the
Compose UID claim (corrected: same UID unless `HORIZON_PROVER_UID` is set);
the legend of the "exercised" column (redefined: "lab" includes the CI runs of
the test suites); the operator guard of `/api/revoke-key` credited without a
test (test added to `tests/horizon/firewall.test.ts`, seven token
configurations against the four routes); imprecise wording on key storage and
on the GCP key table; missing requirements (durable single-issuance store,
operator-only state view and `bundle_hash` exposure, operator token lifecycle,
trusted time, mTLS certificate lifecycle, encryption at rest and single-writer
availability, supply-chain signing, log retention and personal data, issuer
services as separate deployments), all added to section 2. The review is
internal and is not an audit; it executed no deployment.

## 6. What this document is not

Not a regulatory assessment, not a provider recommendation, not a security
audit, not a statement that any cloud offering is compatible or incompatible
beyond the dated sources of the cloud comparison. It is a list of
requirements and of the evidence that is missing.
