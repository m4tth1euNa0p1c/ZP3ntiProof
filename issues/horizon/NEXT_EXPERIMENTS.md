# Decision tickets after the initial experiment

## H11 — Need validation, P0, product blocker

**Hypothesis**: two organizations want to control the same rule on
amounts they refuse to share with the controller, and accept an
adapted issuance. Potential buyer: delegating insurer, claims control.
Collect, with authorization, interviews and measurements from anonymized case
files: volume, control time, cost of errors, cost of integrating two sources.
**Acceptance**: sponsor identified, non-disclosure constraint documented,
signed/selective-disclosure alternative evaluated and explicit experimental budget.
**Abandonment of the private profile for this case**: adaptation impossible, or
an accepted alternative (sharing of the values / signed verdict) satisfying the
same control at a lower complete cost. A permitted sharing or an accepted signed
verdict refutes the alleged cryptographic necessity, without establishing the
economic balance on its own.
No automatic outreach. Deliverable: sourced quantified model, without customer data.

**Preparation delivered**: [review protocol and result sheet](../../docs/horizon/REVIEW_PROTOCOL.md).
The dossier explicitly confronts the profile with the signed verdict of an accepted
third party, with the joining of the witnesses at the prover and with the costs
imposed on issuers.
**H11 remains open**: no interview executed, sponsor committed or budget validated.
The availability of the dossier and the technical tests do not satisfy this ticket.

## H12 — Identical Vega relation, P1 research

Obtain or rebuild, with an authorized specification, the exact mDL credential
circuit, signature, parsing and proof of possession of the paper. Today the
upstream SHA-256 benches are not enough. Reproduce the same inputs, security, CPU,
preprocessing, memory and sizes before any ratio. `node scripts/horizon-vega.mjs`
reproduces only the published SHA-256 reference. No record in the meantime.
**Protocol documented 25 October 2026**:
[docs/experiments/vega/EQUIVALENT_STATEMENT_PLAN_2026-10-25.md](../../docs/experiments/vega/EQUIVALENT_STATEMENT_PLAN_2026-10-25.md)
defines the five equalities an equivalent statement requires, the two
admissible paths and the decision rule; no new measurement, no ratio.

## H13 — Qualified issuance and provenance, P0 security

Two authorities compute the commitment from their validated fact, sign the exact
schema and publish revocation/version. Protocol for handing over the openings, KMS,
access rights and minimization. Evaluate MPC if no actor may know
both witnesses. Tests: substituted source, wrong role, different case file,
out-of-domain value, revocation during dispatch. All mutations refused.
**Delivered 25 October 2026 (laboratory)**: worker `issue` operation, registry
revocation list, two source-format adapters (JWS report, signed ledger line)
with 38 refusal cases, see
[docs/horizon/ISSUER_PROVENANCE_2026-10-25.md](../../docs/horizon/ISSUER_PROVENANCE_2026-10-25.md).
**Still open**: real issuers and issuance change accepted by them, handover
protocol for the openings, KMS and access rights, MPC evaluation, report
freshness and issuance de-duplication policy.

## H14 — Recovery on a remote target, P0 integration

Remote sandbox adapter with idempotency key, ETag/version, status endpoint,
response loss and crash at every transition. Controller's durable database
separated from the target. Accept at most one effect despite two processes and
recovery. Without an adequate target contract: keep UNKNOWN and forbid automatic
retry. Initial tests: `npm run test:horizon`, mandatory extension before production.
**Delivered 25 October 2026 (laboratory)**: separate durable sandbox target with
idempotency key, version precondition, deadline, status route and fence;
controller dispatch/reconciliation; thirteen counted scenarios, see
[docs/horizon/REMOTE_TARGET_2026-10-25.md](../../docs/horizon/REMOTE_TARGET_2026-10-25.md).
**Still open**: a real target contract accepted by its operator, authentication
of the target (H17), a true two-process crash trial on the remote path.

## H15 — Cryptographic and confidentiality qualification, P0 security

External audit of domains, commitment generation, relation, parsing, randomness
sources and side channels. Validate metadata leakage/correlation with
the stakeholders. Prove the limits of Ed25519/Ristretto against quantum attacks,
without a post-quantum label. No-Go if an anonymity need is incompatible with this
profile. Tests: `cargo test --locked --manifest-path labs/horizon/Cargo.toml`.
**Review package assembled 25 October 2026** (the review itself has not taken
place): [docs/publication/EXTERNAL_REVIEW_PACKAGE_2026-10-25.md](../../docs/publication/EXTERNAL_REVIEW_PACKAGE_2026-10-25.md)
lists the relation, domains, encodings, randomness, parsing, assumptions,
fixtures, test suites and ten open objections with their falsification
experiments.
Local input for the auditor (not a substitute): the SEC-1 binding regression
suite and its mutation check, [docs/horizon/VERIFIER_BINDING_TESTS_2026-10-25.md](../../docs/horizon/VERIFIER_BINDING_TESTS_2026-10-25.md),
plus `npm run test:horizon` and `npm run test:proofkit`.

## H16 — Complete cost and load, P1 performance

Repeat independent campaigns on isolated machines, temperature/energy,
RSS per process, failures and throughput at variable concurrency. Measure cold/warm,
network, storage and real source. Evaluate pre-generation of public parameters
without an authorization cache and measure before/after with the same relations.
No gain announced before validation. `npm run horizon:benchmark` produces the raw data.
**Evidence rules and budget documented 25 October 2026**:
[docs/experiments/gpu/CPU_GPU_PQ_FEASIBILITY_2026-10-25.md](../../docs/experiments/gpu/CPU_GPU_PQ_FEASIBILITY_2026-10-25.md)
fixes what a GPU figure or a post-quantum statement would require, records the
single negative GPU observation, and gives a parameterized budget without
amounts; no GPU run, no PQ claim.

## H17 — Operations and compliance, P0 before production

IAM/mTLS and separate operator roles, KMS, externally anchored log,
backup/restoration, monitoring, multi-tenant limits, retention and applicable
DORA/GDPR review.
Docker Compose is a local demonstration; it does not satisfy these criteria.
Criterion: operations dossier and independent reviews, no implicit
approval on the basis of the ZK proof alone.
**Requirements documented 25 October 2026**:
[docs/publication/PRODUCTION_THREAT_MODEL_2026-10-25.md](../../docs/publication/PRODUCTION_THREAT_MODEL_2026-10-25.md)
maps IAM, mTLS, KMS, backup/restore, tenant isolation and operations
requirements to the existing controls, marks each as exercised or not, and
records the production NO-GO with the falsification experiments still to run.
Nothing in that document has been exercised against a deployed system.
