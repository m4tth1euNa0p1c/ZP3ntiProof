# Horizon experiment log

## H00 — Baseline, October 17, 2026

Reference `d18fe65840d5f1cd9dc6155e404c942dabf2bcc7`. 14 Rust tests,
25 Node tests, two historical RISC Zero receipts re-verified. No change to the
initial relation. Details: [audit](AUDIT.md).

## H01 — Vega SHA-256 reproduction completed

Official source cloned at
`c0ee259053cd12eaf43ed71b5cde375452b3ee4d`. The two published benches are
`sha256_vega_sc` and `sha256_vega_mc_zkp`. They measure SHA-256 circuits; the
presence of the mDL presentation figures in the README does not mean that these
benches implement the complete mDL relation.

Environment: same physical CPU and 8 CPU / 12 GiB container as the RISC Zero
laboratory, Rust 1.98.0, `RUSTFLAGS=-C target-cpu=native`. A Cargo resolution
is frozen before the measurements, because the reference repository ships no
lockfile. The setup / prep_prove / prove / verify costs remain distinct.

Both unmodified upstream commands finished with exit code 0:

```sh
cargo bench --offline --locked --bench sha256_vega_mc_zkp
cargo bench --offline --locked --bench sha256_vega_sc
```

`BENCH_THREADS=8`, `RAYON_NUM_THREADS=8`. Sources/lock kept in the references
and [MC raw output](raw/vega-mc.txt), [SC raw output](raw/vega-sc.txt),
[Criterion samples and CIs](raw/vega-criterion.json). MC uses the Criterion
slope estimate; SC the flat mode and its central estimate. The 10 Criterion
groups are not individual requests yielding a service p99.
MC 2 KiB preparation: 75.765 ms; proof: 65.836 ms; verification: 19.885 ms.
`node scripts/horizon-vega.mjs` rebuilds the reference with the retained lock.

**Negative result**: no reproduction of the 92/23 ms of the complete credential.
The available public benches prove SHA-256, without the whole mDL relation.
The application-level comparison remains open; no victory against Vega.

## H02–H04 — Research and arbitration

The three adversarial responsibilities produced state of the art/design,
market/prior art/cost, and security/metrology. Five domains were evaluated.
Joint vote: synthetic laboratory for delegated claim authorization, without
payment; no commercial validation or claimed invention. The transformation into
two ranges is in [the statement](FORMAL_STATEMENT.md). The approved sources
must issue commitments from their values. If this issuance contract is
impossible or disclosure is permitted, the choice must be abandoned in favor of
a simpler alternative.

## H05 — Real prototypes and adversarial correction

Commit `80b2202`: A fresh proof, B historical proof and fresh signature, C
policy selection, non-ZK baseline. The Rust worker verifies all signatures and
the complete proof. HTTP is separate from the historical MCP path. The SQLite
controller consumes nonce and operation and retains UNKNOWN.

Defects detected then corrected before qualification: disclosure request to the
provider despite a private policy; clock rollback before the sources' validity
after verification; error response that could suggest zero effects without
reconciliation. The initial singleton p99 statistical test had an erroneous
expectation, corrected after an independent binomial computation. None of these
failures is concealed in the verdict.

## H06 — Controlled optimization of public parameters

Before: `80b2202`. After: `353652d`. Same image, CPU, 8 CPU / 12 GiB limits,
Rust 1.98.0, `RUSTFLAGS=-C target-cpu=native`, CPU only. Container network
disconnected after compilation. No other heavy benchmark/build running
concurrently. Sequential before/after execution, and alternating A/B order
inside each run. General Windows/WSL activity is not fully controlled.

```sh
cargo build --offline --release --locked --manifest-path labs/horizon/Cargo.toml
horizon-benchmark --samples 500 --warmup 30 --output horizon-before.json
# rebuild commit 353652d in the same environment
horizon-benchmark --samples 500 --warmup 30 --output horizon-after.json
```

The effective binary and sources were under `/lab/horizon/agentik` with
`CARGO_TARGET_DIR=/lab/horizon/target` in the lab container. The raw
[before](raw/horizon-linux-before.json) and [after](raw/horizon-linux-after.json)
files keep 13 phases × 500 samples, five cases and 30 excluded warm-ups. A
first timing command, badly passed between PowerShell and Bash, produced no
file; it was corrected before these two runs. No zero from that command is
counted as a measurement.

The two `OnceLock`s share only the constant public generators. p95 results:
A 7.770→6.546 ms; B verification 2.266→1.247 ms; proof 672 bytes in both
versions. Each run rejects 500 re-signed canonical algebraic corruptions at
the `INVALID_RANGE_PROOF` stage. The public proof produced before optimization
is verified after optimization. CIs and envelope sizes are in
[the report](BENCHMARK_RESULTS.json).

User CPU time of the whole campaign: 11.725→8.930 s; wall-clock durations
11.764→9.054 s. These totals include all phases and the warm-ups; they are not
per-operation costs. No Rust RSS peak/energy/GPU measured. The k=1/2/5/10/100
amortization simulations in the report are arithmetic computations over the
observed means, not executed k series.

## H07–H08 — Durable controller and validation

`npm run test:horizon`: 18 tests, 0 failures/skips. Seven integration groups
with real proofs and 11 statistical tests. The challenger executed them
independently, including two concurrent nonces and two concurrent
presentations: four requests, one admission and one effect. The other
historical suites are preserved: 14 Rust and 25 Node; Horizon adds 9 Rust.
Typecheck, formatting and strict Clippy pass. CI was extended to the laboratory
and to the Docker smoke test.

`node scripts/horizon-firewall-benchmark.mjs --samples 500 --warmup 30`:
Windows 10.0.26200, Node 24.11.1, release Rust worker identified by SHA-256.
The 44.116 s campaign creates 530 distinct synthetic databases/actions, reuses
a single B proof and encounters no error. Database creation, challenge
issuance, HTTP, network and close/checkpoint are excluded. The four timed
phases remain separate in the raw report.

Continuous p95 result for IPC verification + SQLite reservations/effect/audit:
**13.014 ms**, p99 **15.126 ms**, maximum **180.310 ms** retained. The ≤10 ms
hypothesis for this path is rejected on this bench. Observed Node RSS maximum
72,548,352 bytes, excluding Rust and system cache; this is not a total memory
peak. The n=2 smoke files are kept as smoke, without a purportedly robust tail
CI and without mixing with n=500.

## H09 — Local deployment executed

`docker compose -f deploy/horizon/compose.yaml up -d --build --wait`: pinned
images compiled, non-root services healthy. First negative trial: Docker
Desktop did not publish the ports of services attached only to the internal
network. Correction: secret-free relay, with fixed destinations, sole loopback
entry point; prover/verifier keep their internal network.

`node scripts/horizon-http-smoke.mjs`: real proof over HTTP, downgrade and
tampering refused with zero effects, single admission then replay refused.
After `docker compose ... restart`, `... smoke.mjs replay` refuses replay and
new challenge with still a single effect. Unauthorized routes, oversized body
and foreign origin refused. No financial system contacted.

`node scripts/horizon-container-verify.mjs`: the earlier public proof is
verified in a fresh `--network none --read-only` container, without mount,
without witness or private key. This historical verification authorizes no
action. The static interface was checked at desktop and mobile widths by the
frontend agent; the interactive CUA browser was not available for the root
check. The real path was validated through the HTTP API and the target counter.

The first Linux GitHub CI run passed the suites but failed at Compose startup:
the `0600` bind files, owned by runner UID 1001, were not accessible to the
UID 1000 services. This case was masked by the Windows mounts. Correction:
public file alone in explicit `0644`, private kept in `0600`, UID of the prover
alone aligned with the non-root owner. The verifier keeps its own UID and
volume. Reference of the failure retained:
[run 38995262984](https://github.com/m4tth1euNa0p1c/ZK-agentiK/actions/runs/38995262984).

## H10 — Decision

Useful POC and local optimization demonstrated. No external record, no customer
qualification, no production compliance or security established.
[Verdict](FINAL_VERDICT.md) and [next experiments](../../issues/horizon/NEXT_EXPERIMENTS.md).

## SEC-1 — Verifier binding regression suite (25 October 2026)

Six Rust unit tests (`labs/horizon/proof/src/binding_tests.rs`), three
integration tests over the release worker, SQLite controller and SDK tool
(`tests/horizon/binding.test.ts`) and one Proofkit SDK test were added.
They refuse foreign profiles, agent-selected registry/policy/key/backend
fields, cross-mode and relabeled transcripts, prover-chosen commitment
layouts and generators, 64-bit/single/four-commitment proofs (by length),
misconfigured registries and policies, malformed proofs, and verifier output
departing from the expected statement, each with its exact code and a target
counter at zero. Four deliberate mutations of `lib.rs` (transcript ignoring
the challenge, unshifted commitments, profile check removed, proof length
relaxed) were each caught; the file was restored.

Executed: Horizon `cargo test --locked` 15 lib + 4 campaign tests, fmt and
clippy exit 0; `binding.test.ts` 3/3; `tool.test.ts` 10/10;
`npm run typecheck` exit 0; `npm run agent:check:full` PASS with its eleven
fixed steps at exit 0 (`test:horizon` 34/34, `test:proofkit` 22/22; local
report `.tools/agent-sessions/2026-10-24T23-10-56-335Z-39140.json` after the review fixes, see the table in
[VERIFIER_BINDING_TESTS_2026-10-25.md](VERIFIER_BINDING_TESTS_2026-10-25.md)).
Observation: signed bytes follow Rust declaration order while worker JSON
output sorts keys; refused attempts do not consume the nonce. This is a
local regression suite, not an external audit (H15 open).

## H14 — Remote sandbox target and two-controller reconciliation (25 October 2026)

A separate durable HTTP target (`packages/horizon-demo/src/target.ts`) with
idempotency key, `If-Match` version precondition, status route and fence was
added, with a one-attempt client and a controller dispatch/reconciliation path
(`store.ts` `dispatch`, `reconcileWith`). Thirteen scenarios in
`tests/horizon/remote-target.test.ts` count the target's records and received
mutation attempts: two controllers on separate databases (1 record, 2
attempts), lost acknowledgement (UNKNOWN then COMPLETED, 1/1), controller
crash after reservation (fenced, late write refused, 0/1), stale version
(REJECTED, no retry), unreachable target (nothing consumed before reservation;
UNKNOWN then fenced REJECTED, 0/0), target crash before commit (0/1), two
distinct operations on one object (precondition serializes), HTTP path with
operator reconciliation (1/1), target input validation, plus after an
independent agent review: controller crash after acknowledgement (reconciled
COMPLETED), deadline reached before dispatch (no attempt), deadline enforced by
the target clock (410 expired), reconciliation addressed to another target
(TARGET_MISMATCH), reconciliation racing the in-flight attempt. Four mutations
(ambiguity settled as COMPLETED, non-fencing fence, ignored precondition,
hidden retry) were each caught. `npm run test:horizon` 47/47, typecheck and
build exit 0; `npm run agent:check:full` PASS twice (final report
`.tools/agent-sessions/2026-10-24T23-37-19-731Z-42240.json`). Details and limits:
[REMOTE_TARGET_2026-10-25.md](REMOTE_TARGET_2026-10-25.md). Laboratory
contract only: no remote API, no authentication on the target (H17), no audit.

## H13 — Issuer provenance adapters and revocation (25 October 2026)

The Rust worker gained an `issue` operation (fresh blinding, Pedersen
commitment to the validated fact, Ed25519 signature of the exact schema,
role-dependent domain checks) and the trust registry a `revoked_public_keys_hex`
list refused as `REVOKED_ISSUER_KEY` before any signature; registries without
the field still parse and the historical public fixture still verifies. Two
separate TypeScript adapters (`packages/horizon-demo/src/issuers.ts`) consume
a JWS expert report (EdDSA, kid allowlist) and a signed delegation ledger line
(six strict CSV columns, detached Ed25519 signature under a domain string),
check case, tenant and validity window against the holder's request, and issue
through the worker; the holder signs each issuance request (proof of
possession), each source document backs one issuance, attestation validity is
capped after the assessment, and the controller applies per-key revocation
(`revokeIssuerKey`, operator route `/api/revoke-key`) merged into the registry
handed to the verifier. Five Rust tests and six TypeScript tests: nominal path
admitted once (effects 1), 23 expert and 17 delegation refusals with exact codes
and zero issuances, the bearer-document residual recorded, swapped roles and
foreign holders refused with zero effects (SDK pinning and raw
`INVALID_SIGNATURE`), per-key revocation refusing new challenges, revocation
injected into a remote dispatch refused before any target attempt. Four
mutations (skipped report signature, ignored delegation window, uncompared case
identity, ignored revocation list) were each caught. Horizon `cargo test`
20 + 4, fmt/clippy exit 0, `issuers.test.ts` 6/6, `test:horizon` 53/53,
typecheck exit 0, `agent:check:full` PASS twice (final report
`.tools/agent-sessions/2026-10-25T00-03-18-537Z-5016.json`); details in
[ISSUER_PROVENANCE_2026-10-25.md](ISSUER_PROVENANCE_2026-10-25.md). Synthetic
keys and documents only; no real issuer, KMS, MPC or audit.
