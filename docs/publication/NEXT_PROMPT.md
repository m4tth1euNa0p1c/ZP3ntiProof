# Next mission: resolve unknowns, not proclaim perfection

## State on 25 October 2026 (read before the prompt below)

The prompt below records the decisions of 17 October 2026 and is kept as
written. Since then, the following items were delivered as a stack of draft
pull requests on top of the release branch (none merged; `main` untouched):

| Item (prompt item number, or regression suite) | Delivered | Where |
| --- | --- | --- |
| 2. H13 two authentic issuances | Laboratory adapters (JWS expert report, signed delegation ledger line), worker `issue` operation, registry revocation; synthetic keys only | [ISSUER_PROVENANCE](../horizon/ISSUER_PROVENANCE_2026-10-25.md) |
| 3. H14 separate durable controller and target | Sandbox target with idempotency key, version precondition, deadline, status and fence; controller dispatch and reconciliation; 13 counted scenarios | [REMOTE_TARGET](../horizon/REMOTE_TARGET_2026-10-25.md) |
| 4. H15 independent review package | Package assembled, objections listed with falsification experiments; the review itself has not taken place | [EXTERNAL_REVIEW_PACKAGE](EXTERNAL_REVIEW_PACKAGE_2026-10-25.md) |
| 5. H17 requirements | Production threat model, requirement by requirement, verdict NO-GO | [PRODUCTION_THREAT_MODEL](PRODUCTION_THREAT_MODEL_2026-10-25.md) |
| 5. H16 cost and GPU | Evidence rules and parameterized budget, no run, no price | [CPU_GPU_PQ_FEASIBILITY](../experiments/gpu/CPU_GPU_PQ_FEASIBILITY_2026-10-25.md) |
| 7. Vega comparison | Equivalent-statement protocol, no measurement, no ratio | [EQUIVALENT_STATEMENT_PLAN](../experiments/vega/EQUIVALENT_STATEMENT_PLAN_2026-10-25.md) |
| Verifier regression suite (SEC-1) | Binding of profile, transcript, layout, registry and malformed proofs, with mutation check | [VERIFIER_BINDING_TESTS](../horizon/VERIFIER_BINDING_TESTS_2026-10-25.md) |

Still open and not deliverable by an agent: H11 (no interview conducted, no
sponsor, no budget), H15 (no independent reviewer engaged), every experiment
of the production threat model against a deployed environment, the merge of
the pull-request stack, the tag and the manual release workflow. Agent
reviews were applied to each delivered item; they are internal.

```text
You are working in ZK-agentiK. Start with AGENTS.md, Git status, the
register docs/publication/CLAIMS.md and issues/horizon/NEXT_EXPERIMENTS.md. Preserve
others' changes and CLAUDE.md. Record the starting commit and assign
paths before any explicitly authorized parallel work.

Objective: make the next pilot decision falsifiable. Proofkit SDK
and Horizon remain a laboratory. Announce neither a world standard, a Vega
record, banking compliance nor an automatic generator of safe circuits.
Decisions confirmed on October 17, 2026: “GA” means GitHub Actions for
automating proofs and sandbox deployments; compare Azure and GCP
without deploying cloud resources; make the repository public after checks.
Repository publication is already authorized: do not ask for that permission again.
It implies neither general product availability nor npm publication.

1. H11 — Buyer need and substitute
   Read the existing interview protocol. Prepare a problem sheet with
   decision-maker, data prohibited from disclosure, reason, real workflow and known
   or unknown budget. Compare signed verdict, bounded disclosure and credential/predicate.
   Do not contact anyone without explicit instruction. An interview not conducted
   remains “not conducted”. Abandon the ZK need if the substitute satisfies
   the constraints with less complexity. Do not invent a prospect or budget.

2. H13 — Two authentic issuances
   Implement or specify, based on actual available access, two independent
   sources binding authoritative fact, unit, domain, version, commitment,
   signature and opening transfer to the prover. Test false facts, substitution,
   unknown key, revocation and version change. A valid signature does not
   prove the truth of its source. If nobody may know both
   openings, this profile requires another architecture, not a marketing sentence.
   For KMS, verify algorithm AND protection level: software Ed25519 does not
   mean HSM Ed25519. No signature change without a versioned profile.

3. H14 — Genuinely separate durable controller and target
   Define a target contract with business operation identifier, idempotency key,
   version precondition and status reading. First build a local laboratory
   with two processes/targets and a shared durable store; PostgreSQL alone does not
   make a remote call atomic. Inject lost ACK, crashes before/after
   reservation and effect, two-controller concurrency, new requests
   for the same operation and recovery after restoration. Count effects on the
   target. An UNKNOWN state does not release the operation and does not trigger
   automatic redispatch without a sufficient contract. No effect before proof.

4. H15 — Independent review package
   Prepare the relation, domains, encodings, RNG, parsing, issuer assumptions,
   leaks, fixtures and adversarial tests for external cryptographic review.
   An agent review can improve the package; it does not close H15.
   Record unresolved objections and their falsification experiments.

5. Infrastructure and cost — compare Azure and GCP without deployment
   Read docs/publication/CLOUD_COMPARISON.md. Revalidate current documentation.
   Compare both providers with region, identity, compatible keys,
   durable storage, network and parameterized costs. The current choice authorizes
   no cloud deployment or creation of a resource or key. Existing
   foundations cover only network/identity, validatable locally. H17 requires tested IAM,
   isolation, restoration, audit and multi-tenant limits. Instance SQLite
   is not a distributed database. Establish H16 without inventing prices
   or workloads; no GPU without measured benefit on the relevant profile.

6. GitHub Actions — proofs and ephemeral sandbox
   Read docs/publication/GITHUB_ACTIONS.md and the reusable workflow
   .github/workflows/proof-sandbox.yml, triggerable through workflow_call and
   workflow_dispatch. Allowed profiles are horizon and math; deploy_sandbox
   is a boolean, false by default and allowed only for Horizon. The Docker
   sandbox runs on the GitHub runner and is not a cloud deployment.
   Actually verify calls from ci.yml and evidence.yml. Maintain a
   closed profile list, pinned actions, least privilege,
   and no cloud secret, free-form command or private key in artifacts.
   Distinguish process results, historical fixture, new numerical
   execution and verified proof. Retain commit, versions, hashes, unknown
   state or failure without automatically promoting it to success. Uploaded summaries
   and their SHA-256 hashes do not replace selected and reviewed raw results.
   Any future cloud deployment requires an explicitly authorized scope;
   do not add a fictitious stage announcing a nonexistent environment.

7. CPU/GPU experiments, Vega and post-quantum migration
   Read docs/experiments/gpu/RESULTS_2026-10-17.md: two builds failed
   due to lack of memory and no GPU receipt was produced. Do not rerun
   the same parameters. First justify the profile, RAM, maximum duration
   and stop criterion; no global driver change or GPU rental is
   authorized by this prompt. A new trial must separate compilation,
   preparation, proving, independent verification, serialization and memory,
   retain the negative result and verify rejection of development mode.
   Compare CPU/GPU only with the same relation, security, inputs and parameters.
   Do not mix Vega's SHA-256 circuit with the Horizon predicate; a trial
   with a different relation remains in a separate ranking. Do not extrapolate
   reference figures to SDK code or a new dependency.

   For post-quantum, inventory all assumptions: commitment,
   source signature, fresh signature, proof, transcript and parameters.
   Replacing only Ed25519 with ML-DSA or SLH-DSA does not make Bulletproofs
   post-quantum. Propose a separate profile based on published primitives,
   establish its assumptions and costs, then build a POC only if its
   need and feasibility are established. Reject any PQ request for the
   current classical profile. No homegrown protocol or PQ label based on SHA-256 alone.

Deliverables: bounded diff, claim/evidence/limitation matrix, negative tests with
effect counters, failure artifacts, cost with assumptions, GO/NO-GO decision
per experiment. Run the appropriate AGENTS.md checks and modified
profiles. Do not rerun heavy campaigns without a change that justifies it.

Use the .agents/roles/ contracts for explicit challenge, without
claiming that all clients autodiscover them. Address each objection
with evidence, a fix or a retained limitation. Making the repository public, already
authorized, happens after publication checks on the exact candidate
revision; record the effective result without claiming unverified visibility.
External contacts, npm publication and cloud resources are not
included in this authorization. Preserve the user's private files
and distinguish the state of checks, GitHub and product qualification.
```
