# Laboratory publication

This release presents a **research repository and an experimental SDK**. It
does not qualify a banking platform or a generally available product.
Historical results remain available; each new experiment
states its own scope and limitations.

## Read and reproduce

| Objective | Artifacts |
| --- | --- |
| Install a version and view its artifacts | [Packages](../../PACKAGES.md), [changelog](../../CHANGELOG.md), [0.1.0-alpha.1 notes](../releases/v0.1.0-alpha.1.md) |
| Understand the customer problem and decide whether ZK is needed | [H11 protocol](../horizon/REVIEW_PROTOCOL.md), [business case](../horizon/BUSINESS_CASE.md) |
| Understand the proven relation and assumptions | [White paper PDF](../whitepaper/whitepaper.pdf), [LaTeX](../whitepaper/whitepaper.tex), [bibliography](../whitepaper/references.bib) |
| Run the arithmetic checks | [MATLAB/Octave](../../math/README.md), [correlated campaigns and MATLAB R2026b](../experiments/circuit/RESULTS_2026-10-17.md) |
| Create an HTTP/MCP tool with independent control | [SDK](../../packages/proofkit-sdk/README.md), [compiled adapter](../../packages/horizon-demo/src/tool.ts) |
| Run a profile or verify artifacts | [Proofkit CLI](../../tools/proofkit/README.md), [catalog](../../evidence/catalog.json) |
| Automate proofs and sandbox | [Reusable GitHub Actions](GITHUB_ACTIONS.md) |
| Evaluate Azure/GCP and customize the foundations | [Comparison](CLOUD_COMPARISON.md), [local validation](VALIDATION.md) |
| Read what production would require and why the verdict is NO-GO | [Production threat model, 25 October 2026](PRODUCTION_THREAT_MODEL_2026-10-25.md) |
| Examine the CUDA experiment | [GPU report](../experiments/gpu/README.md), negative results retained, [CPU/GPU/PQ evidence rules and budget](../experiments/gpu/CPU_GPU_PQ_FEASIBILITY_2026-10-25.md) |
| Compare with Vega without a record claim | [Equivalent-statement protocol](../experiments/vega/EQUIVALENT_STATEMENT_PLAN_2026-10-25.md), [executed references](../horizon/COMPETITOR_COMPARISON.md) |
| Check public claims | [Editorial register](CLAIMS.md), [checklist](RELEASE_CHECKLIST.md) |
| Read the decision and the checks actually run | [Dated publication review](PUBLICATION_REVIEW_2026-10-17.md) |
| Read security fixes and limitations | [Agent counter-review](INDEPENDENT_AGENT_REVIEW.md), [dependencies](DEPENDENCY_REVIEW.md), [local validation](LOCAL_VALIDATION_2026-10-17.json) |
| Continue the work | [Exact prompt](NEXT_PROMPT.md), [H11–H17 issues](../../issues/horizon/NEXT_EXPERIMENTS.md) |

The [skills](../../.agents/skills/) and [agent contracts](../../.agents/roles/)
allow writing, challenge, cloud boundaries and publication review to be
assigned. An agent review does not replace an external auditor.

## Business decision and security

The case explored is **confidential authorization of a delegated insurance claim**.
The current circuit establishes a bounded relation over two attested commitments; it
does not calculate deductibles, aggregate claims, reserves, fraud or remaining
budget. The action records a local synthetic authorization.

The commercial need remains conditional: it requires two authoritative sources,
a documented reason to hide values from the controller, a holder authorized
to know their openings, and an insufficient signed alternative. No
interview, buyer, budget or economic benefit absent from the sources is added.

The remaining open areas are H11 (customer qualification), H13 (real issuance),
H14 (remote controller and target), H15 (external audit), H16 (full cost) and
H17 (operations). Azure/GCP provide network/identity foundations here,
without a banking runtime ready to deploy. No cloud service has been deployed.

## Reading the evidence correctly

- Numerical calculations are integer and finite-model tests. The
  [correlated campaigns](../experiments/circuit/RESULTS_2026-10-17.md) distinguish
  Octave and MATLAB R2026b runs. The written proof remains
  conditional on the primitives.
- Bulletproofs proofs and RISC Zero receipts are real within their profiles.
  The historical MCP DevSecOps simulator remains explicitly a simulation.
- Vega SHA-256 results are references reproduced on a different
  relation; no equivalent outperformance or global record is established.
- The Horizon stack uses elliptic-curve groups and Ed25519. It is not
  post-quantum. FIPS 204/205 are not sufficient to make its circuit PQ.
- Register hashes bind selected bytes. Dates and commits
  declared in a manifest are not authenticated by these hashes.
- Historical CPU benchmarks do not automatically measure new
  transports; a blocked CUDA attempt does not become a GPU measurement.

Publishing code, publishing an npm package, deployment and production
qualification are separate decisions. Only the Proofkit SDK is distributed
separately with this prerelease; the other npm workspaces remain private.
See [PACKAGES.md](../../PACKAGES.md), the workflows and the release
manifest for the Git revision, checks run and actual artifacts.
