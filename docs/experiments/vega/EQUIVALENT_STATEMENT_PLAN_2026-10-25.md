# H12 — Equivalent-statement comparison with Microsoft Vega: protocol, blockers, decision

Date: 25 October 2026. Status: **research protocol; no new measurement, no
ratio, no record claim**. Backlog entry `H12` (P1). Acceptance: equivalent
signatures, statements, environment and boundaries; otherwise separate
comparisons, never a record claim.

This document fixes what "equivalent statement" means for a comparison
between the Horizon profile and Vega, lists what the repository can and cannot
reproduce today, and states the decision rule for publishing any figure. The
executed references and their limits are in the dated
[comparison](../../horizon/COMPETITOR_COMPARISON.md) and in
[BENCHMARK_RESULTS.json](../../horizon/BENCHMARK_RESULTS.json); the sampling and
timing rules are in the [benchmark methodology](../../horizon/BENCHMARK_METHODOLOGY.md).

## 1. What has been executed, and what it is not

| Executed | Where | What it shows | What it does not show |
| --- | --- | --- | --- |
| Vega upstream SHA-256 benches (`sha256_vega_mc_zkp`, `sha256_vega_sc`), pinned commit `c0ee259…`, 8 CPU / 12 GiB Linux container, Criterion central estimates | `scripts/horizon-vega.mjs`, `labs/horizon/reference/vega-Cargo.lock` | The pinned public code builds and its SHA-256 benches run in the same container family as Horizon's cryptographic benches | The paper's credential-presentation application (parsing, signature verification, proof of possession): the published repository does not provide that circuit |
| Horizon A / B / disclosure baseline, 500 samples per phase over five value cases, quantiles with binomial ranks | `scripts/horizon-benchmark.mjs`, `BENCHMARK_RESULTS.json` | Costs of a two-range relation over Pedersen commitments, with issuer and holder signatures verified **outside** the proof | Any relation that hides a signature or parses a credential inside the proof |
| Historical RISC Zero DevSecOps receipt (154–163 s CPU) | `labs/risc0`, `tests/fixtures/risc0` | A different relation under a zkVM with in-guest signatures | A speed ratio against Horizon or Vega |

Three relations, three disclosure models. The three cryptographic references
ran in the same 8 CPU / 12 GiB Linux container; only the Windows durable bench
of Horizon B differs and is not in this table. **No row is comparable to
another as a ranking.** The paper's figures (92 ms online prove / 23 ms verify /
108 kB, MC mode, 16 threads, Azure Standard F16as v7 with 16 vCPU and 64 GB,
simulated signing device, as recorded in
[STATE_OF_THE_ART](../../horizon/STATE_OF_THE_ART.md)) come from a relation
the repository cannot run.

## 2. Definition of an equivalent statement

A comparison figure may be published only if all five columns are equal for
both systems, with evidence for each:

| Dimension | Required equality | Horizon today | Vega today (pinned code) |
| --- | --- | --- | --- |
| Statement | Same public inputs, same relation (what is proven), same hidden set | Two 32-bit ranges over derived Pedersen commitments; amounts hidden; signatures public | SHA-256 circuits over 1–2 KiB inputs; the paper's credential relation hides the issuer signature and parses the credential |
| Signatures | Same scheme, same placement (inside or outside the proof), same count | Ed25519, two issuer + one holder, **outside** the proof | Credential signature **inside** the proof in the paper; none in the SHA benches |
| Disclosure | Same information released to the verifier | Commitments, metadata, verdict public; values hidden | Depends on the circuit; not reproducible here |
| Environment | Same machine class, threads, memory limit, OS, compiler flags, warm/cold policy | 1 thread for Horizon cryptographic benches; 8 threads for the Vega SHA benches, same container | Paper: Azure Standard F16as v7, 16 vCPU, 64 GB, 1 and 16 threads; the local Vega benches ran with 8 threads in a 12 GiB container |
| Boundaries | Same phases timed (setup, preparation, proof, presentation, verification, transport), same statistics (quantiles with CI versus central estimates) | Phases separated, p50/p95/p99 with binomial ranks; first presentation (A) versus reused presentation (B) | Criterion central estimates (slope estimate for MC, flat-mode estimate for SC); setup, preparation and online prove reported separately in the paper |

Beyond these five, the [benchmark methodology](../../horizon/BENCHMARK_METHODOLOGY.md)
also freezes the issuance contract, the trust roots, the freshness checks
(nonce, epochs, dates) and the cache conditions; a comparison must state them
for both systems, and must map "first presentation" to Horizon A and "reused
presentation" to Horizon B explicitly.

Today **zero** dimensions are equal across the board. Publishing a ratio would
be a record claim without an equivalent statement, which `AGENTS.md` and the
[claims register](../../publication/CLAIMS.md) forbid.

## 3. Two admissible paths

**Path A — port Horizon's statement to Vega.** Express "two 32-bit ranges over
two Pedersen-committed values with public issuer and holder signatures" in
Vega's framework, using its own commitment and range primitives if they exist,
or its generic circuit layer otherwise. Requirements: an authorized
specification of Vega's circuit interface at the pinned commit; signatures kept
outside the proof on both sides; Vega's acceptance contract included in the
timed verification (its API returns the public values and the application must
compare them with the expected statement, as recorded in
[STATE_OF_THE_ART](../../horizon/STATE_OF_THE_ART.md)), or the boundary
difference stated; identical bounds `1 ≤ a ≤ 2^32`,
`a ≤ c ≤ a + 2^32 − 1`; identical hidden set. Outcome: a comparison of two
proof systems on **Horizon's** statement. It says nothing about credential
presentation.

**Path B — port Vega's credential statement to Horizon.** Horizon would have
to hide the issuer signature inside the proof, which Bulletproofs range proofs
do not do; it would need a different proof system (a zkVM or a general
circuit), that is, a new profile with a new identifier, new vectors and a new
review. Outcome: a comparison on **Vega's** statement, between Vega and a
Horizon-successor that does not exist.

Either path requires the same machine, the same thread count, the same
memory limit, the same compiler flags, the same warm/cold policy, the same
timing boundaries and the same statistics, run in one campaign, with raw
samples published. Mixed sources (a paper figure against a local quantile) are
not admissible.

## 4. Decision rule

```text
equivalent_statement(A, B) and same_environment(A, B) and same_boundaries(A, B)
    -> publish both distributions side by side, with CIs, no ratio anywhere
otherwise
    -> publish separate tables with their own scope lines, never a ratio,
       never "faster than", never "record"
```

The word "record" is excluded in every case: a laboratory campaign on one
machine does not establish a record even with an equivalent statement.

## 5. Blockers and what would unblock them

| Blocker | Evidence | Unblocked by |
| --- | --- | --- |
| Vega's credential circuit is not in the pinned repository | `COMPETITOR_COMPARISON.md`, "reproduction … remains blocked by the relation not being provided" | An authorized specification or published code of the exact circuit, with its signature scheme and parsing |
| No shared statement | Section 2 | Path A implementation and review, or a Horizon successor (Path B) |
| Different thread counts and statistics in the executed references | 1 thread versus 8 threads; quantiles versus Criterion central estimates | One campaign script running both under identical settings, raw samples kept |
| Paper machine differs from the local container | Azure Standard F16as v7, 16 vCPU, 64 GB versus 8 CPU / 12 GiB container | Rerun on the same hardware class or state the difference and avoid ratios |

No resource is requested now. If Path A is attempted, its budget is one
engineer-week of specification reading plus a bounded Linux campaign on the
existing 8 CPU / 12 GiB container; no GPU, no cloud.

## 6. What this document is not

Not a measurement, not a critique of Vega's correctness, not a statement that
Horizon is faster or slower than Vega on any task. The only controlled
improvement measured in this repository is internal to Horizon (retained public
generators, A proof p95 −15.75 %, B verification p95 −44.97 %), on an
unchanged relation and format, from one before/after campaign on one machine:
not a universal speedup or an external scientific record, and a known
optimization.

## 7. Review

An internal read-only audit by the benchmark auditor agent on 25 October 2026
corrected this note before it entered the repository: the paper's machine is
recorded in the repository (not "unknown"), all three cryptographic references
share one container, sampling is 500 per phase over five value cases, Criterion
figures are central estimates, "no ratio" admits no exception, and the
methodology's additional frozen dimensions (issuance contract, trust roots,
freshness, cache, A versus B mapping, Vega's public-value comparison) are now
listed. The audit is internal and is not an audit of either system.
