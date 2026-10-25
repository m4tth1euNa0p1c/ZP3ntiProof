# Publication claims register

Editorial status: October 17, 2026. “Demonstrated” means only within the
scope of the cited artifact. Historical results do not automatically validate
a later SDK or deployment. The release log must
identify the candidate commit and its current checks.

| ID | Admissible claim | Status and evidence | Limitation / falsification condition |
| --- | --- | --- | --- |
| P01 | The Horizon profile proves a relation over two committed amounts | Implementation and [statement](../horizon/FORMAL_STATEMENT.md); since 2026-10-25 two synthetic [issuer adapters](../horizon/ISSUER_PROVENANCE_2026-10-25.md) issue the attestations from real-format sources with revocation | Truth of facts and honest issuance outside the proof; synthetic issuers only, no KMS or real source; H13 remains open for real issuers |
| P02 | Amounts a and c remain hidden from the controller in the intended presentation | Model and [analysis](../horizon/CRYPTOGRAPHIC_DESIGN.md) | Public commitments A and C; prover knows both openings; correlatable metadata; external audit H15 absent |
| P03 | B reuses an immutable proof and signs a complete fresh challenge | [Architecture](../horizon/ARCHITECTURE.md) | Not a new proof of knowledge; no promise of unlinkability |
| P04 | Invalid requests in the tested scenarios do not trigger the local effect | Tests and [log](../horizon/EXPERIMENT_LOG.md); since 2026-10-25 the [SEC-1 binding suite](../horizon/VERIFIER_BINDING_TESTS_2026-10-25.md) lists each refused case, its code and the target counter | List the cases and commit; no universality over all inputs |
| P05 | Replay protection and operation reservation survive the tested local restart | [Local deployment](../horizon/DEPLOYMENT.md), SQLite; since 2026-10-25 a [separate sandbox target](../horizon/REMOTE_TARGET_2026-10-25.md) with idempotency key, version precondition and fence is exercised by nine counted scenarios | Laboratory target contract only; no remote banking API, no target authentication; H14 remains open for a real operator-accepted contract |
| P06 | B verifies at p95 1.247 ms in the CPU benchmark after optimization | [Frozen report](../horizon/BENCHMARK_RESULTS.json) and associated raw data | 500 samples/case, specific machine and scope; not an SLA |
| P07 | The observed durable path has a p95 of 13.014 ms | Same report, Windows IPC and SQLite campaign | 10 ms objective not met; maximum 180.310 ms |
| P08 | A prepared B presentation can cost less than a fresh A proof | Measurements of separate phases | Compare the functions actually provided; not a ZKP record |
| P09 | The project contains extension points for verified tools | `packages/proofkit-sdk`, current checks to record in the release log | Adapters remain a trust boundary; no universal generator of safe circuits |
| P10 | Azure/GCP foundations can be validated locally | [Validation](VALIDATION.md), IaC sources | No cloud deployment or IAM/network test performed |
| P11 | Buyer need justifies ZK complexity | **Not established**, H11 | Abandon if a signed verdict/disclosure is acceptable or there is no budget and sponsor |
| P12 | No identical offering exists on the market | **Not demonstrated** | [Bounded search](../horizon/NOVELTY_AND_PRIOR_ART.md); no universal absence or legal freedom to operate |
| P13 | The profile is post-quantum | **False for Horizon** | Bulletproofs/Ristretto and Ed25519 do not provide this guarantee |
| P14 | The system is DORA, AI Act or banking qualified | **Not established** | Code and a log do not constitute a regulatory assessment |
| P15 | The sealed package is authentic and its results true | **Not established by a hash alone** | A hash binds bytes; signer identity, time and truth require other evidence |
| P16 | The correlated benchmark processes 4,096 vectors with 4,086 valid proofs, 4,106 invalid candidates and 36,794 verifications | [Windows/Linux and MATLAB R2026b campaigns](../experiments/circuit/RESULTS_2026-10-17.md), 0 observed disagreements | Synthetic finite tests; same library in a separate verifier process; invalid candidates distinct from valid proofs; not a soundness bound |

Any change to a row must state the new supporting evidence and the limitations
removed or added. A rejected claim remains visible to prevent
its accidental reintroduction in commercial materials.

## DevSecOps review for a customer presentation — October 17, 2026

Sources examined: `1ff00fc8663bd88e0ba6ff7f571ddef62d16fc7f`.
The [focused dossier](devsecops-client/README.md) separates code, execution and proposed integration.

| ID | Admissible claim | Status and evidence | Limitation / falsification condition |
| --- | --- | --- | --- |
| P17 | The MCP DevSecOps flow enforces a policy and verifies before the simulated merge | **Verified locally**, [validation](devsecops-client/VALIDATION.json), 14 Rust tests, 25 Node/MCP tests and critical demo with 23 denials without an additional merge | Witness-disclosing simulator, fixtures and in-memory stores; no customer mutation or crash recovery |
| P18 | The retained RISC Zero verifier accepts the historical authorizing receipt and rejects the five counter-cases for the expected reasons | **Reverified**, [six cases](devsecops-client/RISC0_REVERIFICATION.json) | Retained binary not rebuilt from HEAD; synthetic authority, fixed logical time; no dispatch or new proof generated |
| P19 | Playwright and an autonomous LLM agent are integrated and evaluated on this flow | **Not demonstrated**, [inventory and target](devsecops-client/README.md) | No Playwright in the tracked files examined; tests use the MCP client with fixed arguments |
| P20 | Authentic Jira/Sonar/GitLab APIs currently feed the authorization | **Not demonstrated**, [fixtures](../../packages/enterprise-gateway/src/connectors.ts) | Local collector HMAC and synthetic objects; do not attribute them to the vendors |
| P21 | Proofkit SDK and registry tests pass for this validation | **Verified**, [21 tests after rerun](devsecops-client/VALIDATION.json) | Initial sandbox EPERM retained; adapters carry crypto, persistence and mutation; no SLA inferred |
| P22 | Microsoft Research provides a scientific reference for proven actions and limited disclosure | **Primary sources consulted**, [dossier](devsecops-client/README.md) | Magnetar not integrated; Vega SHA-256 is a separate benchmark; no transferred endorsement, partnership, record or PQ guarantee |
