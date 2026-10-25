# H16 — CPU, GPU and post-quantum research: feasibility, evidence rules and resource budget

Date: 25 October 2026. Status: **research note; no new measurement, no GPU
run, no post-quantum claim**. Backlog entry `H16` (P1). Acceptance: no GPU
benchmark without a GPU receipt independently verified; full post-quantum
chain required, no signature-only relabeling; cost and limits explicit.

## 1. Where the evidence stands

| Track | Executed | Result | Document |
| --- | --- | --- | --- |
| CPU, Horizon cryptographic functions | 500 samples per phase over five value cases, 1 thread, Linux container 8 CPU / 12 GiB | A proof p95 6.546 ms, B verification p95 1.247 ms, 672-byte proofs; durable Windows path p95 13.014 ms, maximum 180.310 ms | [BENCHMARK_RESULTS.json](../../horizon/BENCHMARK_RESULTS.json), [EXPERIMENT_LOG](../../horizon/EXPERIMENT_LOG.md) |
| CPU, historical RISC Zero DevSecOps receipt | Real `Succinct` receipts, generations 153.681, 163.232, 158.619 and 157.560 s in the same 8 CPU / 12 GiB container | Different relation (in-guest Ed25519 attestation), verified by the independent verifier of `labs/risc0` | [RISC Zero lab results](../../08-RISC0-LAB-RESULTS.md) |
| GPU, RISC Zero 3.0.6 CUDA | Two attempts, 17 October 2026, RTX 5060 Ti, CUDA 12.8.1, container limited to 12 GiB of RAM | **No GPU receipt**: compilation of the recursive CUDA kernel by `nvcc` stopped by the container's RAM limit (cgroup OOM), with four Cargo jobs then one | [GPU results](RESULTS_2026-10-17.md), [protocol](README.md) |
| GPU, Horizon (Bulletproofs) | Never attempted | — | — |
| Post-quantum | Not implemented anywhere | Horizon: Bulletproofs/Ristretto + Ed25519, classical; RISC Zero lab: STARK stack but Ed25519 attestation in the guest | [THREAT_MODEL](../../horizon/THREAT_MODEL.md), [GPU README](README.md) |

The negative GPU result is preserved as is: it demonstrates neither
incompatibility nor impossibility, only that this configuration did not
produce a receipt. The `test:risc0:gpu` command in the validation profiles
runs the runner's unit tests, not a CUDA proof.

## 2. Evidence rules (what may be written, and when)

### 2.1 GPU

A GPU figure may be published only with all of the following, in one dated run
directory: the image digest and driver version; the exact command and flags
(`-arch`, features, `--locked`); the receipt bytes and their SHA-256; an
**independent CPU verification** of that receipt on a different host or at
least a different process without the GPU; the dev-mode rejection and the
hidden-GPU rejection executed in the same run; raw per-sample durations with
N, warm/cold policy and what the timer brackets. Without a receipt there is
no GPU benchmark, whatever the setup time measured.

Any GPU/CPU ratio must come from the same relation, the same guest, the same
proof type and the same statistics in one campaign. The historical CPU
receipts (154–163 s) may be cited as context, not as the denominator of a
ratio computed against a future GPU run on another day or another host.

For Horizon (Bulletproofs), a GPU attempt would first require a reason: the
CPU verification already sits at about 1.2 ms p95 and the proof at about
6.5 ms p95 on one thread. A GPU would be justified only for a batch workload
whose profile and volume a buyer has stated; none has (H11 open). Zero GPU
resources are planned by default, as the cloud comparison already states.

### 2.2 Post-quantum

"Post-quantum" may be written about a profile only when **every** link of the
chain resists the stated quantum adversary, with sources:

| Link | Horizon today | What a PQ profile would need |
| --- | --- | --- |
| Commitment | Pedersen over Ristretto: hiding is unconditional, binding relies on discrete log; a quantum adversary could open a commitment to another value (forgery), not read past commitments | A commitment whose binding rests on a post-quantum assumption (lattice- or hash-based), with its own hiding/binding analysis |
| Range / relation proof | Bulletproofs: discrete-log assumptions, Fiat–Shamir | A proof system whose soundness is argued against quantum adversaries (hash-based STARK-style systems are conjectured so in the quantum random-oracle model, lattice-based systems under lattice assumptions; both are external claims not sourced in this repository), re-deriving the two-range statement and its bounds |
| Issuer signatures | Ed25519 | FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA) over the same canonical bytes, with new domain strings and a new profile identifier |
| Holder signature | Ed25519 | Same as above |
| Transport and key exchange | Not in scope of the profile; HTTP on loopback in the laboratory | Post-quantum or hybrid key establishment at the transport layer, outside this profile |
| Transcript hashing | SHA-256 for commitments and audit; Merlin transcripts (STROBE over the Keccak-f[1600] permutation, an external fact about the pinned `merlin` crate, distinct from the Keccak-256 used by Vega) | Hash functions are expected to keep collision resistance and lose part of their preimage margin to Grover-type search (external claim, unsourced here); parameters to restate |

**Replacing only the signatures by FIPS 204/205 does not make the profile
post-quantum**: the commitments and the range proof remain discrete-log based.
Conversely, the RISC Zero `Succinct` STARK stack does not make the DevSecOps
laboratory post-quantum either, because the in-guest attestation is Ed25519.
A PQ profile is a **new profile** (new identifier, new vectors, new review,
new performance campaign), not a parameter change of `horizon-range-v1`.

### 2.3 CPU

CPU figures remain bound to their machine, thread count, sample size and
timing boundaries. The methodology's rules apply unchanged
([BENCHMARK_METHODOLOGY](../../horizon/BENCHMARK_METHODOLOGY.md)): no figure
becomes an SLA, no local p95 becomes a cloud transaction price.

## 3. Feasibility assessment

| Question | Assessment | Basis |
| --- | --- | --- |
| Can the CUDA RISC Zero receipt be obtained? | Unproven: the blocker was the container's 12 GiB RAM limit during `nvcc` compilation of the recursive kernel, not GPU memory and not a runtime failure; nothing shows that a higher limit suffices | GPU results; the host has about 32 GiB of RAM ([lab results](../../08-RISC0-LAB-RESULTS.md)) and the 12 GiB limit is a protocol choice, so raising it is a documented protocol change, not a fix |
| Would a GPU change the Horizon decision? | No, on current evidence: millisecond-level CPU costs and no stated batch volume | Benchmark results, H11 open |
| Is a post-quantum Horizon profile a parameter change? | No: four of the six links (commitment, range proof, issuer and holder signatures) must change, with new analyses | Section 2.2 |
| Is a post-quantum profile needed by a buyer? | Unknown; must not be invented | H11 open ([review protocol](../../horizon/REVIEW_PROTOCOL.md), claim P11), claims register P13 "False for Horizon" |
| Can the repository state any PQ or GPU performance number today? | No | Sections 1–2 |

## 4. Resource budget (parameterized, no invented amounts)

Prices, regions and volumes are unknown and must be taken from official pages
at estimation time, as the [cloud comparison](../../publication/CLOUD_COMPARISON.md)
requires. Each experiment below lists its inputs, not an amount.

| Experiment | Inputs to cost | Fixed limits |
| --- | --- | --- |
| CUDA RISC Zero receipt, local host | Engineer time (one to two days), electricity; container memory limit raised above 12 GiB **as a documented change of the protocol**; no driver change, no paid service | Stop at the first receipt plus independent verification; N ≤ 10 samples for the first run; no ratio published |
| CUDA RISC Zero receipt, rented GPU | Hourly GPU price × hours × runs, image storage, egress of receipts; dated price source; spending cap | Needs explicit user authorization (`CLAUDE.md`: never spend cloud resources or rent GPUs silently); not planned |
| Horizon GPU attempt | Not budgeted: no justification on current evidence | — |
| PQ profile study (paper only) | Engineer time (one to two weeks) to select candidate primitives, restate the relation and the bounds, list new domain strings | No implementation before the study is reviewed |
| PQ profile implementation | New crate or profile, vectors, review, campaign; dependencies pinned; external audit required before any claim | Out of scope of the current backlog |

The repository's own fixed validation profiles cost only CPU time on the
runner; they run no proving on GPU and no cloud call.

## 5. Review

An internal read-only audit by the benchmark auditor agent on 25 October 2026
corrected this note before it entered the repository: the GPU blocker was the
container's RAM limit during compilation, not GPU memory; the historical
RISC Zero timings and their verification are sourced from the lab results, not
from an untracked re-verification file; four of six chain links change for a
PQ profile; sampling is 500 per phase over five value cases; external
cryptographic statements in the chain table are flagged as such. The audit is
internal and is not an audit of the primitives.

## 6. What this note is not

Not a benchmark, not a GPU result, not a post-quantum design, not a price. It
records the rules under which such results could later be written, the single
negative GPU observation already in the repository, and the fact that no
buyer requirement for GPU throughput or post-quantum security has been
established.
