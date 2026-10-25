# RISC Zero 3.0.6 CUDA experiment — October 17, 2026

This laboratory checks whether **the same critical DevSecOps guest** as the
historical CPU testbed produces a `Succinct` receipt with the local RTX 5060 Ti.
It triggers no business action. Results and blockers are retained in dated
`runs/` directories; `run.json` gives the actual state. A visible GPU,
a successful build or a stop before verification is not a proof.

**October 17 result: blocked during CUDA compilation under 12 GiB,
with four then one Cargo job. No GPU receipt produced.**
See the [two-attempt report](RESULTS_2026-10-17.md), with logs,
OOM counters and checks actually executed.

## Reproduction

```bash
node --test labs/risc0/gpu/runner.test.mjs
node scripts/risc0-gpu-lab.mjs probe
node scripts/risc0-gpu-lab.mjs critical 1
# Resume the container retained in run.json after diagnosing a blocker:
node scripts/risc0-gpu-lab.mjs critical 1 zk-agentik-risc0-gpu-<identifier>
```

Scenarios are `base`, `critical` and `denied`, with 1 to 3 generation
measurements. Development mode is rejected before any Docker call and inside
the executables. Each invocation retains its own files; it overwrites neither
CPU receipts nor the historical CPU container.

The runner builds a CUDA user-space image and starts a new container limited
to **8 CPU, 12 GiB RAM, 512 processes, one Cargo job**, with capabilities
removed and `no-new-privileges`. The repository is mounted read-only and then
copied into the container for compilation. The GPU remains shared with the
desktop: neither exclusivity nor a hardware VRAM limit is guaranteed.
Installation uses the network; it is removed before tests and generation.
The container is stopped and retained at the end of an attempt.

The independent check uses a new container without GPU or network access,
with a single read-only public mount: verifier, receipt and expected inputs.
Its image contains CUDA/Rust for glibc compatibility, but contains neither
the compiled prover, witness nor repository. The variables
`NVIDIA_VISIBLE_DEVICES=void` and `CUDA_VISIBLE_DEVICES=-1` hide GPUs.

## Compatibility and primary references

- NVIDIA identifies CUDA **12.8** as the first release supporting Blackwell,
  capabilities 10.0 and 12.0. The CUDA number displayed by `nvidia-smi` is
  the driver's maximum supported version, not the version of an installed toolkit.
  [NVIDIA matrix](https://docs.nvidia.com/datacenter/tesla/drivers/cuda-toolkit-driver-and-architecture-matrix.html).
- CUDA 12.8 notes document the Linux/Windows/WSL runtime and driver prerequisites.
  The experiment uses CUDA **12.8.1** with explicit compilation flag
  `NVCC_APPEND_FLAGS=-arch=sm_120`, on Windows driver **595.95**, without
  installing a host driver or changing global Docker configuration.
  [CUDA 12.8 notes](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-toolkit-release-notes/).
- RISC Zero requires the CUDA runtime to execute and the toolkit to compile
  kernels; initial JIT compilation may take time. Local generation keeps the
  witness with the prover operator, who can read it.
  [Local proving, 3.0 documentation](https://dev.risczero.com/api/generating-proofs/local-proving).
- The `cuda` feature of `risc0-r0vm` enables the corresponding `risc0-zkvm`
  feature. Segment selection is a CUDA compilation branch, without CPU fallback
  in that function; the protocol also includes a test with the GPU hidden.
  [v3.0.6 manifest](https://github.com/risc0/risc0/blob/v3.0.6/risc0/r0vm/Cargo.toml),
  [v3.0.6 prover selection](https://github.com/risc0/risc0/blob/v3.0.6/risc0/circuit/rv32im/src/prove/mod.rs),
  [v3.0.6 CUDA build](https://github.com/risc0/risc0/blob/v3.0.6/risc0/circuit/rv32im-sys/build.rs).

Upstream issue [#3785](https://github.com/risc0/risc0/issues/3785) reports a
CUDA **Groth16** wrapping problem in 3.0.5/3.0.6. It is a report, not an audit;
this experiment requests only `Succinct` and tests no Groth16 wrapping.
It therefore supports neither a claim that this testbed fails nor a guarantee
that no other defects exist.

## Pinning and provenance

| Component | Version or identity |
| --- | --- |
| RISC Zero source | `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` (`v3.0.6`) |
| External prover features | `cuda,disable-dev-mode` |
| Linux amd64 CUDA base | `nvidia/cuda@sha256:4b9ed5fa8361736996499f64ecebf25d4ec37ff56e4d11323ccde10aa36e0c43` |
| Rust source image | `rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922` |
| Host / guest Rust | `1.98.0` / RISC Zero `1.97.0` |
| Requested type | `Succinct`, `poseidon2`, segment `po2=20` |
| Expected ELF | `sha256:53cbbc340bc8ab586353893f22d64daf5ffa756a41c798a55db203ca3ee9d29e` |

Cargo dependencies remain locked. Ubuntu packages needed for the build are
resolved during image construction and then inventoried by `dpkg-query`;
they are not individually pinned to an APT snapshot. The final image ID,
hashes of copied sources, lockfiles and executables, versions, commands,
exit codes and durations are retained. This makes this execution auditable
without promising a bit-for-bit reproducible build on another host.

## Measurements and success criteria

Success requires a real receipt, a guest identical to the historical CPU one,
dev-mode and hidden-GPU rejections, then independent CPU verification.
Generation measurements come from the unchanged host: they include the local
`r0vm` call and its checks, exclude build and Docker startup.
No warmup is discarded. Command durations are separate.

The raw report inherited from the host contains a `real CPU proof` label and
a generation `p95_ms` over small N. **These inherited fields do not characterize
this CUDA experiment.** Metadata in the new `run.json` specifies the accelerator
and values in order, minimum, maximum and mean; its `p95_ms` and `p99_ms`
are `null`. The raw report is retained as is.
Repeated warm verification of the same receipt measures neither a service
nor concurrency. No SLA, record, controlled GPU/CPU ratio or guarantee of
critical confidentiality follows from this exploratory testbed.

The `Succinct` scheme uses RISC Zero's STARK stack, but the guest attestation
uses **Ed25519** and a public fixture key. The complete system is therefore
**not post-quantum** and authenticates no real supplier. Selecting CUDA changes
neither this limitation nor the trust model.
[NIST describes migration of vulnerable elliptic-curve primitives](https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/)
to post-quantum signatures and key establishment; this profile does not
perform that migration.

## Evidence rules and budget (25 October 2026)

What a future GPU figure or post-quantum statement would require, and a
parameterized budget without invented amounts, are in
[CPU_GPU_PQ_FEASIBILITY_2026-10-25.md](CPU_GPU_PQ_FEASIBILITY_2026-10-25.md).
The negative result above is unchanged.
