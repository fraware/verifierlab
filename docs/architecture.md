# Architecture

```text
CLI (valab)
    → Campaign engine (attack plane)
        → Local launcher (default)  or optional Slurm / Kubernetes
            → Workers (process pool preferred; threads opt-in)
                → Environment + VerifierBroker (no GT imports)
    → FreezeRecord (append-only)
    → AdjudicationService (coordinator; loads GT)
    → LabelVault v2 + label release
    → StatsPlan compiler / offline report rebuild
```

## Content addressing

Artifacts are serialized as canonical JCS-style JSON and digested with SHA-256.
Digests form directory keys under `.valab/store/sha256/<prefix>/<digest>`.

## Run bundles

Each campaign run writes:

```text
.valab/runs/<run_id>/
  manifest.json      # pointer / index to lifecycle tip
  checkpoint.json    # resume state
  work_units/        # attack-plane unit results (no gt_valid)
  vault/             # commitments + sealed labels
  adjudications/     # post-freeze GT evaluations
  attackers/         # persistent strategy checkpoints
  report/            # after release + `valab report builds`
```

Failed units are persisted for visibility. Resume is automatic when the run
directory already exists (`resume=True` default in the engine).

## Trust split (coordinator vs workers)

- Workers execute environment / verifier episodes via `VerifierBroker` and return
  public outcomes + trajectory commitments (`digest(traj || nonce)`).
- The coordinator freezes, adjudicates with GT, commits sealed labels, and
  releases them for analysis. Strategies observe `public_attack_feedback` only.
- Reports require `freeze → adjudicate → release-labels`.

## Import constraint

The base package must not import torch, ray, Kubernetes client libraries, or model
SDKs. Optional extras in `pyproject.toml` pin real packages (gymnasium,
inspect-ai, harbor, openenv, boto3, kubernetes) where they exist; adapters fail
closed or skip when extras are absent. See [adapters.md](adapters.md) and
[limitations.md](limitations.md).

## Extension points

- `verifierlab.plugins` entry points (`valab plugins list`)
- Python adapters under `verifierlab.targets.*` (shared conformance harness)
- Attack strategy registry under `verifierlab.attacks`
- Disclosure registry under `verifierlab.disclosure`

## Related docs

- [Concepts](concepts.md)
- [Threat model](threat-model.md)
- [Getting started](getting-started.md)
