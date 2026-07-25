# Architecture

```text
CLI (valab)
    → Campaign engine
        → Local launcher (default)  or optional Slurm / Kubernetes
            → Workers (thread or process pool)
    → Budget / ledger
    → Targets (environment, verifier, ground truth)
    → Filesystem CAS (.valab/store)
    → Run bundle (.valab/runs/<run_id>)
    → Offline report rebuild
```

## Content addressing

Artifacts are serialized as canonical JCS-style JSON and digested with SHA-256.
Digests form directory keys under `.valab/store/sha256/<prefix>/<digest>`.

## Run bundles

Each campaign run writes:

```text
.valab/runs/<run_id>/
  manifest.json      # digests, status, schema_version
  checkpoint.json    # resume state
  work_units/        # idempotent unit results
  report/            # after `valab report builds`
```

Failed units are persisted for visibility. Resume is automatic when the run
directory already exists (`resume=True` default in the engine).

## Trust split (coordinator vs workers)

- Workers execute environment / verifier episodes and return public outcomes.
- The coordinator commits labels and enrichments; strategies observe
  `public_attack_feedback` only (no `gt_valid` before release).
- Freeze seals the vault; post-freeze injection is rejected.

## Import constraint

The base package must not import torch, ray, kubernetes client libraries, or model
SDKs. Optional extras in `pyproject.toml` pin real packages (gymnasium,
inspect-ai, harbor, openenv, boto3, kubernetes) where they exist; adapters fail
closed or skip when extras are absent. See [adapters.md](adapters.md) and
[limitations.md](limitations.md).

## Extension points

- `verifierlab.plugins` entry points (`valab plugins list`)
- Python adapters under `verifierlab.targets.*`
- Attack strategy registry under `verifierlab.attacks`
- Disclosure registry under `verifierlab.disclosure`

## Related docs

- [Concepts](concepts.md)
- [Threat model](threat-model.md)
- [CLI](cli.md)
