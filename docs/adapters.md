# Adapters

External system adapters live under `verifierlab.targets` and are gated by
optional extras. When an SDK is missing, imports fail with an install hint or
tests skip with an explicit reason—never a silent stub pass.

## Install

```bash
pip install "verifierlab[gym]"
pip install "verifierlab[inspect]"       # pins inspect-ai
pip install "verifierlab[harbor]"        # pins harbor; Python >=3.12
pip install "verifierlab[nemo]"          # HTTP client + stdlib reference server
pip install "verifierlab[openenv]"       # optional heavy SDK; reference path works without it
pip install "verifierlab[objectstore]"   # boto3 S3-compatible CAS
pip install "verifierlab[kubernetes]"
pip install "verifierlab[adapters]"      # gym + inspect + harbor + openenv + nemo
```

Or with uv: `uv sync --extra gym` (and similarly for other extras).

## Matrix

| Adapter | Extra | What is live | What is not claimed |
| ------- | ----- | ------------ | ------------------- |
| Native `@verifier` | (base) | Python callable + VALAB-02 contract | — |
| Gymnasium | `[gym]` | Wrap `gymnasium.Env` as `EnvironmentTarget` | Full RL training stack |
| Inspect | `[inspect]` | Task / eval / eval-log mapping via `inspect-ai` | Hosting Inspect’s full product surface |
| Harbor | `[harbor]` | ATIF parse/validate via Harbor types (Py≥3.12); stateful episode | In-process Harbor sandbox/agent orchestration |
| NeMo Gym HTTP | `[nemo]` | HTTP client + in-repo reference resources server | NVIDIA training containers / Ray loops |
| OpenEnv | `[openenv]` | HTTP `/reset` `/step` `/state` + reference env | HF Spaces / Docker provider automation |
| Trainer | `[rl]` / `[trainer]` | Broker-only trainer step loop (`TrainerAdapter`) | Heavy external trainer SDKs |
| S3 CAS | `[objectstore]` | boto3 client (AWS / MinIO) | Default remains filesystem CAS |
| Slurm | `[slurm]` | Live when `sbatch`/`squeue`/`scancel` exist | Otherwise explicit dry-run |
| Kubernetes | `[kubernetes]` | Live Job create/status/delete when client works | Otherwise explicit dry-run |

VALAB-09 release matrix (six integrations): native, Gymnasium, Inspect, OpenEnv,
Harbor (stateful), trainer. See [reproduction-checklist.md](reproduction-checklist.md).

## CI posture

- Default CI: format, mypy, pytest with coverage threshold, packs A/B/F,
  process + thread smokes, refund lifecycle smoke, reproducible bundle check.
- Multi-OS process matrix (Windows may `continue-on-error` initially).
- Inspect / Harbor: fixture log-format regression always; live SDK paths when
  installed (extras matrix / schedule).
- NeMo / OpenEnv: live client against local reference HTTP servers in CI.
- Gym: skip or `ImportError` without gymnasium; tiny discrete env when present.
- CodeQL on PR/push; pip-audit + SBOM on release tags.

Shared conformance: `verifierlab.targets.conformance.run_conformance` covers
decision normalization, timeout/error mapping, and hidden-label isolation.

Details and non-claims: [limitations.md](limitations.md).

## Library usage

There is no `valab adapter` subcommand in this alpha. Import adapters from
Python (for example `verifierlab.targets.gym_adapter`) after installing the
matching extra. Fake / in-tree tutorial targets need no extra.
