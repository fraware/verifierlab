# Adapters

External system adapters live under `verifierlab.targets` (and
`verifierlab.trainers` for RLlib) and are gated by optional extras. When an SDK
is missing, imports fail with an install hint or tests skip with an explicit
reason—never a silent stub pass. Fixture-only paths are never labeled live.

## Install

```bash
pip install "verifierlab[gym]"
pip install "verifierlab[inspect]"       # pins inspect-ai
pip install "verifierlab[harbor]"        # pins harbor; Python >=3.12
pip install "verifierlab[nemo]"          # HTTP client + stdlib reference server
pip install "verifierlab[openenv]"       # optional heavy SDK; reference path works without it
pip install "verifierlab[envassure]"     # forward pin; may be unpublished
pip install "verifierlab[rllib]"         # exact ray[rllib]==2.48.0
pip install "verifierlab[objectstore]"   # boto3 S3-compatible CAS
pip install "verifierlab[kubernetes]"
pip install "verifierlab[adapters]"      # gym + inspect + harbor + openenv + nemo
# Opt-in (not in [adapters] composite): envassure (may be unpublished), rllib (heavy)
```

Or with uv: `uv sync --extra gym` (and similarly for other extras).

## Per-adapter pages

Each page lists supported versions, live vs fixture, boundary, mapping,
unsupported semantics, conformance command, CI status, example, and
troubleshooting:

- [Native](adapters/native.md) — Example V1
- [Gymnasium](adapters/gymnasium.md) — Example V2
- [Inspect](adapters/inspect.md) — Example V3
- [OpenEnv](adapters/openenv.md) — Example V4
- [Harbor](adapters/harbor.md)
- [NeMo](adapters/nemo.md)
- [Trainer](adapters/trainer.md)
- [EnvAssure](adapters/envassure.md) — Example V5 (not-live until installable)
- [RLlib](adapters/rllib.md) — Example V6 (integration conformance)

## Matrix (honest live vs fixture)

The publishable matrix is generated from
[`registry/adapter-matrix-v1.json`](https://github.com/fraware/verifierlab/blob/main/registry/adapter-matrix-v1.json):

```bash
python scripts/generate_adapter_matrix.py
python scripts/generate_adapter_matrix.py --check
```

See the full generated table: [adapters/matrix.md](adapters/matrix.md).
Release manifests embed the same rows under `adapter_matrix`.

| Adapter | Extra | Live? | What is not claimed |
| ------- | ----- | ----- | ------------------- |
| Native `@verifier` | (base) | Live | OS sandbox / soundness |
| Gymnasium | `[gym]` | Live with gymnasium | Legacy `gym`; full RL stacks |
| Inspect | `[inspect]` | `live_task` / `scorer_verifier` when SDK present; `eval_log_import` fixture | Fixture labeled as live |
| Harbor | `[harbor]` | ATIF fixture always; live SDK on Py≥3.12 | Full Harbor orchestration |
| NeMo Gym HTTP | `[nemo]` | Live vs in-repo reference server | NVIDIA training containers |
| OpenEnv | `[openenv]` | Live HTTP reference; prefer official client when present | Hosted Spaces automation |
| Trainer | `[rl]` / `[trainer]` | Broker-only trainer loop (base) | Heavy external SDKs |
| EnvAssure | `[envassure]` | **Not live** until package installable | Fixture-as-live |
| RLlib | `[rllib]` | Live when Ray installed (conformance) | Capability / SOTA results |
| S3 CAS | `[objectstore]` | Live with boto3 | Default remains filesystem CAS |
| Slurm / Kubernetes | optional | Live when tools/client work | Otherwise explicit dry-run |

## Examples V1–V6

| Example | Path | Extra |
| --- | --- | --- |
| V1 Native | `examples/v1_native_verifier/` | (base) |
| V2 Gymnasium | `examples/v2_gymnasium/` | `[gym]` |
| V3 Inspect | `examples/v3_inspect/` | `[inspect]` |
| V4 OpenEnv | `examples/v4_openenv/` | `[openenv]` (optional) |
| V5 EnvAssure | `examples/v5_envassure/` | `[envassure]` (not-live fixture) |
| V6 RLlib | `examples/v6_rllib/` | `[rllib]` |

## CI posture

- Gym / Inspect / OpenEnv: release-qualified hard-fail in `adapters.yml`
- EnvAssure: fixture always; live hard-fail only when installable
- RLlib: soft-fail / skip-if-missing; image partial-qualification
- Harbor / NeMo: existing extras; no parallel APIs invented

Shared conformance: `verifierlab.targets.conformance.run_conformance`.

Details and non-claims: [limitations.md](limitations.md).
