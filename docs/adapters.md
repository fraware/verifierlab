# Adapters

External system adapters live under `verifierlab.targets` (and
`verifierlab.trainers` for RLlib) and are gated by optional extras. When an SDK
is missing, imports fail with an install hint or tests skip with an explicit
reason—never a silent stub pass. Fixture-only paths are never labeled
live-tested.

## Shared adapter contract (WP-16)

Every matrix adapter is evaluated against
`verifierlab.targets.contract.ADAPTER_CONTRACT_V1`, covering:

- decision normalization
- timeout / error taxonomy
- hidden-label isolation
- version reporting

Shared harness: `verifierlab.targets.conformance.run_conformance`.

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
- [EnvAssure](adapters/envassure.md) — Example V5 (fixture-only until installable)
- [RLlib](adapters/rllib.md) — Example V6 (protocol-reference / integration conformance)

## Matrix statuses (honest live vs fixture)

Allowed statuses only:

| Status | Meaning |
| ------ | ------- |
| `live-tested` | Exercised against a real installable backend in CI or release qualification |
| `protocol-reference-tested` | Exercised against an in-repo or skip-if-missing protocol reference |
| `fixture-only` | Fixture / log-format regression only — never labeled live-tested |
| `unsupported` | Explicitly out of scope |

The publishable matrix is generated from
[`registry/adapter-matrix-v1.json`](https://github.com/fraware/verifierlab/blob/main/registry/adapter-matrix-v1.json):

```bash
python scripts/generate_adapter_matrix.py
python scripts/generate_adapter_matrix.py --check
```

See the full generated table: [adapters/matrix.md](adapters/matrix.md).
Release manifests embed the same rows under `adapter_matrix`.

| Adapter | Extra | Status | What is not claimed |
| ------- | ----- | ------ | ------------------- |
| Native `@verifier` | (base) | live-tested | OS sandbox / soundness |
| Gymnasium | `[gym]` | live-tested | Legacy `gym`; full RL stacks |
| Inspect | `[inspect]` | live-tested (SDK modes); eval_log_import fixture-only | Fixture labeled as live-tested |
| Harbor | `[harbor]` | fixture-only (matrix) | Full Harbor orchestration |
| NeMo Gym HTTP | `[nemo]` | protocol-reference-tested | NVIDIA training containers |
| OpenEnv | `[openenv]` | protocol-reference-tested | Hosted Spaces automation |
| Trainer | `[rl]` / `[trainer]` | live-tested | Heavy external SDKs |
| EnvAssure | `[envassure]` | **fixture-only** until package installable | Fixture-as-live |
| RLlib | `[rllib]` | protocol-reference-tested | Capability / SOTA results |
| S3 CAS | `[objectstore]` | live-tested (scoped prefix) | Default remains filesystem CAS |
| Slurm / Kubernetes | optional | live when tools/client work | Otherwise explicit dry-run |

## Examples V1–V6

| Example | Path | Extra |
| --- | --- | --- |
| V1 Native | `examples/v1_native_verifier/` | (base) |
| V2 Gymnasium | `examples/v2_gymnasium/` | `[gym]` |
| V3 Inspect | `examples/v3_inspect/` | `[inspect]` |
| V4 OpenEnv | `examples/v4_openenv/` | `[openenv]` (optional) |
| V5 EnvAssure | `examples/v5_envassure/` | `[envassure]` (fixture-only) |
| V6 RLlib | `examples/v6_rllib/` | `[rllib]` |

## CI posture

- Gym / Inspect / OpenEnv: release-qualified hard-fail in `adapters.yml`
- EnvAssure: fixture-only always; live hard-fail only when installable
- RLlib: soft-fail / skip-if-missing; image partial-qualification
- Harbor / NeMo: existing extras; no parallel APIs invented
- Object-store: scoped-prefix isolation tests in core pytest

Base import gate (`scripts/check_base_imports.py`) must remain free of heavy
optional deps.

Details and non-claims: [limitations.md](limitations.md).
