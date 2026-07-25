# Getting started

## Install

```bash
uv sync --extra dev
# or: pip install -e ".[dev]"
uv run valab doctor
uv run valab --version   # expect 0.1.0a0 for this release line
```

Python `>=3.11,<3.14`. The base package does not pull PyTorch, Ray, Kubernetes
clients, or model SDKs. Optional extras are documented in [adapters.md](adapters.md).

## Tutorial (offline refund campaign)

```bash
uv run valab init
uv run valab inspect examples.refunds.verifier:grade
uv run valab run campaigns/refund-blackbox.yaml
# note run_id / run_dir from stdout
uv run valab report builds .valab/runs/<run-id>
```

What you exercise:

1. Workspace under `.valab/` (content-addressed `store/` + `runs/`)
2. A `@verifier`-decorated grader with an explicit `VerifierSpec`
3. Ordinary + optimized cohorts under a black-box access model
4. Offline HTML/JSON/CSV report rebuild from immutable work units

Faster smoke (no planted refund depth):

```bash
uv run valab campaign validate campaigns/fake-smoke.yaml
uv run valab campaign run campaigns/fake-smoke.yaml --threads
```

CI-oriented refund smoke: `campaigns/refund-ci-smoke.yaml`.

## Campaign packs

Offline packs under `campaigns/packs/` (A–E) exercise taxonomy recovery themes
(outcome vs process, rubric gaming, isomorphic remapping, eval cheating,
coevolution). Validate before run:

```bash
uv run valab campaign validate campaigns/packs/pack-a-outcome-vs-process.yaml
```

## Next reading

- [Concepts](concepts.md) — vocabulary
- [CLI reference](cli.md) — full command table
- [Methodology](methodology.md) — how to interpret results
- [Limitations](limitations.md) — what not to claim
- [Reproduction checklist](reproduction-checklist.md) — third-party reproduce path
