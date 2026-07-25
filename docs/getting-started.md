# Getting started

## Install

```bash
uv sync --extra dev
# or: pip install -e ".[dev]"
uv run valab doctor
uv run valab --version   # expect 0.2.0rc1 for this release line
```

Python `>=3.11,<3.14`. The base package does not pull PyTorch, Ray, Kubernetes
clients, or model SDKs. Optional extras are documented in [adapters.md](adapters.md).

## Ten-minute path (offline refund campaign)

Lifecycle after Phase B: **run → freeze → adjudicate → release-labels → report**.

```bash
uv run valab init
uv run valab inspect examples.refunds.verifier:grade
uv run valab run campaigns/refund-blackbox.yaml
# note run_id / run_dir from stdout
uv run valab campaign freeze .valab/runs/<run-id>
uv run valab campaign adjudicate .valab/runs/<run-id> --campaign campaigns/refund-blackbox.yaml
uv run valab campaign release-labels .valab/runs/<run-id>
uv run valab report builds .valab/runs/<run-id>
```

What you exercise:

1. Workspace under `.valab/` (content-addressed `store/` + `runs/`)
2. A `@verifier`-decorated grader with an explicit `VerifierSpec`
3. Attack plane only during `campaign run` (no `gt_valid` / exploits on disk yet)
4. Coordinator-owned freeze → hidden-GT adjudication → label release
5. Offline HTML/JSON/CSV report rebuild (blocked until labels are released)

Faster smoke (no planted refund depth):

```bash
uv run valab campaign validate campaigns/fake-smoke.yaml
uv run valab campaign run campaigns/fake-smoke.yaml --processes
```

CI-oriented refund smoke: `campaigns/refund-ci-smoke.yaml` (same lifecycle).

## Campaign packs

Offline packs under `campaigns/packs/` (A–F) exercise taxonomy recovery themes.
Default CI runs A, B, F; packs C–E are optional (`pack_heavy` / nightly) but
runnable locally:

```bash
uv run valab campaign validate campaigns/packs/pack-a-outcome-vs-process.yaml
uv run pytest tests/test_packs.py -m "not pack_heavy"   # A, B, F
uv run pytest tests/test_packs.py -m pack_heavy           # C, D, E
```

| Pack | Theme |
| ---- | ----- |
| A | Outcome vs process |
| B | Rubric gaming |
| C | Isomorphic remapping (optional in default CI) |
| D | Evaluation cheating (optional in default CI) |
| E | Co-evolution (optional in default CI) |
| F | Integrity tamper / timeout bypass / approval laundering |

## Next reading

- [Concepts](concepts.md) — vocabulary
- [CLI reference](cli.md) — full command table
- [Attacks](attacks.md) — strategies and plugins
- [Labels and statistics](labels-and-stats.md) — freeze / StatsPlan
- [Methodology](methodology.md) — how to interpret results
- [Limitations](limitations.md) — what not to claim
- [Reproduction checklist](reproduction-checklist.md) — third-party reproduce path
- [Disclosure templates](templates/disclosure.md) — community disclosure
- [Incident template](templates/incident.md) — integrity incident notes
