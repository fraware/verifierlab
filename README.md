<div align="center">

```
 __     _______ ____  ___ _____ ___ _____ ____  _        _    ____  
 \ \   / / ____|  _ \|_ _|  ___|_ _| ____|  _ \| |      / \  | __ ) 
  \ \ / /|  _| | |_) || || |_   | ||  _| | |_) | |     / _ \ |  _ \ 
   \ V / | |___|  _ < | ||  _|  | || |___|  _ <| |___ / ___ \| |_) |
    \_/  |_____|_| \_\___|_|   |___|_____|_| \_\_____/_/   \_\____/ 
```

### Verifier Assurance Lab

**Stress-test graders, reward functions, and policy checkers under optimization — not another model leaderboard.**

[![CI](https://github.com/fraware/verifierlab/actions/workflows/ci.yml/badge.svg)](https://github.com/fraware/verifierlab/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-0.2.0rc2-blue.svg)](CHANGELOG.md)

`verifierlab` · CLI: `valab`

</div>

---

## Pitch

**VerifierLab** is a local-first lab for running reproducible campaigns that ask a hard question: *when something is optimized against your verifier, does the verifier still do its job?*

`verifierlab` is a local-first lab for running reproducible campaigns that ask a hard question: *when something is optimized against your verifier, does the verifier still do its job?*

You wrap a grader or reward function, run ordinary baselines alongside optimized-*tagged* attack cohorts under declared budgets and access models, then rebuild reports from content-addressed artifacts after **freeze → adjudicate → release-labels**. Finding no exploit is evidence under those conditions — not a proof of correctness. This integration candidate (`0.2.0rc2` on `integration/final-assurance`) meets executable RC gates 1–6 and final-acceptance hooks A–J in-repo; do not claim soundness, SOTA verifier assurance, `scientifically_qualified`, or `security_grade` without derived artifacts. Honest gaps are listed in [docs/limitations.md](docs/limitations.md) and [docs/claim-language.md](docs/claim-language.md).


## Why it exists

Modern agents and training loops lean on **verifiers**: graders, reward models, rubrics, policy checkers. Those components can be gamed — reward hacking, rubric gaming, eval cheating — and the failure modes only show up under pressure.

VerifierLab exists so you can:

- Separate **ordinary** behavior from **optimized-tagged** attack cohorts
- Keep runs **reproducible** with content-addressed artifacts and digests
- Stay **local-first**: the base install has no PyTorch, Ray, Kubernetes, or model SDKs
- Record **budgets** (queries, steps, wall time) instead of pretending attacks are free

## Status

**Integration line** (`integration/final-assurance`, package `0.2.0rc2`). This
branch closes the final-assurance programme through Gates G0–G6 feature work and
G7 in-repo acceptance hooks. It is **not** stable `main` until maintainers
fast-forward protected `main` after G7.

RC gates 1–6 remain encoded in `tests/test_acceptance_gates.py`. Final gates A–J
live in `tests/test_final_acceptance_gates.py` and [docs/final-acceptance.md](docs/final-acceptance.md).

Honest maturity: the flagship study at `studies/flagship-2026/` is
**`internally_verified`** with machine-derived blockers. This tree does **not**
claim `scientifically_qualified`, `security_grade`, or `deployment_calibrated`.
Approved phrasing: [docs/claim-language.md](docs/claim-language.md). Gaps:
[docs/limitations.md](docs/limitations.md), [SECURITY.md](SECURITY.md).

APIs and CLI may still shift before a post-G7 stable tag. Do not bump to `1.0`
without the release gate and an explicit maintainer request.


## Install

Requires Python `>=3.11,<3.14`. [uv](https://docs.astral.sh/uv/) is recommended.

```bash
git clone https://github.com/fraware/verifierlab.git
cd verifierlab
uv sync --extra dev
# or: pip install -e ".[dev]"

uv run valab doctor
uv run valab --version
```

From a published package (when available on your index):

```bash
pip install verifierlab
valab doctor
```

## Quick start

Offline refund tutorial (full lifecycle):

```bash
uv run valab init
uv run valab inspect examples.refunds.verifier:grade
uv run valab run campaigns/refund-blackbox.yaml
uv run valab campaign freeze .valab/runs/<run-id>
uv run valab campaign adjudicate .valab/runs/<run-id> --campaign campaigns/refund-blackbox.yaml
uv run valab campaign release-labels .valab/runs/<run-id>
uv run valab report builds .valab/runs/<run-id>
```

Faster smoke:

```bash
uv run valab campaign validate campaigns/fake-smoke.yaml
uv run valab campaign run campaigns/fake-smoke.yaml --processes
```

## What you can do

| Goal | How |
| ---- | --- |
| **Wrap a verifier** | Decorate a grader with `@verifier`, then `valab inspect MODULE:ATTR` |
| **Run a campaign** | `valab run PATH` or `valab campaign run PATH` (attack plane only) |
| **Freeze, adjudicate, release** | `freeze` → `adjudicate` → `release-labels` before reports |
| **Rebuild a report** | `valab report builds RUN_DIR` → HTML / JSON / CSV (post-release) |
| **Compare a repair** | Call `compare_repair` in Python: regression corpus plus a mandatory fresh attacker |
| **Plan sample size** | `valab stats power` for binomial power / *n* planning |

Full CLI table: [docs/cli.md](docs/cli.md).

## Optional extras

Keep the base install light. Pull only what you need:

| Extra | Use |
| ----- | --- |
| `gym` | Gymnasium adapter |
| `inspect` | Inspect AI adapter |
| `harbor` | Harbor adapter (Python ≥3.12) |
| `openenv` | OpenEnv adapter |
| `nemo` | NeMo Gym HTTP client surface |
| `objectstore` | S3-compatible object store |
| `kubernetes` | Kubernetes launcher client |
| `adapters` | Bundle of the adapter extras above |

```bash
uv sync --extra gym
# or: pip install -e ".[gym]"
```

Details: [docs/adapters.md](docs/adapters.md).

## Documentation

| Doc | Topic |
| --- | ----- |
| [Getting started](docs/getting-started.md) | Install and tutorial |
| [Concepts](docs/concepts.md) | Verifiers, cohorts, store, access models |
| [Architecture](docs/architecture.md) | Engine, store, run bundles |
| [Methodology](docs/methodology.md) | How to interpret campaign results |
| [Attacks](docs/attacks.md) | Built-in strategies |
| [Labels and statistics](docs/labels-and-stats.md) | Vault, freeze, error rates |
| [Threat model](docs/threat-model.md) | Assets, boundaries, non-goals |
| [Limitations](docs/limitations.md) | What not to claim |
| [Security policy](SECURITY.md) | Vulnerability reporting |

## Contributing

Contributions are welcome — new attack strategies, adapters, campaigns, docs, and bug fixes all help.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, PR expectations, and coding standards
- Browse [open issues](https://github.com/fraware/verifierlab/issues), especially ones labeled for newcomers
- Keep the **base** dependency graph light; heavy stacks belong behind extras
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)

```bash
uv sync --extra dev
uv run ruff check src tests
uv run mypy
uv run pytest
uv run python scripts/check_base_imports.py
```

## Security

Do not open public issues for security-sensitive reports. Prefer a private [GitHub Security Advisory](https://github.com/fraware/verifierlab/security/advisories/new), or see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).

## Links

- Repository: https://github.com/fraware/verifierlab
- Issues: https://github.com/fraware/verifierlab/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
