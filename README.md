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

**VerifierLab** is a local-first lab for reproducible campaigns that ask: *when something is optimized against your verifier, does the verifier still do its job?*

You wrap a grader or reward function, run ordinary baselines alongside optimized-*tagged* attack cohorts under declared budgets and access models, then rebuild reports from content-addressed artifacts after **freeze → adjudicate → release-labels**. Finding no exploit is evidence under those conditions — not a proof of correctness.

## Why it exists

Modern agents and training loops lean on **verifiers**: graders, reward models, rubrics, policy checkers. Those components can be gamed — reward hacking, rubric gaming, eval cheating — and the failure modes only show up under pressure.

VerifierLab exists so you can:

- Separate **ordinary** behavior from **optimized-tagged** attack cohorts
- Keep runs **reproducible** with content-addressed artifacts and digests
- Stay **local-first**: the base install has no PyTorch, Ray, Kubernetes, or model SDKs
- Record **budgets** (queries, steps, wall time) instead of pretending attacks are free

## Status

**Release candidate** `0.2.0rc2` on branch `integration/final-assurance` — G7-ready
*in-repo* (executable RC gates 1–6 plus final-acceptance gates A–J). It is **not**
stable `main` until maintainers fast-forward protected `main` after G7 review.

Honest maturity: the flagship study at `studies/flagship-2026/` is
**`internally_verified`** with machine-derived blockers. This tree does **not**
claim `scientifically_qualified`, `security_grade`, or `deployment_calibrated`.
Local/process execution is development-grade; security-grade evidence requires
rootless (or stronger) separate-domain runners.

| Read next | Purpose |
| --------- | ------- |
| [docs/claim-language.md](docs/claim-language.md) | Approved / banned phrasing |
| [docs/limitations.md](docs/limitations.md) | Honest non-claims |
| [docs/final-acceptance.md](docs/final-acceptance.md) | Gates A–J + external blockers |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

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
| **Qualify assurance** | `valab assurance qualify` from artifacts (EvidenceResolver; no caller-boolean promotion) |

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
| `envassure` | EnvAssure binding (fixture-only until package installable) |
| `rllib` | RLlib trainer conformance (heavy; not a capability claim) |
| `objectstore` | S3-compatible object store |
| `kubernetes` | Kubernetes launcher client |
| `adapters` | Bundle of the common adapter extras |

```bash
uv sync --extra gym
# or: pip install -e ".[gym]"
```

Details: [docs/adapters.md](docs/adapters.md) and [docs/adapters/matrix.md](docs/adapters/matrix.md).

## Documentation

| Doc | Topic |
| --- | ----- |
| [Getting started](docs/getting-started.md) | Install and tutorial |
| [Concepts](docs/concepts.md) | Verifiers, cohorts, store, access models |
| [Architecture](docs/architecture.md) | Trust planes, evidence, run bundles |
| [Methodology](docs/methodology.md) | How to interpret campaign results |
| [Claim language](docs/claim-language.md) | Approved / banned phrasing |
| [Attacks](docs/attacks.md) | Built-in strategies |
| [Labels and statistics](docs/labels-and-stats.md) | Vault, freeze, error rates |
| [Threat model](docs/threat-model.md) | Assets, boundaries, non-goals |
| [Limitations](docs/limitations.md) | What not to claim |
| [Final acceptance](docs/final-acceptance.md) | Gates A–J and external blockers |
| [Security policy](SECURITY.md) | Vulnerability reporting |

## Contributing

Contributions are welcome — new attack strategies, adapters, campaigns, docs, and bug fixes all help.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, PR expectations, and coding standards
- Browse [open issues](https://github.com/fraware/verifierlab/issues), especially ones labeled for newcomers
- Keep the **base** dependency graph light; heavy stacks belong behind extras
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Run claim-language lint before docs PRs: `uv run python scripts/check_claim_language.py`

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
- Roadmap: [ROADMAP.md](ROADMAP.md)
