# Changelog

All notable changes to Verifier Assurance Lab (`verifierlab` / `valab`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with pre-release tags (`a` = alpha, `b` = beta, `rc` = release candidate).

## [Unreleased]

### Planned

- Optional `[stats]` extra with SciPy-backed exact intervals
- Stronger sandbox enforcement for untrusted verifier code
- CLI surfaces for disclosure and adapter routing (today: Python APIs)

## [0.1.0a0] — 2026-07-25

Research alpha: local-first campaign engine through packs, adapters, and
acceptance documentation (milestones M0–M6 in-tree).

### Added

- Package `verifierlab` and CLI `valab` (`init`, `doctor`, `inspect`, `run`,
  `campaign`, `report`, `stats`, `plugins`)
- Filesystem content-addressed store (canonical JSON + SHA-256)
- Campaign specs, budgets/ledgers, local launcher with resume and idempotent
  work units
- Ordinary vs optimized cohorts; public-channel attack feedback (no pre-release
  `gt_valid` to workers/strategies)
- Label vault, freeze records, label release, lifecycle enforcement
- FAR/FRR metrics with abstention/missingness; Wilson and Clopper–Pearson
  (pure Python); binomial power CLI
- Attack strategies: ordinary, fuzz, coverage-guided, evolutionary, inference
  (best-of-N / beam), local tabular RL
- Delta-debug minimization; repair comparison with fresh attacker
- Offline HTML/JSON/CSV report rebuild
- Offline refund tutorial and planted packs A–E
- Optional adapters: Gymnasium, Inspect (`inspect-ai`), Harbor (ATIF), NeMo Gym
  HTTP, OpenEnv HTTP; optional Slurm / Kubernetes launchers and S3 object store
- Disclosure registry (filesystem states / public views)
- Adversarial self-tests for label leak, freeze injection, budget undercount,
  secret-in-report
- CI workflow (ruff, mypy, pytest, import gate, campaign smokes)

### Notes

- Base install intentionally excludes heavy ML and cluster SDKs.
- See [docs/limitations.md](docs/limitations.md) for the Solid / Thin split and
  non-claims.

[Unreleased]: https://github.com/fraware/verifierlab/compare/v0.1.0a0...HEAD
[0.1.0a0]: https://github.com/fraware/verifierlab/releases/tag/v0.1.0a0
