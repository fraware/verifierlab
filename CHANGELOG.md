# Changelog

All notable changes to Verifier Assurance Lab (`verifierlab` / `valab`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with pre-release tags (`a` = alpha, `b` = beta, `rc` = release candidate).

## [Unreleased]

### Added / hardened (VALAB-01…09 experimental framework)

- **VALAB-01:** Documented baseline gate (ruff/mypy/pytest/doctor/fake-smoke);
  canonical `science_digest` parity in `scripts/repro_bundle_check.py` +
  `tests/test_valab01_baseline.py`
- **VALAB-02:** First-class `VerifierSpec` contract fields; `valab inspect`
  surfaces full contract; campaign validate rejects incomplete contracts
  (`legacy_contract` escape for planted verifiers)
- **VALAB-03:** Access models extended with `score_only`, `label_only`,
  `partial_feedback`, `stateful` + `may_retain_episode_state`; broker channel
  stripping; episode feedback capability-gated (no score synthesis under
  `label_only`); stateful episode state rejects GT keys
- **VALAB-04:** `max_candidates` / `max_compute_units`; thread-safe ledger;
  crash-no-refund persist; verifier invocations ≡ queries; LocalLauncher
  prefers atomic voucher `merge_events` (full batch charged before STOP);
  candidate eval meters compute units
- **VALAB-05:** `SealedRunManifest` on freeze; sealed immutability checks;
  tip-index mutation only via legal lifecycle transitions (same-lifecycle
  rewrite rejected after seal); incomplete-run resume restores spend without
  double-charging; byte-identical canonical report rebuild
- **VALAB-06:** `LabelTier` (development/regression/release/private_holdout);
  private quarantine under `vault/private/`; reports omit raw private labels
- **VALAB-07:** Repair gates incl. `trivial_reject_detected` failure
- **VALAB-08:** StatsPlan `stopping_rule` / `multiple_comparison_policy`;
  censored counts; required optimization_gap; schema validation fails if missing
- **VALAB-09:** Trainer adapter (GT-isolating, broker-metered) + six-adapter
  release matrix; gym fixture mandatory in `adapter-fixtures` CI; `[adapters]`
  includes `[trainer]`

### Planned

- Optional `[stats]` extra with SciPy-backed exact intervals
- Stronger OS/sandbox enforcement for untrusted plugins (default remains process-local)
- CLI surfaces for disclosure and adapter routing (today: Python APIs)
- Cross-process voucher issuance under concurrent workers still snapshots
  remaining budget at submit time (serialized merge; not a distributed lock)

## [0.2.0rc1] — 2026-07-25

Release candidate: scientifically gated ordinary-vs-optimized studies with
hidden adjudication, broker metering, and StatsPlan analysis. Executable
acceptance suite: `tests/test_acceptance_gates.py` (gates 1–6).

### Added / hardened

- Attack-worker budget vouchers: atomic `broker.query` reserve against
  remaining campaign query budget; exact event merge on the coordinator
- Fail-closed typed decisions on repair / minimization / metamorphic paths
  (no `bool("reject")` accept)
- RL tabular candidate probes on by default when a broker is bound
- BoN/beam brokerless paths no longer invent verifier query counts
- StatsPlan optimization-gap bootstrap CI (`bootstrap_samples`)
- Adjudication seals outcome dimensions; ungated reports stamped
  `research_ungated` / NON-ASSURANCE
- PlantedOracle commitments v2 (nonce; not Boolean-guessable); exact env
  RNG snapshot/restore
- Worker refuse of GT-like plugin refs; acceptance gate suite for RC sign-off
- Reproducible campaign bundle check (`scripts/repro_bundle_check.py`)

### Notes

- Still research-grade: default trust boundary is process-local Python;
  Docker sandbox remains optional (`[sandbox]`). Do not claim soundness
  from “no exploit found.”
- See [docs/limitations.md](docs/limitations.md) and
  [docs/beta-acceptance.md](docs/beta-acceptance.md).

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

[Unreleased]: https://github.com/fraware/verifierlab/compare/v0.2.0rc1...HEAD
[0.2.0rc1]: https://github.com/fraware/verifierlab/compare/v0.1.0a0...v0.2.0rc1
[0.1.0a0]: https://github.com/fraware/verifierlab/releases/tag/v0.1.0a0
