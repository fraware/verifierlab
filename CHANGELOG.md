# Changelog

All notable changes to Verifier Assurance Lab (`verifierlab` / `valab`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with pre-release tags (`a` = alpha, `b` = beta, `rc` = release candidate).

## [Unreleased]

### Planned

- Optional `[stats]` extra with SciPy-backed exact intervals
- Stronger OS/sandbox enforcement for untrusted plugins (default remains process-local)
- CLI surfaces for disclosure and adapter routing (today: Python APIs)

## [0.2.0rc2] — 2026-07-26

Public beta RC gate: Milestones A–E (release integrity, scientific runtime,
integrations, research assets, docs/governance) on the SemVer RC line. Do not
rebrand to `0.2.0b1`. Tag: `v0.2.0rc2`.

### Added (Milestone D — research assets)

- Science packs A–E completeness: splits + StatsPlan in YAML; sidecars for
  `planted-failure.json`, `adjudication-protocol.json`, primary estimand /
  interval method in expected public digests; pack lint enforces ≥2 optimized
  attacks, baseline, and no labels in the public pack tree (Pack F remains
  integrity-only)
- Reproducibility bundle layout (`scripts/repro_bundle_layout.py`), builder
  (`scripts/build_repro_bundle.py`), and verifier extensions
  (`scripts/verify_repro_bundle.py` directory/archive/download paths);
  `CITATION.cff`; `reproduce.yml` download path stays graceful when unpublished
- Adapter matrix generator (`scripts/generate_adapter_matrix.py`) from
  `registry/adapter-matrix-v1.json` → `docs/adapters/matrix.md` +
  `dist/adapter-matrix.json`; release-manifest loads the same registry rows
  (EnvAssure **not-live**, RLlib **partial** / skip-if-missing)
- Examples V1–V6 READMEs document released-wheel install paths alongside
  editable development installs

### Added (Milestone C — integrations)

- Examples V1–V6 under `examples/v{1..6}_*/` with the example contract
  (`README`, `campaign.yaml`, `verifier/`, `environment/`, `expected/`,
  `run.sh`, `verify.sh`, `example-manifest.json`)
- Gymnasium matrix expansion: Dict spaces, terminated/truncated, invalid
  action, non-JSON obs, fixed-seed replay, wrapper stack capture; legacy
  `gym` removed from release-qualified claims (`[gym]` → gymnasium only,
  pin `>=0.29,<1.3`)
- Inspect modes `live_task` / `scorer_verifier` / `eval_log_import` (aliases
  `live`, `log_format_regression`); configurable score policies; hidden
  targets adjudication-only with sample ID commitments on worker artifacts
- OpenEnv identity/schemas/health/timeout-retry/episode ID/trajectory/snapshot
  capture; prefer official client when available
- EnvAssure adapter + `[envassure]` extra (`envassure>=0.2.0b1,<0.3`); package
  not yet on PyPI → protocol/fixture **not-live** (never claim live from fixtures)
- RLlib: expanded `ExternalTrainerAdapter` protocol + aliases; `[rllib]` pin
  `ray[rllib]==2.48.0`; `trainers/rllib_adapter.py` + `rllib_env.py` (PPO,
  broker-only rewards, freeze before holdout); PR-tier skip-if-missing tests;
  Docker image marked partial-qualification / integration conformance

### Added (Milestone A — release integrity)

- Normalized GitHub workflows: `ci.yml`, `adapters.yml`, `security.yml`,
  `docs.yml`, `reproduce.yml`, `release.yml` (watch `main` + `release/0.2-rc`)
- `scripts/build_release_manifest.py` → `release-manifest.json`
- Trust-boundary Dockerfiles under `docker/{cli,worker,adjudicator}/` plus
  post-qualification `docker/rllib/` stub; structure tests in
  `tests/test_docker_trust_boundaries.py`
- MkDocs Material site (`mkdocs.yml`, `[docs]` extra) with per-adapter pages
- Package acceptance: `Documentation` / `Changelog` URLs; wheel force-includes
  campaigns + disclosure templates; metadata/wheel check scripts

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

### Added (Milestone B — scientific runtime polish)

- Public `VerifierDecision` alias for `Decision`
- `VerifierProfile` applicability + access_surface contract fields
- `PythonVerifierRunner` subprocess boundary (timeout, best-effort CPU/memory
  limits, structured stdin/stdout, typed errors, deterministic env, digests,
  no label imports); broker prefers runner for packaged native verifiers
- CLI: `valab verifier inspect|test|package|conformance` and
  `valab pack lint|verify|run|reproduce|inspect` (`valab inspect` shares one path)
- Pack sidecars for A–E: `profile.json`, `splits.json`,
  `expected-public-digests.json` under `campaigns/packs/pack-{a-e}/`
- Atomic disjoint query voucher reservation (`reserve_query_voucher`) to close
  concurrent oversubscribe races
- Documented campaign “signing” = content-addressed digest + pins + sealed run

### Added (Milestone E lite — docs / governance)

- `ROADMAP.md`, `CODEOWNERS`, `MAINTAINERS.md`, contributing guides, plugin /
  defect registries, governance charter, good-first-issue templates

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

[Unreleased]: https://github.com/fraware/verifierlab/compare/v0.2.0rc2...HEAD
[0.2.0rc2]: https://github.com/fraware/verifierlab/compare/v0.2.0rc1...v0.2.0rc2
[0.2.0rc1]: https://github.com/fraware/verifierlab/compare/v0.1.0a0...v0.2.0rc1
[0.1.0a0]: https://github.com/fraware/verifierlab/releases/tag/v0.1.0a0
