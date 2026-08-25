# Final integration ledger

Inventory freeze and canonical integration line for VerifierLab final assurance
completion (Gate G0/G1, WP-00). This ledger maps each intended **feature**
source to commits on `integration/final-assurance`. Validation-only histories
are recorded as **not merged**.

Package version remains `0.2.0rc2` until Gate G7.

## Integration line

| Field | Value |
| ----- | ----- |
| Branch | `integration/final-assurance` |
| Created from | `main` |
| Starting SHA | `f59cd5b9bceb9785642938a634440e4eccf2d12f` |
| Starting subject | `chore: remove accidental empty placeholder` |
| Created | 2026-08-25 |
| Feature-close SHA | `44f3e009c74842e5aca327744dedc52c7851eaed` |
| Commits vs `main` | (see `git rev-list --count origin/main..HEAD`) |
| Push | **not pushed** (WP-00 constraint) |
| Merge to `main` | **not done** (WP-00 constraint) |

Untracked local spec `VerifierLab_Final_Engineering_Completion_Specification_2026-08-25.docx`
stays out of the repository.

## Disposition rules applied

- Feature deltas only: cherry-pick of feature commits (no merge of stacked
  histories, no merge of validation PRs).
- Never merge validation-only PRs: #14, #16, #18, #20, #29, #40, #41, #42,
  #44, #46, #48 and analog `validation/*` branches.
- Temporary one-shot validator workflows (`*-once.yml`) omitted; the
  code/test commits they produced were kept.
- Merge commits that stitch already-landed stacks omitted (do not merge
  the whole stack twice).
- Conflicts never resolved by whole-file ours/theirs without semantic
  review.
- Historical CI on validation marker SHAs does **not** automatically apply
  to this tree.

## Source map

| Source | Remote branch | Source head | Integration range | Status |
| ------ | ------------- | ----------- | ----------------- | ------ |
| Inventory freeze | (new docs) | n/a | `94ac8070` | landed |
| PR #12 | `origin/maintenance/ci-lint-baseline` | `cf5600cb` | `107c89a`..`f63a3f82` | landed |
| PR #5 | `origin/assurance/p0-scientific-closure` | `7fa27c9d` | `c971a5f`..`c7975470` | landed |
| PR #6 | `origin/assurance/p0-release-integrity` | `2f817210` | `f0db3d3f` | landed |
| PR #7 | `origin/assurance/p0-score-fail-closed` | `a90ea6b6` | `43ab590`..`6dffb624` | landed |
| PR #8 | `origin/assurance/p0-statistics-plan` | `77190f1b` | `eb2ed5a`..`f365fb56` | landed |
| PR #11 | `origin/assurance/p0-worker-plane-isolation` | `0d082794` | `cd68926`..`7e1adf76` | landed |
| PR #27 | `origin/assurance/p0-preregistered-estimands` | `f6e6f6fa` | `d28b13d`..`4a779d14` | landed |
| PR #9 | `origin/assurance/p0-repair-reattack` | `4a981f89` | `3ca4dc7`..`509c10a9` | landed |
| Container executor | `origin/assurance/p0-container-execution` | `81428a7b` | `55f81d6`..`cebe5fc3` | landed |
| PR #39 H/F/S | `origin/research/hacker-fixer-solver` | unique tip `f9d1162` | `c423196`..`004c6956` | landed |
| PR #43 surface | `origin/research/robustness-response-surface-v2` | unique | `7843fbb`..`c9edb1b6` | landed |
| PR #45 metamorphic | `origin/research/metamorphic-registry` | unique | `33432c6`..`45f8c6c6` | landed |
| PR #47 failure layers | `origin/research/failure-layer-taxonomy` | `06af47eb` | `6b4ff7c`..`8c5db4bd` | landed |
| WP-01 calibration | `origin/research/planted-calibration` | `085a7f7c` | `1da3947`..`402275bc` + `8e2a47ef` | landed (hygiene follow-up) |
| PR #10 maturity | `origin/assurance/p0-claim-maturity` | `d87b88e8` | `6f7ca8e`..`ba46493` + `44f3e009` | landed as **policy seed only** |

## Validation-only sources (not merged)

| PR / branch | Head / note | Why omitted |
| ----------- | ----------- | ----------- |
| #14, #16, #18, #20, #29 | validation P0 markers | Evidence surfaces, not product deltas |
| #40, #41, #42, #44, #46, #48 | research validation markers | Prove *those exact trees only* |
| `origin/validation/p0-container-clean` | container validation | Forbidden; feature commits taken from `p0-container-execution` |
| `origin/validation/research-core-combined` @ `7eaa8788` | combined research core | Historical validation of a composed tree |
| `origin/validation/*-clean` | various | Validation markers |
| Highest validated research composition | `31f47568` (PR #47/#48) | Does not apply until equivalent tests rerun here |

## Intentional omissions

Temporary `*-once.yml` workflows that add then delete a one-shot GitHub Actions
job are omitted on this tree. Product and test commits they produced were
cherry-picked. `git range-diff` after PR #12 and PR #7 showed those workflow
commits as the only missing source commits (`=` for every feature patch).

The validation composer `4e8c3b8` (`chore(validation): compose research
assurance core`) is omitted: it restates already-landed P0 + H/F/S files.
Pack sidecars after combining PR #7 score mapping with PR #27 estimands were
taken from the composed sidecar *content* at `4e8c3b8` during conflict
resolution (see Slice PR #27), not by merging the composer commit.

Container duplicate `0df0d09` (`fix(worker): prune command module as a file`)
was skipped as empty: already applied via PR #11 `90b42db` / `104a675`.

PR #10 public API `qualify_assurance` / `AssuranceEvidence` booleans are
**not** the public qualification path. Follow-up `44f3e009` keeps the
decision table as `compile_maturity_policy_seed` and
`SEED_NOT_QUALIFICATION_PATH`. WP-05 rewrites this.

`.github/workflows/container-isolation.yml` is kept: it is the product live
probe workflow from the container feature branch, not a one-shot validator.

## Conflicts

| Slice | Files | Resolution |
| ----- | ----- | ---------- |
| PR #7 `d62265e` | `profile.py` (auto-merge) | Semantic keep: PR #12 formatter wrapping of `decision_space.value if isinstance(...)`; range-diff showed formatting-only `!` |
| PR #7 `d2aee23` | `worker.py` (auto-merge) | Semantic keep: PR #12 `Callable` annotations plus PR #7 profile digest binding |
| PR #27 `43f2154` | pack `profile.json` + `expected-public-digests.json` A–E | Semantic merge of PR #7 (`decision_mapping`, schema v2) with PR #27 (`pack-*@2`, campaign digest from preregistered YAML). Sidecar bytes matched composed research core `4e8c3b8` / failure-layer tip (not whole-file ours or theirs of the conflicted cherry-pick) |
| PR #9 `a9a7108` | `tests/test_acceptance_gates.py` (auto-merge) | Semantic keep: PR #11 planted-oracle import path + PR #12 comment style + PR #9 qualification assertions |
| Container `0df0d09` | Dockerfile prune | Empty after PR #11; skipped |

No other content conflicts.

## Range-diff / golden-file proof

| Seam | Proof |
| ---- | ----- |
| PR #12 | `git range-diff origin/main..origin/maintenance/ci-lint-baseline 94ac807..f63a3f8` — all feature commits `=`; only one-shot formatter add/remove omitted |
| PR #7 | `git range-diff` — feature commits `=` except `d62265e` formatting `!` from PR #12 wrap; one-shot workflows omitted |
| PR #9 | feature commits `=`; one-shot workflows omitted |
| PR #5/#6/#8/#11 | clean cherry-picks; empty `git diff` vs source heads for unique modules where checked |
| H/F/S | empty `git diff origin/research/hacker-fixer-solver -- src/verifierlab/campaigns/hacker_fixer_solver.py tests/test_hacker_fixer_solver_protocol.py` |
| Surface / metamorphic / layers | empty `git diff` vs respective source heads for unique modules |
| Container | empty `git diff origin/assurance/p0-container-execution -- src/verifierlab/execution/container.py docker/worker/Dockerfile src/verifierlab/execution/__init__.py` |
| Calibration | unique files match `085a7f7c` except WP-01 hygiene `8e2a47ef` (mypy loop-variable leak + ruff format/RUF005) |

## Slice log

### Slice 0 — inventory freeze

| Field | Value |
| ----- | ----- |
| Final commit | `94ac8070ab9e0a08fce8f2aca079a51c4ee01863` |
| Contents | This ledger + `docs/claim-invalidation-ledger.md` |
| Conflicts | none |
| Tests | none (docs only) |
| Historical evidence applies | n/a |

### Slice PR #12 — CI lint baseline

Feature commits landed; omitted `d822f60` / `992eeca` one-shot formatter workflow.

### Slice PR #5 + #6 — Beam + release integrity

All four Beam commits + unsigned-tag fail-closed release workflow.

### Slice PR #7 — score / profile fail-closed

Omitted one-shot lint and sidecar-refresh workflows. Sidecar *content*
`9a5366b` kept.

### Slice PR #8 — executable StatsPlan

All four commits.

### Slice PR #11 — worker-plane isolation

All 18 feature commits. No one-shot workflows in this series.

### Slice PR #27 — preregistered estimands

Omitted one-shot wiring/migration/repair helper workflows. Pack YAML
preregistration from `43f2154` kept. Sidecars semantically merged (see
Conflicts).

### Slice PR #9 — canonical fresh-repair evidence

Omitted one-shot validation/mypy/schema helper workflows.

**High-risk seam score+repair tests:** 47 passed
(`test_score_decision_*`, `test_campaign_profile_binding`,
`test_campaign_e2e`, `test_repair_qualification_boundary`,
`test_canonical_fresh_run_evidence`, `test_phase_d_exploits_repair`,
`test_beam_regression`, `test_stats_plan_controls`).

### Slice container executor

Omitted one-shot maintenance/validation/boundary helper workflows.
Skipped empty duplicate Dockerfile prune `0df0d09`. Kept product
`container-isolation.yml`.

**High-risk seam isolation+container and container+engine tests:** 49 passed
(`test_worker_plane_source_isolation`, `test_docker_trust_boundaries`,
`test_container_execution_boundary`, `test_container_isolation_workflow`,
`test_isolation_probe_source_contract`, `test_campaign_e2e`,
`test_process_worker`).

### Slice PR #39 — H/F/S unique commits

`18dce98`, `f9f7fd6`, `d729391`. Omitted `validate-hfs-once.yml`.

**High-risk seam stats+HFS tests:** 44 passed
(`test_hacker_fixer_solver_protocol`, `test_stats_plan_controls`,
`test_preregistered_estimands`, `test_metrics_report`, repair evidence tests).

### Slice PR #43 / #45 / #47 — surface, metamorphic, failure layers

Unique feature/test commits only. Omitted compose-research-core and
`validate-*-once.yml`. Research golden tests: 54 passed.

### Slice WP-01 — planted calibration

Validated `085a7f7c` in a detached worktree (did not move this branch):
Ruff RUF005 + format debt + mypy assignment leak in
`statistics/calibration.py`; planted + regression tests 48 passed on that
SHA. Unique feature commits cherry-picked; hygiene follow-up `8e2a47ef`.
No one-shot validators in the unique series.

**High-risk seam calibration+failure layers:** 42 passed
(`test_planted_calibration`, `test_failure_layers`,
`test_robustness_response_surface`, `test_metamorphic_registry`).

### Slice PR #10 — policy seed

Feature commits landed, then `44f3e009` removed boolean qualification from
the public `verifierlab.assurance` API. Tests: 8 passed.

## Ordinary CI on this tree (WP-00 close)

Host: Windows / CPython 3.13.11 (conda). `uv sync` failed on TLS
(`UnknownIssuer`); tests ran via conda Python with `PYTHONPATH=src;.`.

| Command | Result |
| ------- | ------ |
| `python -m ruff check src tests` | pass |
| `python -m ruff format --check src tests` | pass (166 files) |
| `python -m mypy` | 9 errors, **host-specific**: `os.geteuid` / `resource.setrlimit` absent on Windows; `gym_adapter` unused `type: ignore` because local gymnasium is installed. Ubuntu CI (no gymnasium extra, POSIX `os`/`resource`) is the ordinary gate. `runner.py` setrlimit is pre-existing on `main`. |
| `python -m pytest -m "not pack_heavy"` | **442 passed**, 4 skipped, 3 deselected, **1 failed**: `tests/integration/envassure/test_envassure.py::test_envassure_live_when_installable` — local stub `envassure` package exposes neither `EnvAssureTarget` nor `make_target`. Adapter was not touched on this branch (`git log origin/main..HEAD -- src/verifierlab/targets/envassure_adapter.py` empty). Fail-closed adapter behavior; not an integration delta. |
| `python scripts/check_base_imports.py` | OK |

## Historical validation evidence

Does **not** still apply to this SHA. Re-run equivalent suites here
(ordinary CI above is the start). Beam-derived robustness numbers remain
invalid until Beam-dependent experiments are re-executed (see
`docs/claim-invalidation-ledger.md`). Implicit-score results remain
noncanonical.

## Remaining gaps (out of WP-00 / merge-prep)

Ordinary GitHub CI / Security / Adapters workflows have not been executed on
this branch (not pushed).

### WP-01 — planted calibration instrument (completed on this line)

| Item | Status |
| ---- | ------ |
| Observation uniqueness on `work_unit_digest` (shared `run_digest` allowed) | done |
| Seal-before-attack: `CalibrationInstrumentSeal` + public commitment only | done |
| Truth join only after freeze/label release | done |
| `CalibrationAnalysisRegistration` before observations | done |
| Recursive public-artifact leakage harness | done |
| `supports_unknown_robustness_claim=false` hard-coded | intact |
| Commit | `4686125` |

### WP-02 — security-grade three-plane execution (completed with honest host gaps)

| Item | Status |
| ---- | ------ |
| Digest-pinned immutable worker + ContainerWorkerExecutor controls | done |
| `ExecutionBoundaryManifest` schema v2 (backend, trust domain, probe digest) | done |
| `IsolationProbeReport` + malicious probe catalogue | done |
| `SecureLauncher` + capability negotiation (refuse, never degrade to local) | done |
| MicroVM / separate-host backend **interfaces** | done (unavailable locally) |
| Campaign engine selects security-grade via `metadata.execution` | done |
| Sealed run binds execution/probe digests | done |
| Worker entrypoint runs probe catalogue in-executor when flagged | done |
| Real rootless in-executor probes on this Windows host | **not attested** — fail-closed |
| `security_grade=true` claim on this host | **false / refused** without rootless Docker |
| Commit | `f6500a5` |

### WP-03 — AttackerStateEnvelope (completed)

| Item | Status |
| ---- | ------ |
| Opaque CAS envelope, size cap, scan, append-only lineage | done |
| `persistent_attack` vs `fresh_attack` (`parent_state_digest=null`) | done |
| Explicit branches (no last-write-wins) | done |
| Fresh reattack inheritance blocker (HFS + canonical evidence) | done |
| Commit | `d753022` |

### WP-12 — score/profile (verified intact)

`ScoreDecisionMapping` / single profile digest tests remain green
(`test_score_decision_*`, `test_campaign_profile_binding`). No migration gaps
found on this tree beyond what #7 already landed.

### WP-04 — freeze → adjudicate → release + hidden-holdout custody

| Item | Status |
| ---- | ------ |
| Freeze seals campaign/split/profile/budget/work-unit CAS/execution/state/commitments/prereg | done (`SealedRunManifest` v2 + `FreezeSealBundle`) |
| `LabelReleaseReceipt` binds sealed run + label set | done |
| Post-freeze attack mutation reject; split rebind reject; label inject gates | done |
| Opaque holdout IDs + side-channel scan | done |
| Chronology + research registration hooks (calibration/metamorphic/HFS/surface/deployment) | done |
| Reports require release receipt (or explicit public-only ungated) | done |
| Tests | `tests/test_lifecycle_custody_wp04.py` |

### WP-05 — artifact-derived assurance maturity

| Item | Status |
| ---- | ------ |
| `EvidenceResolver` → typed `EvidenceFact` (not caller booleans) | done |
| `ExternalAssuranceAttestation` vs external trust roots (reject self/wrong subject) | done |
| Cumulative scientific gates; local/rootful ⇒ `security_grade=false` | done |
| CLI `valab assurance qualify RUN --claim CLAIM.json` | done |
| `SEED_NOT_QUALIFICATION_PATH` retained | intact |
| Tests | `tests/test_assurance_resolver_wp05.py` |

### WP-06 — statistical engine closure

| Item | Status |
| ---- | ------ |
| Task/environment default sampling unit; trajectory primary forbidden | done |
| Expanded estimand metrics + Holm/Bonferroni + TOST equivalence | done |
| Real Lan-DeMets `StoppingPlan` or fail-closed (no fake sequential) | done |
| Digest-bound `PowerPlan`; underpowered → indeterminate blocker | done |
| Optional `[stats]` SciPy extra declared; pure-Python remains executable path | done (no golden SciPy suite in this pass) |
| Tests | `tests/test_stats_engine_wp06.py` + updated plan/prereg tests |

WP-07–11 methods, WP-13 study, WP-14–22 remain for later agents.
