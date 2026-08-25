# VerifierLab public roadmap

Public engineering roadmap for the `0.2.0rc` line on
`integration/final-assurance`. Updated for Gate G7 in-repo readiness.
Percentage-complete reporting is intentionally avoided.

Every item records: **problem**, **claim enabled**, **owner**, **dependencies**,
**acceptance criterion**, **security boundary**, **benchmark impact**, and
**status**.

Statuses: `proposed` · `committed` · `in_progress` · `blocked` · `done` ·
`declined` · `deferred`.

---

## Current line (`0.2.0rc2` / final-assurance)

In-repo programme through Gates G0–G6 feature work and G7 acceptance hooks A–J
is **complete on this branch**. Package version stays **`0.2.0rc2`** until a
maintainer-signed stable cut. Flagship study maturity remains
`internally_verified` with blockers — not `scientifically_qualified` /
`security_grade` / `deployment_calibrated`.

See [docs/final-acceptance.md](docs/final-acceptance.md) for the executable
gate list and remaining **external** blockers (branch protection, rootless
runners, independent attestation, field outcomes, signed PyPI publish).

### RC-01 — Land VALAB hardening on the RC branch

| Field | Value |
| ----- | ----- |
| Problem | Untracked hardening (broker metering, ledger, lifecycle, attacker runtime, trainer adapter) must stabilize before claiming RC integrity. |
| Claim enabled | Process-worker GT exclusion, append-only freeze, persistent attackers, and budgeted broker calls are enforceable in CI. |
| Owner | Core runtime (`MAINTAINERS.md` — Runtime) |
| Dependencies | Existing acceptance gates; `tests/test_valab_hardening.py` |
| Acceptance criterion | Hardening tests green; no P0/P1 truthiness or voucher races open. |
| Security boundary | Workers never receive hidden labels; adjudication remains coordinator-only. |
| Benchmark impact | None until packs re-run against hardened runtime. |
| Status | `done` |

### RC-02 — Release integrity workflows and manifest

| Field | Value |
| ----- | ----- |
| Problem | Public RC needs signed-tag release path, multi-OS smoke, checksums/SBOM/manifest, and honest adapter matrix. |
| Claim enabled | Artifacts for a tagged RC are byte-identical across PyPI and GitHub Release. |
| Owner | Release (`MAINTAINERS.md` — Release) |
| Dependencies | Branch protection on `main` (admin); Milestone A workflows |
| Acceptance criterion | Annotated tag gate → wheel/sdist once → fresh install → separation tests → trusted publish attach succeeds. |
| Security boundary | Release images keep CLI / worker / adjudicator trust boundaries separate. |
| Benchmark impact | Release assets may include pack digests and repro bundle pointers. |
| Status | `done` (in-repo workflows/policy) · `blocked` (GitHub admin enablement + trusted publish) |

### RC-03 — Scientific runtime polish (Decision, runner, pack CLI)

| Field | Value |
| ----- | ----- |
| Problem | Discoverability gaps: Decision aliases, subprocess verifier runner, `valab verifier` / `valab pack` surfaces. |
| Claim enabled | Packaged verifiers can run behind a subprocess boundary with typed decisions and no label access. |
| Owner | Runtime + Verifiers |
| Dependencies | RC-01 |
| Acceptance criterion | `PythonVerifierRunner` wired for packaged native verifiers; pack lint/verify/run/inspect operate on pack trees. |
| Security boundary | Runner has no vault/GT access; worker fixtures stay label-free. |
| Benchmark impact | Pack sidecar manifests enable digest-stable pack identity. |
| Status | `done` |

### FA-01 — Final assurance stack (G0–G7 in-repo)

| Field | Value |
| ----- | ----- |
| Problem | Assurance maturity, container boundary, method surfaces, schema registry, claim language, and flagship study must land as one coherent line. |
| Claim enabled | G7 software/acceptance hooks A–J executable; maturity derived from artifacts only. |
| Owner | Maintainers |
| Dependencies | RC-01…03; assurance work packages WP-00…WP-22 |
| Acceptance criterion | `tests/test_final_acceptance_gates.py` green; flagship `internally_verified` with blockers. |
| Security boundary | Process-local caps maturity; security-grade needs rootless/separate-domain evidence. |
| Benchmark impact | Flagship underpowered estimands remain indeterminate. |
| Status | `done` (in-repo) · external blockers listed in final-acceptance |

---

## Next RC / post-G7

### NX-01 — Qualify Gymnasium / Inspect / OpenEnv live paths

| Field | Value |
| ----- | ----- |
| Problem | Adapter matrix must distinguish live SDK paths from fixture-only regression. |
| Claim enabled | Documented live adapters run against real supported packages where claimed. |
| Owner | Adapters |
| Dependencies | Extras pins; release-qualified CI jobs |
| Acceptance criterion | Matrix marks live vs fixture honestly; fixture-only paths never labeled live. |
| Security boundary | Hidden targets only in adjudication; worker artifacts carry IDs/commitments only. |
| Benchmark impact | Conformance results may cite adapter digests; not capability leaderboards. |
| Status | `done` (honest matrix + contract); live CI remains skip-if-missing where SDKs absent |

### NX-02 — EnvAssure + RLlib extras (when installable)

| Field | Value |
| ----- | ----- |
| Problem | Spec requires EnvAssure and RLlib integration conformance behind extras. |
| Claim enabled | Optional `[envassure]` / `[rllib]` paths exist with protocol tests; live CI hard-fails only when packages install. |
| Owner | Adapters + Trainers |
| Dependencies | Upstream package availability; NX-01 patterns |
| Acceptance criterion | Protocol/fixture tests always; live status explicit in matrix; no live claim from fixtures. |
| Security boundary | Attackers see actor observations + public verifier feedback only. |
| Benchmark impact | Integration conformance only — not attacker capability claims. |
| Status | `committed` — EnvAssure fixture-only until installable; RLlib protocol + skip-if-missing |

### NX-03 — Examples V1–V6 from released wheel

| Field | Value |
| ----- | ----- |
| Problem | Examples must install the released wheel in an isolated workspace and satisfy the example contract. |
| Claim enabled | Newcomers can reproduce a full lifecycle without a source checkout of this repo. |
| Owner | Docs + Examples |
| Dependencies | RC-02; pack/example contracts |
| Acceptance criterion | Each example has README, campaign, verifier/env, expected, run/verify scripts, example-manifest. |
| Security boundary | Example fixtures contain no hidden labels or vault keys. |
| Benchmark impact | Examples may reference packs but do not redefine primary estimands. |
| Status | `done` (contract in tree); public wheel publish still blocked on release tag |

### NX-04 — External scientific / security maturity

| Field | Value |
| ----- | ----- |
| Problem | `internally_verified` is not scientific or security-grade maturity. |
| Claim enabled | Independent attestation + rootless probes + field outcomes can raise derived labels. |
| Owner | Program + Security |
| Dependencies | FA-01; rootless runners; external trust roots |
| Acceptance criterion | EvidenceResolver-derived `scientifically_qualified` / `security_grade` / `deployment_calibrated` only from real artifacts. |
| Security boundary | No self-issued independence; no process-local security-grade. |
| Benchmark impact | Flagship blockers clear only when evidence exists. |
| Status | `blocked` (external) |

---

## Research

### RS-01 — Packs 1–5 completeness (A–E science themes)

| Field | Value |
| ----- | ----- |
| Problem | Science packs need baseline, two optimized attacks, access/budget/splits, estimand, intervals, planted failure, public digests, hidden adjudication protocol. |
| Claim enabled | Published pack results are stratified and content-addressed. |
| Owner | Benchmarks |
| Dependencies | Governance charter; StatsPlan execution |
| Acceptance criterion | Packs validate; labels never in public pack trees; expected public digests match. |
| Security boundary | Hidden adjudication assets remain custodian-held. |
| Benchmark impact | Direct — pack version bumps require council process for major/minor changes. |
| Status | `done` |

### RS-02 — Reproducibility bundle + reproduce workflow

| Field | Value |
| ----- | ----- |
| Problem | Independent teams need a downloadable bundle verifiable without this source tree. |
| Claim enabled | Downloaded repro bundle verifies digests and rebuilds reported tables. |
| Owner | Release + Statistics |
| Dependencies | RC-02; `scripts/repro_bundle_check.py` |
| Acceptance criterion | `reproduce.yml` downloads published bundle and verifies; excludes keys/unreleased labels. |
| Security boundary | Bundles never include vault keys or unreleased labels. |
| Benchmark impact | Enables independent challenge of published claims. |
| Status | `done` (in-repo mechanics); public published-bundle download path waits on release |

### RS-03 — Persistent attacker / co-evolution depth (honest limits)

| Field | Value |
| ----- | ----- |
| Problem | Research-grade attack depth remains limited; overclaiming RL-agent capability is a risk. |
| Claim enabled | Documented attack families under declared budgets; non-claims stay in `docs/limitations.md`. |
| Owner | Attacks |
| Dependencies | Persistent attacker runtime |
| Acceptance criterion | Limitations page lists depth bounds; no verifier-soundness claim. |
| Security boundary | Attack plugins cannot import adjudicator/GT modules. |
| Benchmark impact | Attack additions to packs follow minor/major versioning rules. |
| Status | `committed` — depth remains research-grade by design |

---

## Community requests

### CR-01 — Plugin registry and contribution guides

| Field | Value |
| ----- | ----- |
| Problem | External authors need a metadata registry and clear contribution paths without a marketplace installer. |
| Claim enabled | Curated plugin metadata with review status; inclusion ≠ auto-execution. |
| Owner | Community |
| Dependencies | Schema; CODEOWNERS; contributing guides |
| Acceptance criterion | `registry/plugins-v1.json` validates; guides cover verifiers/attacks/envs/adapters/packs/stats/defects/release. |
| Security boundary | Catalog renderer parses metadata only — never imports plugin code. |
| Benchmark impact | None directly; plugins used in packs still need pack governance. |
| Status | `done` |

### CR-02 — Good-first issues and defect registry seed

| Field | Value |
| ----- | ----- |
| Problem | Newcomers need scoped tasks that avoid security-critical surfaces. |
| Claim enabled | At least twelve good-first issues and a public defect record template exist. |
| Owner | Community |
| Dependencies | CR-01 |
| Acceptance criterion | Twelve seeded bodies; `VER-2026-0001` public fields only; security defects stay private until disclosure. |
| Security boundary | Issues exclude oracle isolation, vault crypto, budget atomicity, sandboxing. |
| Benchmark impact | Defect fixes may invalidate prior pack claims when severity warrants. |
| Status | `done` |

### CR-03 — Independent reproduction grants (out of band)

| Field | Value |
| ----- | ----- |
| Problem | Paid clean-room reproduction strengthens evidence but is operational, not engineering. |
| Claim enabled | Grant *rules* may be published; selection and payment stay out of this repository. |
| Owner | Program (external) |
| Dependencies | Repro bundle; charter |
| Acceptance criterion | Engineering seeds only this cycle — no grant administration in-repo. |
| Security boundary | Grantees never receive vault keys; embargoed defects stay private. |
| Benchmark impact | Successful/failed reproductions update claim status. |
| Status | `deferred` |

---

## Security and integrity

### SI-01 — Dual review for trust-critical paths

| Field | Value |
| ----- | ----- |
| Problem | Single-reviewer merges on decision/label/budget/stats/sandbox/crypto risk integrity regressions. |
| Claim enabled | CODEOWNERS + MAINTAINERS require dual-review hints on those paths. |
| Owner | Security + Maintainers |
| Dependencies | GitHub branch protection (admin) |
| Acceptance criterion | CODEOWNERS lists dual-review paths; MAINTAINERS documents the policy. |
| Security boundary | Applies to `api/decision`, labels/vault, budgets, statistics, security/sandbox, cryptography. |
| Benchmark impact | None. |
| Status | `done` (in-repo policy) · `blocked` (admin branch protection) |

### SI-02 — Separate signed trust-boundary images

| Field | Value |
| ----- | ----- |
| Problem | Shared default images blur worker vs adjudicator privileges. |
| Claim enabled | CLI / worker / adjudicator images have distinct contents and import bans. |
| Owner | Release + Security |
| Dependencies | Dockerfiles; Milestone A |
| Acceptance criterion | Structure tests assert no shared default data path and banned imports across images. |
| Security boundary | Worker image must not contain GT provider, vault, or adjudicator credentials. |
| Benchmark impact | Repro may pin image digests. |
| Status | `done` |

### SI-03 — No truthiness conversion / no fixture live claims

| Field | Value |
| ----- | ----- |
| Problem | `bool("reject")` and fixture-labeled-as-live claims corrupt science and security. |
| Claim enabled | Typed Decision normalization and honest live/fixture matrix language. |
| Owner | Runtime + Adapters |
| Dependencies | Decision API; adapter docs |
| Acceptance criterion | Regression tests for reject-token truthiness; docs forbid live claims from fixtures. |
| Security boundary | Fail-closed decisions; workers never see hidden labels in fixtures. |
| Benchmark impact | Invalidates any result that relied on truthiness coercion. |
| Status | `done` |

---

## Adapters

### AD-01 — Release-qualified Gymnasium matrix expansion

| Field | Value |
| ----- | ----- |
| Problem | Gym path needs termination/truncation, Dict spaces, invalid action, and seed replay coverage. |
| Claim enabled | Documented Gymnasium behaviors are conformance-tested under `[gym]`. |
| Owner | Adapters |
| Dependencies | `[gym]` extra; NX-01 |
| Acceptance criterion | Matrix rows for listed semantics; legacy `gym` not claimed in beta docs. |
| Security boundary | Env wrappers cannot smuggle hidden labels into worker artifacts. |
| Benchmark impact | Pack envs using Gymnasium cite adapter version. |
| Status | `done` |

### AD-02 — Inspect modes and score policies

| Field | Value |
| ----- | ----- |
| Problem | Inspect modes (`live_task`, `scorer_verifier`, `eval_log_import`) and categorical maps must stay distinct. |
| Claim enabled | Score policies are configurable and tested; hidden targets stay in adjudication. |
| Owner | Adapters |
| Dependencies | `inspect-ai` pin |
| Acceptance criterion | Distinct modes; categorical_map tests; release tests against official mock model when live. |
| Security boundary | Worker artifacts carry sample IDs/commitments only. |
| Benchmark impact | Inspect-backed packs record mode + policy digests. |
| Status | `done` |

### AD-03 — OpenEnv health / identity / trajectory capture

| Field | Value |
| ----- | ----- |
| Problem | OpenEnv adapter must capture health, identity, reset/step/state, and trajectory honestly. |
| Claim enabled | Reference HTTP path works without heavy SDK; live SDK path when `[openenv]` installs. |
| Owner | Adapters |
| Dependencies | OpenEnv protocol; NX-01 |
| Acceptance criterion | Health test + protocol conformance; matrix marks live vs fixture. |
| Security boundary | No adjudicator secrets in OpenEnv client config committed to packs. |
| Benchmark impact | OpenEnv packs cite client/protocol digests. |
| Status | `done` |

---

## Declined

### DC-01 — Rebrand RC line to `0.2.0b1`

| Field | Value |
| ----- | ----- |
| Problem | Spec text sometimes says `0.2.0b1`; shipping two public version brands confuses consumers. |
| Claim enabled | (none) — stay on SemVer RC line `0.2.0rc1` → `0.2.0rc2`. |
| Owner | Maintainers |
| Dependencies | None |
| Acceptance criterion | Docs map any `0.2.0b1` wording to `0.2.0rc2` / tag `v0.2.0rc2`. |
| Security boundary | N/A |
| Benchmark impact | None |
| Status | `declined` — rationale: keep existing RC SemVer; do not rebrand. |

### DC-02 — Parallel adapter API rewrite

| Field | Value |
| ----- | ----- |
| Problem | Spec discoverability could tempt a second adapter API surface. |
| Claim enabled | (none) — thin aliases and CLI only; keep existing Decision / profile / broker / lifecycle. |
| Owner | Maintainers |
| Dependencies | None |
| Acceptance criterion | No fork of parallel adapter APIs this cycle. |
| Security boundary | Avoids divergent trust semantics across twin APIs. |
| Benchmark impact | Preserves pack compatibility. |
| Status | `declined` — rationale: qualify in place; aliases only. |

### DC-03 — In-repo reproduction grant administration

| Field | Value |
| ----- | ----- |
| Problem | Funding selection/payment is operational scope. |
| Claim enabled | (none this cycle) |
| Owner | Program (external) |
| Dependencies | None in engineering gate |
| Acceptance criterion | Milestone E ships docs/seeds only. |
| Security boundary | Avoids committing PII/payment data to the repo. |
| Benchmark impact | Deferred |
| Status | `declined` for this repository cycle — grants remain out of band. |

### DC-04 — Universal aggregate verifier leaderboard

| Field | Value |
| ----- | ----- |
| Problem | Single-score leaderboards hide stratification and invite contamination gaming. |
| Claim enabled | (none) — primary results stay stratified by verifier, env, access, attack, budget, split, pack version. |
| Owner | Benchmark Council |
| Dependencies | Charter |
| Acceptance criterion | Charter forbids universal aggregate leaderboard in beta. |
| Security boundary | Reduces incentive to leak hidden labels for ranking. |
| Benchmark impact | Direct — presentation policy. |
| Status | `declined` — rationale: stratification required; no universal leaderboard in beta. |
