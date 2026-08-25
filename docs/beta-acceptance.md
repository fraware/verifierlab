# Beta / RC acceptance (§38)

Public research release-candidate gate for Verifier Assurance Lab (`0.2.0rc2`).

> **Version gate:** Package version is **`0.2.0rc2`**. Executable RC gates 1–6
> live in `tests/test_acceptance_gates.py`. Final-assurance gates A–J
> (software/programme readiness) live in
> `tests/test_final_acceptance_gates.py` and
> [final-acceptance.md](final-acceptance.md). Do **not** claim verifier
> soundness or “state of the art” assurance from “no exploit found.” See
> [limitations.md](limitations.md) and [claim-language.md](claim-language.md).
> Do **not** claim SOTA verifier assurance from “no exploit found.”
> Default trust boundary is process-local; Docker sandbox is optional.

## Relationship to final acceptance

| Suite | Scope |
| ----- | ----- |
| Gates 1–6 (`test_acceptance_gates.py`) | Original RC scientific/runtime acceptance |
| Gates A–J (`test_final_acceptance_gates.py`) | Final-assurance integration + no-go regressions |

Passing both means the **repository is G7-ready in-tree**. It does **not** mean
`scientifically_qualified`, `security_grade`, or `deployment_calibrated`.

## VALAB-01 baseline gate

Treat the following as the executable acceptance floor for experimental-framework
hardening (CI + local contributors):

```bash
uv sync --extra dev
uv run ruff check src tests
uv run mypy
uv run pytest
uv run python scripts/check_base_imports.py
uv run valab doctor
uv run valab campaign validate campaigns/fake-smoke.yaml
uv run valab campaign run campaigns/fake-smoke.yaml --threads
```

Digest parity: `uv run python scripts/repro_bundle_check.py campaigns/fake-smoke.yaml`
compares **canonical science digests** (campaign digest + metrics fingerprint +
taxonomy set). Raw `run_digest` may differ due to commitment nonces.

Pytest wrapper: `tests/test_valab01_baseline.py`.

## Required capabilities

| Criterion | Status |
| --------- | ------ |
| Local wrap → campaign → report quickstart | **Solid** — offline refund tutorial with `freeze → adjudicate → release-labels → report` |
| Ordinary + optimized cohorts | **Solid** — cohort tags mandatory; persistent BoN/beam/evo/RL via attack runtime + broker metering (depth still research-grade, not a product trainer) |
| Explicit access model + budget | **Solid** — ten access models incl. `score_only` / `label_only` / `partial_feedback` / `stateful`; capability objects at `VerifierBroker`; vouchered budgets + candidates/compute_units |
| Freeze-gated labels | **Solid** — workers emit commitments only; vault v2 salted/encrypted; `LabelTier` + private holdout quarantine; sealed run manifests |
| Fuzz + evolutionary + search + one RL/external path | **Solid** — built-ins + `rl_tabular` + trainer adapter (`[rl]`/`[trainer]`); heavy external trainers remain optional extras |
| ≥3 planted exploit classes recovered | **Solid** for refund pack (taxonomy on adjudications) |
| Packs A–F recovery | **Solid** — A/B/F in default CI; C/D/E runnable offline (`pack_heavy` / nightly) |
| Repair with fresh attacker | **Solid** — `run_repair_campaign` gates: fresh attacker, equal budget, utility / trivial-reject fail, paired CIs, taxonomy |
| Offline report rebuild | **Solid** — byte-identical canonical JSON on sealed runs; ungated API stamped NON-ASSURANCE |
| Six reference integrations | **Solid** — native `@verifier`, Gymnasium, Inspect, OpenEnv, Harbor (stateful), trainer adapter |
| Adapter conformance suite | **Solid** — shared decision/timeout/isolation checks; live SDKs scheduled or skip-if-missing |
| Disclosure docs tested | **Solid** — DisclosureRegistry tests + community templates |
| RC gates 1–6 executable | **Solid** — `tests/test_acceptance_gates.py` |
| Final gates A–J executable | **Solid** — `tests/test_final_acceptance_gates.py` |
| Claim-language lint | **Solid** — `scripts/check_claim_language.py` |

## Versioning surfaces

- Package version (`pyproject.toml`) — **`0.2.0rc2`**
- Artifact `schema_version`
- Plugin API (`verifierlab.plugins` entry points)
- Exploit taxonomy (`ExploitClass`)
- Report format (`report_version`)

## Non-goals (must remain out of scope)

General env framework; full training platform; benchmark marketplace; scalar verifier leaderboard; soundness claims from “no exploit found”; automatic public vuln disclosure; storing partner raw data in a public service.

## Honest gate note

§38’s external-adapter bar is met by **Gymnasium**, **Inspect** (`inspect-ai`),
**Harbor** (ATIF + Harbor types), **NeMo Gym HTTP** (stdlib reference server in
CI), **OpenEnv** (HTTP protocol + reference env in CI), and the **trainer**
adapter (broker-only feedback). EnvAssure remains fixture-only until
installable. Missing SDKs skip or raise install hints — never stub passes. See
[limitations.md](limitations.md) and [adapters/matrix.md](adapters/matrix.md).

**0.2.0rc2** ships with gates 1–6, VALAB-01…09 hardening, and final-acceptance
A–J. Residual non-claims: default process-local trust boundary (not OS
isolation), research-grade attack depth, optional Docker sandbox, flagship
`internally_verified` with blockers. Still not scientific or security-grade
maturity without derived evidence.
