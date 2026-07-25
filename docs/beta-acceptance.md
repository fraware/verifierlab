# Beta / RC acceptance (§38)

Public research release-candidate gate for Verifier Assurance Lab (`0.2.0rc1`).

> **Version gate:** Package version is **`0.2.0rc1`** after executable acceptance
> gates 1–6 pass (`tests/test_acceptance_gates.py`). Do **not** claim SOTA
> verifier assurance or soundness from “no exploit found.” See
> [limitations.md](limitations.md) for trust-boundary notes (Docker sandbox
> optional; default path is process-local).

## Required capabilities

| Criterion | Status |
| --------- | ------ |
| Local wrap → campaign → report quickstart | **Solid** — offline refund tutorial with `freeze → adjudicate → release-labels → report` |
| Ordinary + optimized cohorts | **Solid** — cohort tags mandatory; persistent BoN/beam/evo/RL via attack runtime + broker metering (depth still research-grade, not a product trainer) |
| Explicit access model + budget | **Solid** — capability objects at `VerifierBroker`; worker budget vouchers + ledger candidate-level queries |
| Freeze-gated labels | **Solid** — workers emit commitments only; vault v2 salted/encrypted; adjudicator-only GT; append-only freeze/release chain |
| Fuzz + evolutionary + search + one RL/external path | **Solid** — built-ins + `rl_tabular` (broker probes on by default); heavy external trainers remain optional extras |
| ≥3 planted exploit classes recovered | **Solid** for refund pack (taxonomy on adjudications) |
| Packs A–F recovery | **Solid** — A/B/F in default CI; C/D/E runnable offline (`pack_heavy` / nightly) |
| Repair with fresh attacker | **Solid** — `run_repair_campaign` / `compare_repair`: profiles, regression, holdout, equalized budget, paired stats |
| Offline report rebuild | **Solid** — `valab report builds` blocked until label release; ungated API stamped NON-ASSURANCE |
| One maintained external adapter | **Solid** — Gymnasium live adapter (`[gym]`); see [limitations.md](limitations.md) |
| Adapter conformance suite | **Solid** — shared decision/timeout/isolation checks; live SDKs scheduled or skip-if-missing |
| Disclosure docs tested | **Solid** — DisclosureRegistry tests + community templates |
| RC gates 1–6 executable | **Solid** — `tests/test_acceptance_gates.py` |

## Versioning surfaces

- Package version (`pyproject.toml`) — **`0.2.0rc1`**
- Artifact `schema_version`
- Plugin API (`verifierlab.plugins` entry points)
- Exploit taxonomy (`ExploitClass`)
- Report format (`report_version`)

## Non-goals (must remain out of scope)

General env framework; full training platform; benchmark marketplace; scalar verifier leaderboard; soundness claims from “no exploit found”; automatic public vuln disclosure; storing partner raw data in a public service.

## Honest gate note

§38’s external-adapter bar is met by **Gymnasium**, **Inspect** (`inspect-ai`),
**Harbor** (ATIF + Harbor types), **NeMo Gym HTTP** (stdlib reference server in
CI), and **OpenEnv** (HTTP protocol + reference env in CI). Missing SDKs skip
or raise install hints — never stub passes. See [limitations.md](limitations.md).

**0.2.0rc1** ships with gates 1–6 encoded as tests. Residual non-claims: default
process-local trust boundary (not OS isolation), research-grade attack depth,
optional Docker sandbox. Still not SOTA assurance.
