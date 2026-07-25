# Beta acceptance (§38)

Public research beta / alpha gate for Verifier Assurance Lab (`0.1.0a0`).

## Required capabilities

| Criterion | Status |
| --------- | ------ |
| Local wrap → campaign → report quickstart | **Solid** — offline refund tutorial |
| Ordinary + optimized cohorts | **Solid** — mandatory cohort tagging |
| Explicit access model + budget | **Solid** — CampaignSpec enforced |
| Freeze-gated labels | **Solid** — LabelVault + FreezeRecord + self-tests |
| Fuzz + evolutionary + search + one RL/external path | **Solid** for built-ins + `rl_tabular`; public-channel feedback only |
| ≥3 planted exploit classes recovered | **Solid** for refund pack (taxonomy on exploits) |
| Packs A–E recovery | **Solid** — offline runnable with expected taxonomy assertions |
| Repair with fresh attacker | **Solid** — `compare_repair` (public-channel fresh observe) |
| Offline report rebuild | **Solid** — `valab report builds` |
| One maintained external adapter | **Solid** — Gymnasium live adapter (`[gym]`); see [limitations.md](limitations.md) |
| Disclosure docs tested | **Solid** — DisclosureRegistry tests |

## Versioning surfaces

- Package version (`pyproject.toml`)
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
