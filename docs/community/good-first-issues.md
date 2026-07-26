# Good-first issues (seed bodies)

Ready-to-file issue bodies for VerifierLab newcomers. Target **2–8 focused
engineering hours** each. These tasks intentionally **exclude** oracle
isolation, vault cryptography, budget atomicity, and OS sandboxing.

Copy a section into a new GitHub issue; add labels `good first issue` and the
subsystem tag. Assign the listed reviewer (or `@fraware` until named).

---

## 1. Decision-schema validation

**Title:** Add JSON Schema validation for Decision records in tests

### Problem
Typed `Decision` models exist, but contributors lack a single schema artifact
and test that rejects malformed decision payloads early.

### Why it matters
Fail-closed decisions are a scientific and integrity boundary; schema drift
causes silent report corruption.

### Files likely involved
- `src/verifierlab/api/decision.py`
- `schemas/` (new `decision-v1.schema.json` if missing)
- `tests/` (new or existing decision tests)

### Expected behavior
Canonical Decision JSON validates against a draft schema; invalid status tokens
fail closed.

### Acceptance tests
- Valid accept/reject/abstain/indeterminate/error fixtures pass.
- Unknown required-field omissions fail validation.

### Non-goals
Vault, broker metering, sandbox changes.

### How to run tests
`uv run pytest tests/ -k decision -q`

### Reviewer
Runtime / API (`MAINTAINERS.md`) — dual review if touching normalization semantics.

### Difficulty
easy · **Estimated scope:** 3–5 h

---

## 2. `"reject"` truthiness regression

**Title:** Permanent regression: `bool("reject")` must never become accept

### Problem
Python truthiness makes nonempty strings truthy; `"reject"` must never normalize
to acceptance.

### Why it matters
A single truthiness bug flips scientific outcomes and can hide exploits.

### Files likely involved
- `src/verifierlab/api/decision.py`
- `tests/` decision / acceptance tests

### Expected behavior
`Decision.from_raw("reject")` (and related tokens) yields reject/fail-closed
statuses; never accept.

### Acceptance tests
- Parametrized tokens: `reject`, `rejected`, `fail`, `false`, `no`, `0`.
- Explicit assertion that `bool("reject") is True` is **not** used as the
  acceptance channel.

### Non-goals
Label vault, worker GT exclusion redesign.

### How to run tests
`uv run pytest tests/ -k reject -q`

### Reviewer
Runtime — **dual review** (decision path).

### Difficulty
easy · **Estimated scope:** 2–4 h

---

## 3. Gymnasium termination fixture

**Title:** Fixture covering terminated vs truncated episode ends

### Problem
Gymnasium adapters must distinguish `terminated` and `truncated`; newcomers can
add a focused fixture without touching live training stacks.

### Why it matters
Mis-mapped episode ends corrupt budgets and exploit predicates.

### Files likely involved
- `src/verifierlab/targets/gym_adapter.py`
- `tests/` gym / targets tests
- optional tiny discrete env fixture

### Expected behavior
Adapter records terminated vs truncated distinctly in trajectory metadata.

### Acceptance tests
- Fixture env that ends via terminated once and truncated once.
- Skip or xfail with explicit reason if `[gym]` not installed — do **not** claim live.

### Non-goals
Full RL training, RLlib, sandboxing.

### How to run tests
`uv sync --extra gym --extra dev && uv run pytest tests/ -k gym -q`

### Reviewer
Adapters

### Difficulty
easy · **Estimated scope:** 4–6 h

---

## 4. Inspect categorical mapping

**Title:** Test Inspect `categorical_map` score policy

### Problem
Score policies include categorical maps; a focused unit/fixture test documents
expected mapping behavior.

### Why it matters
Silent mis-maps turn categorical scorer outputs into wrong Decision kinds.

### Files likely involved
- `src/verifierlab/targets/inspect_adapter.py`
- `tests/fixtures/inspect_eval_log.json` (or sibling fixture)
- Inspect adapter tests

### Expected behavior
Configured categorical map yields typed decisions; unknown categories fail
closed or abstain per documented policy.

### Acceptance tests
- Fixture-only test with explicit `fixture` marking in docstring/comments.
- No `live` claim in test name or docs from this change alone.

### Non-goals
Hosting full Inspect product surface; oracle isolation.

### How to run tests
`uv run pytest tests/ -k inspect -q`

### Reviewer
Adapters

### Difficulty
medium · **Estimated scope:** 5–8 h

---

## 5. OpenEnv health test

**Title:** Assert OpenEnv client health endpoint / readiness check

### Problem
OpenEnv adapters should surface health/readiness failures distinctly from step
errors.

### Why it matters
Campaigns otherwise burn budget against a down endpoint and mis-attribute
failures.

### Files likely involved
- `src/verifierlab/targets/openenv_adapter.py`
- reference HTTP server tests
- `docs/adapters.md` (one-line troubleshooting if needed)

### Expected behavior
Unhealthy endpoint → typed error / skipped path with clear diagnostic — not a
false reject/accept.

### Acceptance tests
- Local reference server up → health ok.
- Stopped server → explicit failure mode.
- Mark live only if real `[openenv]` SDK path is exercised; otherwise fixture/protocol.

### Non-goals
HF Spaces automation; vault; sandbox.

### How to run tests
`uv run pytest tests/ -k openenv -q`

### Reviewer
Adapters

### Difficulty
easy · **Estimated scope:** 3–6 h

---

## 6. Plugin-registry schema

**Title:** CI or test: validate `registry/plugins-v1.json` against schema

### Problem
The plugin registry and schema exist; wire a lightweight validation test so
drift fails loudly.

### Why it matters
Broken registry metadata undermines community review status vocabulary.

### Files likely involved
- `registry/plugins-v1.json`
- `schemas/plugin-registry-v1.schema.json`
- `tests/` (new `test_plugin_registry_schema.py`)
- optional `jsonschema` in `[dev]` if not present — prefer stdlib-friendly approach or documented dev extra

### Expected behavior
Registry validates; a mutated invalid fixture in the test fails.

### Acceptance tests
- Load schema + registry; assert valid.
- Document that inclusion ≠ auto-execution in test docstring.

### Non-goals
Plugin installer, marketplace, code execution from registry.

### How to run tests
`uv run pytest tests/ -k plugin_registry -q`

### Reviewer
Community / schemas

### Difficulty
easy · **Estimated scope:** 2–4 h

---

## 7. Benchmark-card linter

**Title:** Lint pack YAML for required public card fields

### Problem
Science packs should expose a minimal “benchmark card” (estimand, access,
budget, splits pointers, public digest refs). A linter catches omissions.

### Why it matters
Missing metadata makes stratified results non-comparable.

### Files likely involved
- `campaigns/packs/*.yaml`
- `scripts/` (new small linter) or `tests/test_pack_cards.py`
- `docs/contributing/benchmark-packs.md`

### Expected behavior
Linter lists missing required keys; CI-invokable locally without network.

### Acceptance tests
- Packs A–E (or documented subset) pass or have explicit waive notes.
- Does not read or require hidden label files.

### Non-goals
Changing pack science content; governance process automation.

### How to run tests
`uv run pytest tests/ -k pack_card -q` (or script exit 0)

### Reviewer
Benchmarks

### Difficulty
medium · **Estimated scope:** 5–8 h

---

## 8. Reproduction-manifest verifier

**Title:** Check repro bundle MANIFEST required members

### Problem
Reproduction bundles need a predictable MANIFEST; a verifier script/test should
confirm required members exist and digests match when present.

### Why it matters
Independent reproduction fails closed on incomplete bundles.

### Files likely involved
- `scripts/repro_bundle_check.py` (extend carefully)
- `docs/reproduction-checklist.md`
- tests around fake-smoke / tutorial bundles

### Expected behavior
Missing required member → nonzero exit / failed test with named member.

### Acceptance tests
- Happy path on existing smoke bundle path.
- Deliberately incomplete temp bundle fails.

### Non-goals
Downloading published release bundles in unit tests; grant ops.

### How to run tests
`uv run python scripts/repro_bundle_check.py campaigns/fake-smoke.yaml`

### Reviewer
Release / statistics

### Difficulty
medium · **Estimated scope:** 4–7 h

---

## 9. Adapter matrix generator

**Title:** Generate adapter matrix table from structured YAML/JSON

### Problem
Docs and release assets need a live/fixture/CI-status matrix; generating from a
single structured source reduces drift.

### Why it matters
Fixture-only paths mislabeled live are a beta gate failure mode.

### Files likely involved
- new `registry/adapter-matrix-v1.yaml` or `docs/` data file
- small generator under `scripts/`
- `docs/adapters.md` (consume generated section or link)

### Expected behavior
Generator emits markdown table with columns: adapter, extra, versions,
live/fixture, CI status, limitations pointer.

### Acceptance tests
- Generator runs offline.
- At least one row deliberately `fixture` and one `live` or `not_live` documented.

### Non-goals
Rewriting CI workflows (`ci.yml`); claiming live without evidence.

### How to run tests
`uv run python scripts/generate_adapter_matrix.py --check` (or equivalent)

### Reviewer
Adapters / docs

### Difficulty
medium · **Estimated scope:** 5–8 h

---

## 10. Report accessibility

**Title:** Improve HTML report accessibility basics

### Problem
HTML reports should have identifiable structure for assistive tech (landmarks,
alt text for meaningful images, contrast-safe status text not color-only).

### Why it matters
Campaign consumers include auditors who rely on accessible artifacts.

### Files likely involved
- `src/verifierlab/reports/html.py`
- report templates under package data if any
- a small snapshot test

### Expected behavior
Generated HTML includes `lang`, main landmark, and non-color status labels.

### Acceptance tests
- Snapshot or DOM assertions for landmarks/status text.
- No change to scientific metrics formulas.

### Non-goals
Full WCAG certification program; CSS redesign for marketing.

### How to run tests
`uv run pytest tests/ -k report -q`

### Reviewer
Reports

### Difficulty
easy · **Estimated scope:** 3–6 h

---

## 11. Query-ledger documentation

**Title:** Document query ledger fields and how to read them

### Problem
Metered broker ledgers are easy to misunderstand; operators need a short doc
explaining fields, vouchers vs totals, and what “exhausted” means.

### Why it matters
Misread ledgers cause false claims about attack budget consumption.

### Files likely involved
- `docs/` new `query-ledger.md` or section in `docs/concepts.md` / `labels-and-stats.md`
- `docs/index.md` link
- optional pointer from `docs/cli.md`

### Expected behavior
Doc lists field meanings, integrity rules (no truthiness), and a tiny example
excerpt from a smoke run.

### Acceptance tests
- Doc links from `docs/index.md`.
- No hidden-label examples in sample excerpts.

### Non-goals
Changing ledger atomicity implementation; sandbox docs.

### How to run tests
Doc review only; optional `uv run valab campaign run campaigns/fake-smoke.yaml --threads` for fresh excerpt.

### Reviewer
Docs / budgets (docs-only PR — single review OK unless code touched)

### Difficulty
easy · **Estimated scope:** 2–4 h

---

## 12. Windows campaign path test

**Title:** Campaign path handling smoke for Windows separators

### Problem
Windows path separators and drive letters can break path joins in campaign load
or artifact layout; a focused test catches regressions.

### Why it matters
Multi-OS smoke is part of the RC gate; path bugs block Windows contributors.

### Files likely involved
- `src/verifierlab/config/campaign.py` / artifact path helpers
- `tests/` using `tmp_path` and pathlib (run on Windows CI or with mocked paths)

### Expected behavior
Loading a campaign from a Windows-style path or joining run dirs does not
double-escape or break digest paths.

### Acceptance tests
- Pure pathlib unit test that fails on naive string `+ "/"` concatenation if
  present.
- Soft-fail documentation only if full Windows runner remains soft-fail — prefer
  hard assert in unit test.

### Non-goals
Docker sandbox on Windows; vault crypto.

### How to run tests
`uv run pytest tests/ -k windows_path -q`

### Reviewer
Runtime / release

### Difficulty
easy · **Estimated scope:** 3–5 h

---

## Explicitly excluded for newcomers

Do **not** file good-first issues for:

- Oracle / GT isolation redesign
- Vault cryptography
- Budget ledger atomicity / voucher races
- OS / Docker sandbox hardening

Those remain maintainer and security dual-review work.
