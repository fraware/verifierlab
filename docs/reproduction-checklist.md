# Independent reproduction checklist

Use this checklist when reproducing a published VerifierLab campaign offline.

## Environment

1. Python `>=3.11,<3.14`
2. Clean virtualenv: `uv sync --extra dev` (or `pip install -e ".[dev]"`)
3. Confirm base import guard: `uv run python scripts/check_base_imports.py`
4. `uv run valab doctor` reports OK (heavy ML deps may warn if present globally)
5. Confirm `uv run valab --version` matches the campaign’s pinned `verifierlab`
   version when applicable

## Reproduce

1. `uv run valab init --force`
2. `uv run valab campaign validate campaigns/<campaign>.yaml`
3. `uv run valab run campaigns/<campaign>.yaml --format json`
4. Record `run_digest` from stdout
5. `uv run valab report builds .valab/runs/<run-id>`
6. Confirm HTML and `report.json` exist under the run bundle

## Integrity checks

1. Re-run the same campaign with the same seed; compare cohort metrics within tolerance
2. Rebuild report from the frozen run bundle without network
3. Confirm worker artifacts contain commitments only (no pre-release labels)
4. After `uv run valab campaign freeze`, confirm post-freeze label injection fails
5. Stratify metrics by `access_model` and `cohort` (never pool blindly)

## Disclosure

1. If exploits are disclosed, verify registry state transitions
2. Public views must omit private detail refs until `public_full`

See [disclosure.md](disclosure.md) and [SECURITY.md](../SECURITY.md).
