# Contributing to VerifierLab

Thank you for contributing. This project prioritizes reproducible assurance
campaigns, a light base dependency graph, and clear artifact contracts.

## Development setup

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

This command chain is the **VALAB-01 baseline gate** (also documented in
[docs/beta-acceptance.md](docs/beta-acceptance.md)). Digest parity:

```bash
uv run python scripts/repro_bundle_check.py campaigns/fake-smoke.yaml
```

Python `>=3.11,<3.14` is required. Package name is `verifierlab`; CLI entry point
is `valab`.

## Pull requests

- Keep changes focused; prefer small PRs.
- Do not add PyTorch, Ray, Kubernetes, or model SDKs to the **base** install.
- Optional adapters belong behind extras (`inspect`, `harbor`, `gym`, …).
- Add tests for digests, schemas, budgets, and campaign orchestration when
  touching those surfaces.
- Follow existing module layout under `src/verifierlab/`.
- Update docs when changing CLI commands, extras, or public claims.

## Coding standards

- Type-annotate public APIs; keep `api/` and `artifacts/` mypy-strict.
- Prefer Pydantic v2 models for specs and artifact records.
- Canonical JSON + SHA-256 digests are the identity of stored artifacts.
- No smileys or emoji in documentation or commit subjects for this project.

## Enhancement proposals (VAEP)

Changes to artifact formats, taxonomy, metrics, access models, lifecycle states,
or disclosure policy require a VAEP discussion (GitHub issue labeled `vaep`)
before merge.

## Conduct and security

- Participants follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Security-sensitive reports: see [SECURITY.md](SECURITY.md). Do not file public
  issues for vulnerabilities.

## License

By contributing, you agree that your contributions are licensed under Apache-2.0.
