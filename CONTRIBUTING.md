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

Docs PRs should also keep claim language clean:

```bash
uv run python scripts/check_claim_language.py
```

Final-assurance acceptance (gates A–J): see
[docs/final-acceptance.md](docs/final-acceptance.md) and
`tests/test_final_acceptance_gates.py`.

Python `>=3.11,<3.14` is required. Package name is `verifierlab`; CLI entry point
is `valab`. Package version on this line is **`0.2.0rc2`**.

## Developer Certificate of Origin (DCO)

All commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "Your message"
```

Each commit message must include a `Signed-off-by: Name <email>` line matching
the author. PRs without DCO sign-off will not be merged.

## Integrity rules (non-negotiable)

- **No truthiness conversion** for decisions or labels. Strings such as
  `"reject"` must never become acceptance via `bool(...)`. Use typed
  `Decision` / `DecisionKind` normalization.
- **No hidden labels in worker fixtures.** Attack-plane and worker test fixtures
  must not embed ground-truth or vault material.
- **No live claim from fixture-only tests.** Adapter docs and the release matrix
  must mark `live` vs `fixture` honestly. Fixture coverage is valuable; it is
  not a live integration claim.
- **No benchmark construct change** without governance review — see
  [docs/governance/charter.md](docs/governance/charter.md).
- **Plugin registry inclusion ≠ automatic execution.** Metadata in
  `registry/plugins-v1.json` never installs or runs plugin code by itself.
- Compatibility tests are required for new plugins (schema + conformance level
  claimed).

## Contribution guides

| Guide | Audience |
| ----- | -------- |
| [Verifiers](docs/contributing/verifiers.md) | Verifier authors |
| [Attacks](docs/contributing/attacks.md) | Attack / cohort authors |
| [Environments](docs/contributing/environments.md) | Environment / target authors |
| [Adapters](docs/contributing/adapters.md) | External SDK integrators |
| [Benchmark packs](docs/contributing/benchmark-packs.md) | Pack maintainers |
| [Statistics](docs/contributing/statistics.md) | StatsPlan / estimand authors |
| [Defects](docs/contributing/defects.md) | Defect reporters |
| [Release process](docs/contributing/release-process.md) | Release engineers |

Good-first issue seeds: [docs/community/good-first-issues.md](docs/community/good-first-issues.md).

## Pull requests

- Keep changes focused; prefer small PRs.
- Do not add PyTorch, Ray, Kubernetes, or model SDKs to the **base** install.
- Optional adapters belong behind extras (`inspect`, `harbor`, `gym`, …).
- Add tests for digests, schemas, budgets, and campaign orchestration when
  touching those surfaces.
- Follow existing module layout under `src/verifierlab/`.
- Update docs when changing CLI commands, extras, or public claims.
- Trust-critical paths (decision, labels/vault, budgets, statistics, sandbox,
  cryptography) need **two reviews** — see [MAINTAINERS.md](MAINTAINERS.md) and
  [.github/CODEOWNERS](.github/CODEOWNERS).

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
- Public verifier defects: [docs/contributing/defects.md](docs/contributing/defects.md).

## Roadmap and ownership

- [ROADMAP.md](ROADMAP.md)
- [MAINTAINERS.md](MAINTAINERS.md)
- [docs/governance/charter.md](docs/governance/charter.md)

## License

By contributing, you agree that your contributions are licensed under Apache-2.0.
