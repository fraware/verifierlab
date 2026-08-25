# Quality engineering (WP-18)

Honest coverage, property, mutation, fuzz, audit, and SBOM posture for the
final release-candidate tree. Package remains `0.2.0rc2` until the release
version is deliberately advanced.

## Coverage partitions

Global CI floor stays **`--cov-fail-under=40`** (see `.github/workflows/ci.yml`).
Module-specific targets live in `config/coverage-partitions.toml`.

| Partition | Practical target | Intent |
| --------- | ---------------- | ------ |
| `semantic_core` | ≥90% branch | canonicalization, CAS, budgets, lifecycle |
| `claim_critical` | ≥95% practical (100% reachable policy) | decision, vault, boundary, resolver, repair provenance |
| `methods` | ≥85% | surface, H/F/S, EnvAssure, deployment, reproduce |

Report (optional / nightly):

```bash
uv run pytest --cov=verifierlab --cov-branch -m "not pack_heavy"
uv run python scripts/check_coverage_partitions.py
uv run python scripts/check_coverage_partitions.py --enforce   # nightly
```

Do not suddenly raise the global floor until partition reports are green on
Python 3.11-3.13.

## Property tests

Hypothesis is already in `[dev]`. Additional property suites:

- `tests/test_science_core.py` - canonicalization digests
- `tests/test_property_wp18.py` - budgets, lifecycle, migration non-promotion

## Mutation / fuzz scaffolding

Nightly-oriented hooks (not required for default CI green):

```bash
python scripts/quality_mutation_fuzz.py
python scripts/quality_mutation_fuzz.py --corpus-only
# Optional heavy mutation (kill high-risk mutants on policy modules):
# mutmut run --paths-to-mutate=src/verifierlab/api/decision.py
```

Regression corpus: `tests/fixtures/fuzz_corpus/` (includes unknown-schema
fail-closed entry).

## Dependency audit

`security.yml` runs CodeQL on PR/push. On protected release lines, `pip-audit`
runs in strict mode and **any unwaived reported vulnerability hard-fails**.
The release workflow does not silently downgrade or suppress findings by
severity. Pull requests targeting `main` use the same hard-fail posture.

Time-bounded waiver documents may be recorded under `security/waivers/` for
review/audit history, but this release does **not** automatically convert those
documents into `pip-audit` suppressions. A waiver therefore cannot make a red
security workflow green by itself; an explicit reviewed workflow change would
be required.

## Worker image SBOM + secret scan

- Release SBOM: CycloneDX via `release.yml` / `security.yml`.
- Worker image SBOM: generate after build, e.g.
  `syft docker/worker -o cyclonedx-json > dist/worker-sbom.cdx.json`
  (documented hook; not yet a required default CI artifact until rootless
  worker publish is enabled).
- Secret / leak scan of the worker tree:

```bash
python scripts/scan_worker_secrets.py
```

The scanner refuses coordinator/adjudicator modules and common secret
patterns under `docker/worker/`.
