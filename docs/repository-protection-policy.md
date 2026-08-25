# Repository protection policy (WP-19)

In-repo documentation of the intended GitHub branch protection / ruleset for
protected `main`. **This file cannot flip GitHub admin settings** from an
agent environment without repository admin rights. Maintainers must apply the
settings below in the GitHub UI (or via admin API) before claiming Gate G7
repository-complete.

Package version remains `0.2.0rc2` until a signed annotated tag after G7.

## Required status checks for protected `main`

Exact workflow job names that must pass before merge (match `.github/workflows/`):

| Required check (job name) | Workflow | Purpose |
| ------------------------- | -------- | ------- |
| `lint-type-test (3.11)` | `ci.yml` | Lint, types, pytest+coverage floor |
| `lint-type-test (3.12)` | `ci.yml` | Same on 3.12 |
| `lint-type-test (3.13)` | `ci.yml` | Same on 3.13 |
| `Process workers (ubuntu-latest)` | `ci.yml` | Process smoke (hard-fail) |
| `Process workers (macos-latest)` | `ci.yml` | Process smoke (hard-fail) |
| `adapter-fixtures` | `ci.yml` | Fixture/reference adapter paths |
| Adapters matrix jobs | `adapters.yml` | Release-qualified gym/inspect/openenv |
| `CodeQL (Python)` | `security.yml` | Security scanning |
| `Worker tree secret/leak scan` | `security.yml` | Worker plane leak scan |
| `Dependency audit + SBOM` | `security.yml` | pip-audit high/critical hard-fail on main |
| Docs build | `docs.yml` | MkDocs `--strict` when configured |

Optional but recommended before stable tag:

| Check | Workflow | Notes |
| ----- | -------- | ----- |
| Container isolation | `container-isolation.yml` | Rootless host required for security_grade |
| Reproduce | `reproduce.yml` | Bundle verify / local repro |

Windows process smoke remains soft-fail (`continue-on-error`) and is **not** a
required check — see [support-matrix.md](support-matrix.md).

## Branch rules (admin must enable)

- Protect `main` (and `release/*` when cut).
- Require the status checks listed above.
- Require a pull request before merging; dismiss stale reviews.
- Require **two** approving reviews for CODEOWNERS trust-critical paths
  (see `.github/CODEOWNERS`).
- Disallow force-push and deletion of `main`.
- Restrict who can push / bypass (admins only, preferably zero bypass).

## Release tag policy (in-workflow; already fail-closed)

`release.yml` `gate-tag` job enforces:

1. Annotated tag (`git cat-file -t` == `tag`)
2. Tag name equals `v` + `project.version` from `pyproject.toml`
3. `git verify-tag` succeeds — **no unsigned fallback**
4. Tag commit is an ancestor of `origin/main`

Do **not** publish to PyPI or create production signed tags from automation
agents without an explicit maintainer release action.

## What can be verified in-repo without admin

| Artifact | Verifiable here |
| -------- | --------------- |
| Workflows exist and encode signed-tag / audit / SBOM / provenance steps | yes |
| CODEOWNERS trust-critical dual-review intent | yes (file present; GitHub must enforce) |
| Adapter matrix honesty + schema registry | yes (tests/scripts) |
| Windows soft-fail posture documented | yes |
| Actual GitHub branch protection enabled | **no** — admin action required |
| Trusted publishing environment `pypi` configured | **no** — admin action required |
| Maintainer GPG/SSH tag signing keys allowlisted | **no** — admin action required |

## Related

- [contributing/release-process.md](contributing/release-process.md)
- [support-matrix.md](support-matrix.md)
- [quality-engineering.md](quality-engineering.md)
- [final-acceptance.md](final-acceptance.md)
