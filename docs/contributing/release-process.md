# Release process

Engineering notes for cutting VerifierLab release candidates on the
`0.2.0rc` line. Admin GitHub settings (rulesets, trusted publishing) are
documented for maintainers; this guide covers repository expectations.

## Version line

- Current: `0.2.0rc2` (see `pyproject.toml`).
- This gate tag: `v0.2.0rc2` (annotated, signed).
- Next after RC gate: `v0.2.0` (stable); do **not** rebrand to `0.2.0b1`.
- Spec text that says beta maps to this RC line.

## Branch topology

- `main` — public development
- `release/0.2-rc` — release branch
- Workflows watch both; do not revive dead `master` triggers

## Signed tags

Annotated tags must verify against the maintainer GPG/SSH identity allowlist
(maintainer-private until published in the release runbook). Unsigned or
wrong-identity tags must fail the release workflow gate.

## Release workflow expectations (Milestone A)

Workflows (required names):

| Workflow | Role |
| --- | --- |
| `ci.yml` | Core lint/type/test + wheel smoke on `main` / `release/0.2-rc` |
| `adapters.yml` | Extras matrix; gym/inspect/openenv hard-fail |
| `security.yml` | CodeQL + pip-audit/SBOM (high-fail on `v*` tags) |
| `docs.yml` | MkDocs Material `--strict` build (+ optional Pages) |
| `reproduce.yml` | Published bundle verify, else local `repro_bundle_check` |
| `release.yml` | Tag/dispatch: smoke → wheel/sdist → checksums/SBOM/manifest → publish |

Local helpers:

```bash
uv run python scripts/build_release_manifest.py --dist-dir dist
uv run python scripts/verify_repro_bundle.py --local-campaign campaigns/fake-smoke.yaml
uv run mkdocs build --strict   # requires --extra docs
```

1. Verify annotated tag identity.
2. Python 3.11–3.13 tests; thread + process workers.
3. Linux / macOS / Windows smoke.
4. Build wheel + sdist **once**; install in clean envs.
5. Release-qualified extras + separation tests.
6. Checksums, CycloneDX SBOM, release manifest, provenance.
7. PyPI trusted publishing; attach **byte-identical** artifacts to GitHub Release.

## Integrity rules for release claims

- No live adapter claim from fixture-only evidence.
- Worker / CLI / adjudicator images keep separate trust boundaries.
- Known limitations stay in `docs/limitations.md`.

## Campaign “signing” semantics (this RC line)

On the `0.2.0rc` line, a **signed campaign** means:

1. **Content-addressed campaign digest** over the public `CampaignSpec` binding
2. **Pinned versions** (`pinned_versions.verifierlab`, `pinned_versions.campaign`, …)
3. **Sealed run manifest** after `freeze` (immutable tip + digests)

Optional author signatures (vault `sign` role or sigstore) are a stretch goal and
are **not** required to claim campaign integrity on this line. Pack sidecars
under `campaigns/packs/pack-{a-e}/expected-public-digests.json` record the
public digests used by `valab pack verify` / `valab pack reproduce`.

## Dual review

Merges into release-critical paths (decision, labels, budgets, statistics,
sandbox, crypto) require two approvals — [MAINTAINERS.md](https://github.com/fraware/verifierlab/blob/main/MAINTAINERS.md).

## Related

- [ROADMAP.md](https://github.com/fraware/verifierlab/blob/main/ROADMAP.md)
- [docs/beta-acceptance.md](../beta-acceptance.md)
- [docs/reproduction-checklist.md](../reproduction-checklist.md)
- [CHANGELOG.md](https://github.com/fraware/verifierlab/blob/main/CHANGELOG.md)
