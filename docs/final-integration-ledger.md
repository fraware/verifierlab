# Final integration ledger

Inventory freeze and canonical integration line for VerifierLab final assurance
completion (Gate G0/G1, WP-00). This ledger maps each intended **feature**
source to commits on `integration/final-assurance`. Validation-only histories
are recorded as **not merged**.

Package version remains `0.2.0rc2` until Gate G7.

## Integration line

| Field | Value |
| ----- | ----- |
| Branch | `integration/final-assurance` |
| Created from | `main` |
| Starting SHA | `f59cd5b9bceb9785642938a634440e4eccf2d12f` |
| Starting subject | `chore: remove accidental empty placeholder` |
| Created | 2026-08-25 |
| Push | **not pushed** (WP-00 constraint) |
| Merge to `main` | **not done** (WP-00 constraint) |

Untracked local spec `VerifierLab_Final_Engineering_Completion_Specification_2026-08-25.docx`
stays out of the repository.

## Disposition rules applied

- Feature deltas only: rebase/cherry-pick of feature commits.
- Never merge validation-only PRs: #14, #16, #18, #20, #29, #40, #41, #42,
  #44, #46, #48 and analog `validation/*` branches.
- Temporary one-shot validator workflows (`*-once.yml`) are omitted; the
  code/test commits they produced are kept.
- Merge commits that stitch already-landed stacks are omitted (do not merge
  the whole stack twice).
- Conflicts are never resolved by whole-file ours/theirs without semantic
  review.
- Historical CI on validation marker SHAs does **not** automatically apply to
  this tree. Ordinary CI must be re-run here.

## Source map (heads at inventory freeze)

| Source | Remote branch | Head SHA | Merge-base vs `main` | Status |
| ------ | ------------- | -------- | -------------------- | ------ |
| PR #12 | `origin/maintenance/ci-lint-baseline` | `cf5600cb0d6bf5f83a8801e592d7a1a5c2438c1b` | `f59cd5b` | pending |
| PR #5 | `origin/assurance/p0-scientific-closure` | `7fa27c9d272c8e416fd862c070d7c26e296d1a26` | `54dab07c` | pending |
| PR #6 | `origin/assurance/p0-release-integrity` | `2f8172101a10a68601ea0a59804d9ad396e57954` | `54dab07c` | pending |
| PR #7 | `origin/assurance/p0-score-fail-closed` | `a90ea6b64cd37b8cb996be4db716bad744219ea7` | `54dab07c` | pending |
| PR #8 | `origin/assurance/p0-statistics-plan` | `77190f1b33156f48e89efe9f250deaa7e01261bc` | `54dab07c` | pending |
| PR #11 | `origin/assurance/p0-worker-plane-isolation` | `0d08279417b795fd6e6717ea97f126917cfdd3d3` | `54dab07c` | pending |
| PR #27 | `origin/assurance/p0-preregistered-estimands` | `f6e6f6fac2f023d05eb54cc11e9cb2c86f6fb47b` | `54dab07c` | pending |
| PR #9 | `origin/assurance/p0-repair-reattack` | `4a981f89f8a3d6070163cd68576ee623b89843ce` | `54dab07c` | pending |
| Container executor | `origin/assurance/p0-container-execution` | `81428a7bdac977ce5670c1c8a95352a898cb3e6a` | `54dab07c` | pending |
| PR #39 H/F/S | `origin/research/hacker-fixer-solver` | `f9d1162` (see unique commits) | `f59cd5b` | pending |
| PR #43 surface | `origin/research/robustness-response-surface-v2` | (stacked on combined research core) | `f59cd5b` | pending |
| PR #45 metamorphic | `origin/research/metamorphic-registry` | (stacked) | `f59cd5b` | pending |
| PR #47 failure layers | `origin/research/failure-layer-taxonomy` | `06af47ebd0b240900e45002eae45b24b96d312ec` | `f59cd5b` | pending |
| WP-01 calibration | `origin/research/planted-calibration` | `085a7f7c295fee5da289cc2435ebf8384a79a1ea` | `f59cd5b` | pending |
| PR #10 maturity | `origin/assurance/p0-claim-maturity` | `d87b88e8be853fffd7e0ed65704c95addfaabf36` | `54dab07c` | pending (policy seed only) |

H/F/S head (unique stack tip, excluding one-shot remove): `f9d1162`.

## Validation-only sources (not merged)

| PR / branch | Head / note | Why omitted |
| ----------- | ----------- | ----------- |
| #14, #16, #18, #20, #29 | validation P0 markers | Evidence surfaces, not product deltas |
| #40, #41, #42, #44, #46, #48 | research validation markers | Prove *those exact trees only* |
| `origin/validation/p0-container-clean` | container validation | Forbidden; take `p0-container-execution` feature commits only |
| `origin/validation/research-core-combined` @ `7eaa8788` | combined research core | Historical validation of a composed tree; compose via unique feature commits |
| `origin/validation/*-clean` | various | Validation markers |
| Highest validated research composition | `31f47568` (PR #47/#48) | Does not apply to this integration SHA until equivalent tests rerun |

## Intentional omissions (feature branches)

Temporary one-shot GitHub Actions workflows that add then delete `*-once.yml`
are omitted on the integration tree. The product/test commits they produced
are cherry-picked. Documented per slice below as each slice lands.

The validation composer commit `4e8c3b8` (`chore(validation): compose research
assurance core`) is omitted: it restates already-landed P0 + H/F/S files and
would merge the stack twice. Pack sidecar refresh after estimands is taken
from PR #27 feature commit `43f2154`, not from the composer.

## Slice log

Slices are recorded as they land. `final_commits` are SHAs **on this branch**.

### Slice 0 — inventory freeze

| Field | Value |
| ----- | ----- |
| Contents | This ledger + `docs/claim-invalidation-ledger.md` |
| Conflicts | none |
| Tests rerun | none (docs only) |
| Historical evidence applies | n/a |

---

Further slices are appended below as cherry-picks land.
