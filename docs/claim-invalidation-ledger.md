# Claim invalidation ledger

This ledger records scientific and product claims that **must not** be cited
from historical trees once `integration/final-assurance` exists. It is part of
Gate G0/G1 (WP-00). New claims may be issued only from artifacts reconstructed
on this integration line (and later protected `main`).

Integration starting SHA: `f59cd5b9bceb9785642938a634440e4eccf2d12f`
(`main` / `0.2.0rc2` product line, 2026-08-25 freeze).

## Active invalidations

### INV-BEAM-001 — Beam-derived robustness results

**Status:** INVALID until rerun on this tree after PR #5 scientific-closure
deltas are present and the Beam family is re-executed under the current
checkpoint/score schema.

**Why:** PR #5 (`origin/assurance/p0-scientific-closure`, head
`7fa27c9d272c8e416fd862c070d7c26e296d1a26`) changes BeamSearch ranking
(retain highest-scoring candidates; prevent top-k inversion) and migrates
checkpoints to score schema v2. Any robustness, attack-success, or ranking
number produced by pre-#5 BeamSearch is not comparable to post-#5 BeamSearch.

**Applies to:** any study, pack run, response-surface cell, H/F/S round, or
report whose attack identity includes BeamSearch (or a Beam checkpoint) from
a tree that does not contain both:

- `0912ab9` `fix(attacks): retain highest-scoring beam candidates`
- `4c49581` `fix(attacks): migrate BeamSearch checkpoints to score schema v2`

**Not a substitute:** validation-marker CI on historical SHAs, including
`31f47568` and `7eaa8788`.

**Revalidation requirement (later WPs, not WP-00):** rerun Beam-dependent
experiments after the integration tree contains the #5 deltas; bind new run
digests. Do not migrate old numeric claims forward.

### INV-SCORE-001 — Implicit-score results are noncanonical

**Status:** NONCANONICAL.

**Why:** Prior to PR #7 (`origin/assurance/p0-score-fail-closed`, head
`a90ea6b64cd37b8cb996be4db716bad744219ea7`), numeric scores could imply
`accepted` via an implicit 0.5 threshold. Canonical identity of an exercised
verifier now requires an explicit `ScoreDecisionMapping` bound into the
profile digest. Results that treated a raw score as an accept/reject decision
without a declared mapping are not part of the canonical decision space.

**Applies to:** any Decision, campaign row, repair comparison, StatsPlan
estimand, or report produced without profile-declared score mapping, including
trees at or before `f59cd5b` that still contain implicit 0.5 acceptance.

**Revalidation requirement:** rerun or re-adjudicate only under a profile
that declares comparator/threshold/scale. Missing mapping ⇒ `accepted=None`
(fail closed). Do not back-interpret historical implicit accepts as canonical.

## Related non-promotions (not historical numbers; still fail-closed)

These are not “old numbers to discard” so much as **labels that must not be
issued** from incomplete evidence. Recorded here so WP-00 does not accidentally
treat landed policy seeds as qualification.

| ID | Rule |
| -- | ---- |
| NG-local-exec | Process/thread execution never promotes scientific qualification. |
| NG-worker-gt | GT/vault/adjudicator modules must not appear in the worker image. |
| NG-validation-merge | Validation PRs are evidence surfaces and are not product history. |
| NG-maturity-booleans | Caller-supplied `AssuranceEvidence` booleans are not the public qualification API (WP-05 `EvidenceResolver`). PR #10 is a policy seed only. |
| NG-planted-robustness | Planted calibration must hard-code `supports_unknown_robustness_claim=false`. |
| NG-surface-scalar | Do not interpolate/average a response surface into a scalar robustness score. |

## Historical validation SHAs (tree-specific; do not transplant)

| SHA | What it proved | Applies to integration line? |
| --- | -------------- | ---------------------------- |
| `7eaa8788` | Combined research core on that exact composed tree (PR #42) | No — rerun equivalent tests here |
| `31f47568` | Highest validated research composition (PR #47/#48) | No — rerun equivalent tests here |
| `085a7f7c` | Planted-calibration head; zero workflow runs at handoff | No — WP-01 must validate, then integrate |

## Closure

Invalidations remain open until a later work package records a **new**
artifact digest on this integration line (or protected `main`) that
reconstructs the claim. Closing an invalidation by citing a validation-only
PR is forbidden.
