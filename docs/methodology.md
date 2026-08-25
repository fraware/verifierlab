# Methodology

How to run and interpret VerifierLab campaigns without overclaiming.
Status: `0.2.0rc2` on `integration/final-assurance`. See
[claim-language.md](claim-language.md).

## Design intent

1. **Three trust planes** — worker / coordinator / adjudicator; GT never on the
   attack plane.
2. **Separate cohorts** — ordinary baseline vs optimized attack search with
   mandatory cohort tags and metered budgets.
3. **Pin everything** — campaign digests, profiles (`ScoreDecisionMapping`),
   seeds, package version, `schema_version`.
4. **Freeze before adjudicate/release** — `LabelReleaseReceipt`; reports require
   the full lifecycle.
5. **Derive maturity** — `valab assurance qualify` from artifacts; never promote
   with caller booleans.

## Recommended workflow

1. `valab campaign validate` then run under an explicit access model.
2. Freeze → adjudicate → `release-labels` → offline report.
3. Optional method surfaces: H/F/S, response surface (exact cells), metamorphic
   search, planted calibration (not unknown-adversary robustness).
4. Bind EnvAssure refs when an environment evidence bundle exists; indeterminate
   upstream cannot be erased by verifier success.
5. For deployment claims: register predictions **before** outcomes
   (`valab deployment …`); synthetic fixtures stay non-deployment.
6. Independent reconstruction: `valab reproduce BUNDLE` (+ external attestation).

## What a result means

| Result | Interpret as |
| ------ | ------------ |
| Exploit recovered under budget | Evidence of failure for that access/cohort/boundary |
| No exploit recovered | Failure to find — not soundness |
| FAR/FRR + intervals | Labeled, non-abstaining units; respect denominators and clustering |
| Response surface cell | Exact coordinate evidence — not a scalar robustness score |
| Planted calibration hit | Detector sensitivity under planted truth — not unknown robustness |
| `internally_verified` study | Publishable with blockers; not `scientifically_qualified` |

## Statistics

- Prefer task/environment cluster sampling; no silent trajectory pseudo-replication.
- Holm / Bonferroni for families; exploratory surfaces stay descriptive.
- Equivalence is per-estimand (TOST-compatible); non-rejection ≠ equivalence.
- Underpowered primary estimands → indeterminate + maturity blocker.

## Reproduction

Follow [reproduction-checklist.md](reproduction-checklist.md) and
[clean-room-protocol.md](clean-room-protocol.md). Compare digests and stratified
metrics — not screenshots alone.
