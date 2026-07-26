# Concepts

## Verifier

A callable exposed through the public decision channel, typically decorated with
`@verifier`. It produces accept / reject / abstain-style decisions over
trajectories or observations. The public channel is distinct from ground truth.

Inspect with:

```bash
valab inspect examples.refunds.verifier:grade
```

## Ground truth (GT)

Labels that judge whether a trajectory is actually valid. GT is held on the
**coordinator**, evaluated only during adjudication after freeze, sealed in the
label vault, and not given to workers or attack strategies before release. See
[labels-and-stats.md](labels-and-stats.md).

## Campaign

A pinned specification (`CampaignSpec`): environment, verifier, GT provider,
baseline, attacks, budget, access model, seed, stats plan, and disclosure class.
Campaigns are YAML/JSON files under `campaigns/`.

## Access model

How much the attacker may assume about the verifier (black-box, gray-box,
white-box, adaptive, transfer, side-channel). Metrics must be stratified by
access model—do not pool blindly.

## Cohorts

- **ordinary** — baseline / non-optimized behavior
- **optimized** — search, fuzz, evolutionary, inference, RL, or other attack
  engines that optimize against the public channel

Never pool ordinary and optimized metrics without stratification.

## Budget and ledger

Campaigns declare query, step, and wall-time limits. The ledger records usage
and applies an overrun policy (`stop` or record-and-continue). Under-counting
budgets is treated as an integrity failure in self-tests.

## Content-addressed store (CAS)

Artifacts serialize to canonical JSON and are keyed by SHA-256 digests under
`.valab/store/`. Run identity is a digest over the immutable bundle, not a
mutable folder name alone.

## Lifecycle

Draft → Validated → Baseline → Attack → **Freeze → Adjudicate → Label release** →
Triage → Stats → Repair → Disclosure. Illegal jumps are rejected. See
[disclosure.md](disclosure.md) for the separate disclosure registry states.
Reports require the freeze → adjudicate → release sequence.

## Exploits and taxonomy

Recovered failures are classified into taxonomy classes (unauthorized action,
duplicate effect, integrity tamper, timeout bypass, approval laundering, reward
hacking, process shortcut, evaluation cheating, isomorphic relabel, rubric
gaming, other). Planted packs assert expected recovery classes.

## Assurance report

`valab report builds RUN_DIR` rebuilds HTML/JSON/CSV from immutable
`work_units/` and the run manifest. Reports are not a live dashboard; the
`[dashboard]` extra is reserved and not shipped in this alpha.
