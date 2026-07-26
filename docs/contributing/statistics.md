# Contributing statistics

How to add or change StatsPlan estimands, intervals, and report metrics.

## Goals

- Keep primary results stratified (verifier, environment, access, attack,
  budget, split, pack version).
- Prefer pre-declared StatsPlan execution over post-hoc score fishing.
- Dual-review any change under `src/verifierlab/statistics/`.

## Surfaces

- `verifierlab.statistics.plan` — StatsPlan models
- `verifierlab.statistics.intervals` — interval methods
- Reports rebuild from released artifacts only

## Required checks

- [ ] Estimand and interval method named in pack/campaign metadata.
- [ ] Unit tests for edge cases (empty splits, zero events, abstentions).
- [ ] No truthiness conversion when mapping decisions to Bernoulli trials.
- [ ] Documentation of assumptions and non-claims.
- [ ] Two reviews for statistics path changes ([MAINTAINERS.md](https://github.com/fraware/verifierlab/blob/main/MAINTAINERS.md)).

## Do not

- Introduce a single global “verifier score” leaderboard for beta.
- Change primary metrics on published packs without governance (major bump).
- Hide multiplicity or peeking adjustments.

## Related

- [docs/labels-and-stats.md](../labels-and-stats.md)
- [Benchmark packs](benchmark-packs.md)
- [Governance charter](../governance/charter.md)
