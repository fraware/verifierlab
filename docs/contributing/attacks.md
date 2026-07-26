# Contributing attacks

How to add ordinary or optimized-tagged attack cohorts.

## Goals

- Declare access model and budget up front.
- Persist attacker state across episodes when tagged optimized.
- Meter every verifier query through the broker.

## Layout

Attack implementations live under `src/verifierlab/attacks/` (families) or as
plugins discovered via `verifierlab.plugins`. Pack-local attack configs live
under pack `attacks/` directories.

## Required checks

- [ ] Budgets (queries, steps, wall time) are declared and enforced.
- [ ] Access capabilities match the campaign access model.
- [ ] Persistent attackers do not smuggle hidden labels.
- [ ] Fixtures for worker tests exclude ground truth.
- [ ] Plugin registry status matches tests you actually run.
- [ ] No truthiness conversion when interpreting verifier feedback.

## Do not

- Use oracle isolation, vault cryptography, budget atomicity, or OS sandboxing
  as “good first issues” — those are maintainer/security work.
- Bypass the broker for “just one” query.
- Claim optimization depth beyond what `docs/limitations.md` allows.

## Related

- [docs/attacks.md](../attacks.md)
- [docs/limitations.md](../limitations.md)
- [Verifiers guide](verifiers.md)
- [Benchmark packs](benchmark-packs.md)
