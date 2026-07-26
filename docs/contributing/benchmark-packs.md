# Contributing benchmark packs

How to author or extend packs under `campaigns/packs/`.

## Goals

- Keep science content runnable while adding sidecar manifests toward the pack
  tree contract (profile JSON, splits, expected public digests).
- Never place hidden labels in the public pack tree.
- Stratify results — no universal aggregate leaderboard.

## Expected pack contents (science packs A–E)

| Asset | Where |
| ----- | ----- |
| Baseline | YAML `baseline` |
| Two optimized attacks | YAML `attacks` with `cohort: optimized` (≥2) |
| Access model | YAML `access_model` |
| Budget | YAML `budget` |
| Splits | YAML `splits` and/or `pack-*/splits.json` |
| Primary estimand | `metadata.primary_estimand` (+ mirrored in digests) |
| Interval method | `stats_plan.methods` / `metadata.interval_method` |
| Planted failure | `metadata.planted_failure` + `pack-*/planted-failure.json` |
| Expected public digests | `pack-*/expected-public-digests.json` |
| Hidden adjudication protocol | `pack-*/adjudication-protocol.json` (labels never included) |

Pack F (integrity) remains CI-required but is not one of the five science packs.

Regenerate sidecars:

```bash
python -c "from pathlib import Path; from verifierlab.campaigns.packs import packs_root, write_pack_sidecars
root = packs_root()
for p in sorted(root.glob('pack-[a-e]-*.yaml')):
    write_pack_sidecars(p, force=True)
    print(p.name)"
valab pack lint campaigns/packs/pack-a-outcome-vs-process.yaml
```

## Required checks

- [ ] `valab campaign validate` (and `valab pack lint|verify`) passes.
- [ ] Public digests match expected sidecars.
- [ ] Science completeness checklist green (baseline, ≥2 optimized, estimand, intervals).
- [ ] Major/minor construct changes follow
      [governance charter](../governance/charter.md).
- [ ] Worker fixtures / public YAML contain no hidden labels.
- [ ] StatsPlan fields are executable, not decorative.

## Do not

- Change primary estimand or hidden reference without council review (major).
- Claim pack results as verifier soundness proofs.
- Commit vault keys or unreleased labels.

## Related

- [docs/methodology.md](../methodology.md)
- [docs/labels-and-stats.md](../labels-and-stats.md)
- [Statistics guide](statistics.md)
- [Governance charter](../governance/charter.md)
