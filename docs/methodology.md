# Methodology

How to run and interpret VerifierLab campaigns without overclaiming.

## Design intent

1. **Separate channels** — public verifier decisions vs sealed ground truth.
2. **Separate cohorts** — ordinary baseline vs optimized attack search.
3. **Pin everything** — campaign digests, seeds, package version, artifact
   `schema_version`.
4. **Budget explicitly** — query/step/time limits with a recorded ledger.
5. **Freeze before release** — labels are not part of the attacker’s observe loop
   until freeze + release.

## Recommended workflow

1. Write or select a campaign YAML; `valab campaign validate`.
2. Run ordinary baseline and optimized attacks under one access model per
   campaign (or stratify if multiple).
3. Freeze the run; release labels when ready for triage/stats.
4. Rebuild the offline report; archive the run digest.
5. Optionally open disclosure records for confirmed exploits
   ([disclosure.md](disclosure.md)).
6. For repairs, use `compare_repair` with a **fresh** attacker on the public
   channel only.

## What a result means

| Result | Interpret as |
| ------ | ------------ |
| Exploit recovered under budget | Evidence the verifier failed for that access model / cohort / seed |
| No exploit recovered | Failure to find an exploit under the stated budget—not a proof of soundness |
| FAR / FRR with intervals | Descriptive error rates on labeled, non-abstaining units; respect denominators |
| Pack taxonomy match | Planted class recovered; useful for regression, not field prevalence |

## Statistics caveats

- Wilson and Clopper–Pearson in base are pure Python; extreme parameters may
  differ slightly from SciPy (see [limitations.md](limitations.md)).
- Do not pool across access models or cohorts.
- Abstentions and missing labels are tracked separately from FAR/FRR
  denominators.
- Power analysis (`valab stats power`) uses a normal approximation for planning.

## Metamorphic / isomorphic checks

`verifierlab.statistics.metamorphic` supports GT invariance checks used by
isomorphic-style packs. Treat these as campaign-level assertions, not as a
general equivalence prover.

## Reproduction

Independent reproduction should follow
[reproduction-checklist.md](reproduction-checklist.md) and compare digests /
stratified metrics within stated tolerance—not screenshots alone.
