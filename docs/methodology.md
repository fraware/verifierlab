# Methodology

How to run and interpret VerifierLab campaigns without overclaiming.

## Design intent

1. **Separate channels** — public verifier decisions vs sealed ground truth.
   Attack workers use the environment + `VerifierBroker` only; GT evaluation
   happens in the coordinator adjudicator after freeze.
2. **Separate cohorts** — ordinary baseline vs optimized attack search.
   Cohort tags are mandatory; persistent optimized strategies (BoN / beam /
   evolutionary / RL) checkpoint under the attack runtime.
3. **Pin everything** — campaign digests, seeds, package version, artifact
   `schema_version`.
4. **Budget explicitly** — query/step/time limits with a broker-backed ledger
   for verifier calls (plus env step accounting).
5. **Freeze before adjudicate/release** — labels must not feed the attacker’s
   observe loop; reports require `freeze → adjudicate → release-labels`.

## Recommended workflow

1. Write or select a campaign YAML; `valab campaign validate`.
2. Run ordinary baseline and optimized-tagged attacks under one access model per
   campaign (or stratify if multiple). Access models are capability-gated at the
   broker for black / gray / white / adaptive / transfer.
3. Freeze the run; adjudicate with the campaign’s GT provider; release labels.
4. Rebuild the offline report; archive the run digest.
5. Optionally open disclosure records for confirmed exploits
   ([disclosure.md](disclosure.md), [templates/disclosure.md](templates/disclosure.md)).
6. For repairs, use `compare_repair` / `run_repair_campaign` with a **fresh**
   attacker on the public channel (holdout, equalized budget, paired stats).
   See [limitations.md](limitations.md) for research-grade depth caveats.

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
- Prefer StatsPlan-compiled strata over ad-hoc overall pooling.

## Metamorphic / isomorphic checks

`verifierlab.statistics.metamorphic` supports GT invariance checks used by
isomorphic-style packs. Treat these as campaign-level assertions, not as a
general equivalence prover.

## Reproduction

Independent reproduction should follow
[reproduction-checklist.md](reproduction-checklist.md) and compare digests /
stratified metrics within stated tolerance—not screenshots alone. CI includes a
reproducible campaign bundle check (`scripts/repro_bundle_check.py`).
