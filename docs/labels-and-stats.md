# Labels, freeze, and statistics

Lifecycle: Draft → Validated → Baseline → Attack → **Freeze → Adjudicate →
Label release** → Triage → Stats → Repair → Disclosure.

## Label vault (v2)

- `LabelVault` commits sealed labels on the **coordinator** after freeze
- Attack workers never load GT providers; commitments are `digest(trajectory || nonce)`
- Reads require freeze **and** release; access is audit-logged
- Post-freeze `commit` raises (injection rejected)
- Labels are encrypted at rest with salted commitments (vault v2)

## Freeze → adjudicate → release

```bash
uv run valab campaign freeze RUN_DIR
uv run valab campaign adjudicate RUN_DIR --campaign campaigns/<campaign>.yaml
uv run valab campaign release-labels RUN_DIR
uv run valab report builds RUN_DIR
```

- `FreezeRecord` / adjudication / release records append to an integrity chain
  (`prev_digest`); do not mutate prior CAS objects
- Hidden GT evaluation runs only in the adjudicator (coordinator process)
- `gt_valid` / exploit enrichment appear after adjudication, not during attack

## Metrics

- FAR = FP / (FP + TN) among labeled **invalid**, non-abstaining, non-failed units
- FRR = FN / (FN + TP) among labeled **valid**, non-abstaining, non-failed units
- Abstention (`accepted is None` / `abstain`) and missing GT are tracked separately
- Metrics are stratified by cohort and must not pool across access models
- Default reports avoid overall cohort pooling; prefer StatsPlan-driven strata

## Statistics / StatsPlan

- `valab stats power` — binomial power / sample-size planning (normal approximation)
- Wilson and Clopper–Pearson intervals in `verifierlab.statistics`
- Clopper–Pearson uses a pure-Python incomplete beta (no SciPy in base). See
  [limitations.md](limitations.md) for numerical caveats.
- Declared `StatsPlan` on `CampaignSpec` compiles into report estimands (per-cohort
  FAR/FRR, optimization gap, CIs, missingness) via `verifierlab.statistics.plan`
- Time-to-exploit helpers and Kaplan–Meier-style censored survival utilities live
  in `verifierlab.statistics` for research workflows

## Related

- [Disclosure](disclosure.md)
- [Methodology](methodology.md)
- [Threat model](threat-model.md)
- [Getting started](getting-started.md)
