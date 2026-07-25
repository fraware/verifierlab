# Labels, freeze, and statistics

Lifecycle: Draft → Validated → Baseline → Attack → Freeze → Label release →
Triage → Stats → Repair → Disclosure.

## Label vault

- `LabelVault` commits sealed labels on the **coordinator** after workers finish
- Workers and attack strategies receive public verifier feedback only (no
  `gt_valid`)
- `worker_payload` returns `{commitment, label: null}` style commitments
- Reads require freeze then release; access is audit-logged
- Post-freeze `commit` raises (injection rejected)

## Freeze

- `FreezeRecord` is content-digested; `assert_freeze_immutable` rejects mutation
- CLI: `valab campaign freeze RUN_DIR` then `valab campaign release-labels RUN_DIR`

## Metrics

- FAR = FP / (FP + TN) among labeled **invalid**, non-abstaining, non-failed units
- FRR = FN / (FN + TP) among labeled **valid**, non-abstaining, non-failed units
- Abstention (`accepted is None` / `abstain`) and missing GT are tracked separately
- Metrics are stratified by cohort and must not pool across access models

## Statistics

- `valab stats power` — binomial power / sample-size planning (normal approximation)
- Wilson and Clopper–Pearson intervals in `verifierlab.statistics`
- Clopper–Pearson uses a pure-Python incomplete beta (no SciPy in base). See
  [limitations.md](limitations.md) for numerical caveats.
- Time-to-exploit helpers and Kaplan–Meier-style censored survival utilities live
  in `verifierlab.statistics` for research workflows.

## Related

- [Disclosure](disclosure.md)
- [Methodology](methodology.md)
- [Threat model](threat-model.md)
