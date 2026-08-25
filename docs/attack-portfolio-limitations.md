# Attack portfolio depth limitations (WP-09)

This note records honest capability depth for VerifierLab's built-in attack
portfolio. It is not a robustness claim.

## Families

| Family | Depth | Notes |
| ------ | ----- | ----- |
| ordinary | shallow baseline | Intended-policy cohort only |
| random_fuzz / structured_fuzz / coverage_fuzz | schema-guided search | Not adaptive adversary evidence alone |
| evolutionary / rl_tabular | local search | Limited state; not model-capable |
| best_of_n / beam | budgeted search | Candidate evals count only with broker |
| metamorphic_search | registered transforms | `invalid_transform` ≠ verifier failure |
| exploit_transfer | non-adaptive replay | Discovery ≠ held-out corpus |
| model plugin (fixture) | fixture only | Live providers require extras |

## Hard separations

- Planted strength calibration never supports unknown-robustness claims
  (`supports_unknown_robustness_claim=false`).
- Access-model completeness is enumerated in `AccessModel`; portfolios must
  name only known values.
- Every candidate evaluation should be metered against `AttackBudgetContract`.

See `verifierlab.attacks.portfolio.PORTFOLIO_DEPTH_LIMITATIONS` for the
machine-readable copy bound into `AttackPortfolioManifest`.
