# Flagship study flagship-2026

Preregistered scientific demonstration for VerifierLab final assurance (WP-13).

## Claim boundary (exact)

- Derived maturity: **internally_verified** (ordinal 2).
- `security_grade_execution`: **False**.
- Ladder blockers at this level: independent_review_missing, independent_reconstruction_missing.
- Prospective scientific blockers (facts not yet true): security_grade_execution, independent_review, independent_reconstruction.
- Underpowered primary estimands (task-cluster): E1_sealed_far_attack_success, E2_paired_repair_delta, E3_clean_frr_delta, E4_fresh_stronger_reattack, E5_metamorphic_violation, E6_planted_sensitivity_fpr, E7_time_to_exploit, E8_surface_budget_access_contrast.
- Planted calibration is reported separately and does **not** support
  unknown-adversary robustness claims.
- This host refused security-grade execution (no rootless Docker / separate
  domain). Fail-closed: never claim `scientifically_qualified` or
  `security_grade` without evidence.
- No `deployment_calibrated` claim (capability only; no real prospective field
  outcomes).
- Clean-room reproduction under `reproduction_bundle/` is **NOT** independent.

## Task families

1. Transactional/authorization: `campaigns/packs/pack-f-integrity-auth.yaml`
2. Code/test / executable remapping: `campaigns/packs/pack-c-isomorphic.yaml`
3. Rubric/policy/process: `campaigns/packs/pack-b-rubric.yaml`

## Partitions

discovery, clean_regression, repair_holdout, final_sealed_evaluation,
transfer_corpus, planted_calibration (never pooled with unknown robustness).

## Primary estimands

E1-E8 in `preregistration.json`. Power planned at task-cluster level;
underpowered cells are marked indeterminate.

## Artifacts

- `scientific_study_registration.json`
- `preregistration.json`, `partitions.json`, `attack_portfolio.json`
- `envassure/`, `assurance_chain_manifest.json`
- `security_grade_attempt.json`, `sealed_run.json`, `claim_table.json`
- `maturity_qualification.json`, `evidence_facts.json`
- `reproduction_bundle/`

EnvAssure bundle digest: `fd26681d1a1467dfdada0236df71d8b8c2f81236e36cc60aefa1ff6cc29e2de8`
