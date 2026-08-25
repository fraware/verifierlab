# Flagship study `flagship-2026`

Preregistered scientific demonstration for VerifierLab final assurance (WP-13).
Package line: `0.2.0rc2` on `integration/final-assurance`.

## Claim boundary (read this first)

| Fact | Value |
| ---- | ----- |
| Derived maturity | **`internally_verified`** (ordinal 2) |
| `security_grade_execution` | **False** |
| Ladder blockers | `independent_review_missing`, `independent_reconstruction_missing` |
| Prospective scientific blockers | `security_grade_execution`, independent review, independent reconstruction |
| Underpowered primary estimands | E1–E8 task-cluster cells marked indeterminate where underpowered |
| Planted calibration | Reported separately; **does not** support unknown-adversary robustness |
| Clean-room under `reproduction_bundle/` | Mechanical only — **not** independent verification |

**Do not claim** from this bundle alone:

- `scientifically_qualified`
- `security_grade` / `security_grade_execution=true`
- `deployment_calibrated`
- soundness, “proven robust,” or verifier SOTA

This host refused security-grade execution (no rootless Docker / separate
domain). Fail-closed: maturity stays capped until evidence exists. Policy:
[`docs/claim-language.md`](../../docs/claim-language.md).

## Task families

1. Transactional/authorization: `campaigns/packs/pack-f-integrity-auth.yaml`
2. Code/test / executable remapping: `campaigns/packs/pack-c-isomorphic.yaml`
3. Rubric/policy/process: `campaigns/packs/pack-b-rubric.yaml`

## Partitions

discovery, clean_regression, repair_holdout, final_sealed_evaluation,
transfer_corpus, planted_calibration (never pooled with unknown robustness).

## Primary estimands

E1–E8 in `preregistration.json`. Power planned at task-cluster level;
underpowered cells are marked indeterminate and block scientific promotion.

## Artifacts

- `scientific_study_registration.json`
- `preregistration.json`, `partitions.json`, `attack_portfolio.json`
- `envassure/`, `assurance_chain_manifest.json`
- `security_grade_attempt.json`, `sealed_run.json`, `claim_table.json`
- `maturity_qualification.json`, `evidence_facts.json`
- `reproduction_bundle/`

EnvAssure bundle digest: `fd26681d1a1467dfdada0236df71d8b8c2f81236e36cc60aefa1ff6cc29e2de8`
