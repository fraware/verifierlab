# Architecture

VerifierLab is an evidence-closed assurance instrument with three trust planes,
content-addressed artifacts, and maturity labels derived only from reconstructable
facts. Package: `0.2.0rc2` on `integration/final-assurance` (not yet stable
`main`).

```text
CLI (valab)
    → Campaign / study engine
        → Worker attack plane (process or digest-pinned rootless container)
        → Coordinator (freeze, CAS, budgets, attacker-state envelopes)
        → Adjudicator (GT / vault — never on the attack plane)
    → LabelReleaseReceipt → offline report / EvidenceResolver
```

## Three trust planes

| Plane | Allowed | Forbidden |
| ----- | ------- | --------- |
| Worker (attack) | Environment + verifier broker, public feedback, attacker state envelopes | GT, vault, adjudicator, label release |
| Coordinator | Campaign control, freeze seal, CAS mediation, budgets | Silent promotion of maturity |
| Adjudicator | Hidden labels, GT evaluation, release receipts | Attack-plane observation loops |

Security-grade execution requires a digest-pinned immutable worker image on a
rootless (or stronger) host with malicious probe catalogue evidence. Process-local
runs remain development-oriented and **cap** maturity.

## Evidence graph

Artifacts are JCS-style canonical JSON + SHA-256 digests (see schema registry).
Qualification uses `EvidenceResolver` → typed `EvidenceFact` records. Caller
booleans cannot promote maturity. External independence requires
`ExternalAssuranceAttestation` against a non-self trust root.

## Method surfaces

- **H/F/S** — hacker → freeze exploits → fixer → solver/regression → fresh attacker
- **Response surface** — exact coordinate cells from released bundle refs; no
  interpolation into a scalar robustness score
- **Metamorphic** — GT-invariance first; invalid transforms are not verifier failures
- **Planted calibration** — sealed instrument; `supports_unknown_robustness_claim=false`
- **EnvAssure** — `EnvironmentAssuranceRef` binds into run identity; upstream
  indeterminate propagates
- **Deployment calibration** — prospective prediction registration before outcomes;
  synthetic fixtures cannot mint `deployment_calibrated`

## Maturity

Labels: `not_implemented` … `deployment_calibrated`. Flagship study
`studies/flagship-2026/` is **`internally_verified`** with honest blockers — not
`scientifically_qualified`. See [claim-language.md](claim-language.md) and
[assurance-status.md](assurance-status.md).

## Run bundles

```text
.valab/runs/<run_id>/
  manifest.json      # tip index
  work_units/        # attack-plane results (no gt_valid)
  vault/             # commitments + sealed labels
  adjudications/     # post-freeze GT evaluations
  report/            # after release + valab report builds
```

## Import constraint

Base package must not import torch, ray, Kubernetes clients, or model SDKs
(`scripts/check_base_imports.py`). Optional adapters: [adapters.md](adapters.md).

## Related

- [Threat model](threat-model.md)
- [Methodology](methodology.md)
- [Claim language](claim-language.md)
- [Final acceptance](final-acceptance.md)
