# Contributing defect reports

How to file **public verifier defects** versus **security vulnerabilities**.

## Two channels

| Kind | Where | Public? |
| ---- | ----- | ------- |
| VerifierLab product vulnerability (CAS/vault bypass, RCE, secret leak) | [SECURITY.md](https://github.com/fraware/verifierlab/blob/main/SECURITY.md) | No until coordinated |
| Public verifier robustness defect (gaming under declared budget) | `registry/verifier-defects/` + GitHub issue | Yes — public fields only |

## Public defect record

Seed format: `registry/verifier-defects/VER-YYYY-NNNN.yaml`.

Public fields include verifier ID/profile digest, versions, class, access model,
optimization method, budgets, exploit predicate summary, public outputs,
adjudicated validity, severity, disclosure state, repair/reattack pointers,
permanent regression reference, discoverer, and evidence digests.

**Do not** put exploit payloads that enable third-party harm, vault keys, or
unreleased labels in the public YAML.

## Severity and status

Severity: `critical` · `high` · `medium` · `low` · `informational`

Status: `reported` · `triaged` · `confirmed` · `disputed` ·
`repair_in_progress` · `fixed` · `reattack_pending` · `closed` · `withdrawn` ·
`embargoed`

A defect closes only when a fixed release exists, a permanent regression exists,
affected claims are updated, release notes explain impact, and (for verifier
repairs) a reattack result is recorded.

## Conflict rule

No verifier author may be the sole adjudicator of defects in that verifier.
See [governance charter](../governance/charter.md).

## Related

- [docs/disclosure.md](../disclosure.md)
- [docs/templates/disclosure.md](../templates/disclosure.md)
- [SECURITY.md](https://github.com/fraware/verifierlab/blob/main/SECURITY.md)
