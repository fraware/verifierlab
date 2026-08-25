# Threat model

Status: research draft aligned to the `integration/final-assurance` tree
(`0.2.0rc2`). Non-claims: [limitations.md](limitations.md),
[claim-language.md](claim-language.md).

## Assets

- Campaign specifications, verifier profiles, and pinned versions
- Content-addressed run/study bundles and digests
- Ground-truth / label vault commitments (adjudicator plane only pre-release)
- Budget and provenance ledgers; attacker-state envelopes
- Execution-boundary manifests and isolation probe reports
- EnvAssure refs, assurance chain manifests, deployment prediction registrations
- Assurance reports and external attestation interfaces

## Trust boundaries

| Boundary | Assumption |
| -------- | ---------- |
| Operator host | Trusted to hold store/vault; untrusted as security-grade evidence if rootful-only |
| Worker processes / containers | Untrusted relative to vault; no GT; pruned coordinator modules |
| Attack strategies | Observe public verifier channel only |
| Coordinator | Mediates CAS/freeze; must not silently promote maturity |
| Adjudicator | Sole GT enrichment path; emits `LabelReleaseReceipt` |
| Optional remotes | Slurm/K8s/S3 behind extras; credentials out of default dry-run scope |

## Adversary capabilities (campaign target)

Explicit access models (black/gray/white/adaptive/transfer/…). Metrics must not
pool across access classes without stratification. Persistent vs fresh attack
state is first-class; inherited state after repair is a qualification blocker.

## Mitigations in this tree

- Canonical JSON + SHA-256 CAS; schema registry with fail-closed unknown versions
- Worker image physical pruning + malicious probe catalogue (security-grade path)
- `public_attack_feedback` strips GT fields; hidden-split side-channel tests
- Budget ledger with vouchers; freeze injection rejected
- EvidenceResolver maturity; planted calibration hard-codes non-robustness boundary
- Adapter contract + honest matrix statuses; base import gate without heavy SDKs
- Claim-language lint against banned overclaims

## Non-goals

- Soundness guarantees from “no exploit found”
- Self-issued `independently_verified` / `scientifically_qualified` /
  `security_grade` / `deployment_calibrated`
- Treating Windows soft-fail CI as release-qualified support
- Averaging response surfaces into a scalar robustness score

## Open items (external)

- Rootless/separate-domain runner for live security-grade probes
- External trust root for independent attestation
- Admin enablement of protected `main` required checks
- Real field outcomes for deployment calibration

## Reporting product vulnerabilities

See [SECURITY.md](https://github.com/fraware/verifierlab/blob/main/SECURITY.md).
