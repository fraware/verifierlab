# Threat model

Status: **research draft** (`0.2.0rc2` release-candidate surfaces). See also
[limitations.md](limitations.md) for honest non-claims on adapters and launchers.

## Assets

- Campaign specifications and pinned verifier versions
- Content-addressed run bundles and digests
- Ground-truth / label vault commitments (not released to workers pre-freeze)
- Budget and provenance ledgers
- Assurance reports rebuilt from immutable artifacts

## Trust boundaries

| Boundary | Assumption |
| -------- | ---------- |
| Operator host | Trusted to run local campaigns and hold the store / vault |
| Worker processes | Untrusted relative to the label vault; must not receive hidden labels or `gt_valid` |
| Attack strategies | Observe **public verifier channel only** |
| Public verifier channel | Distinct from ground-truth channel |
| Optional remote launchers | Untrusted networks; live behind `[slurm]` / `[kubernetes]` when binaries/client exist — treat credentials as out of scope for default dry-run |

## Adversary capabilities (campaign target)

Attack strategies model adversaries with an explicit **access model**
(black-box, gray-box, white-box, adaptive, transfer, side-channel). Metrics must
not be pooled across access classes without stratification.

## Mitigations in this tree

- Local filesystem CAS with SHA-256 digests over canonical JSON
- Coordinator-only GT enrichment after worker episodes
- `public_attack_feedback` strips ground-truth fields before `observe`
- Label vault freeze / release with access audit log
- Budget ledger with stop-or-record overrun policy
- Secret scanning before report emit
- Adversarial self-tests in `tests/test_integrity.py`
- Base install free of heavy ML / cluster SDKs
- Failed work units persisted for visibility

## Non-goals

- Soundness guarantees from “no exploit found”
- Automatic public vulnerability disclosure
- Storing partner raw data in a public service
- Over-claiming Harbor sandbox orchestration or NeMo training loops beyond the
  shipped adapters (see [limitations.md](limitations.md))

## Open items

- Full sandbox profiles for untrusted verifier code
- Credential isolation hardening for live Slurm/K8s/S3 paths
- Optional SciPy-backed exact intervals

## Reporting product vulnerabilities

See [SECURITY.md](https://github.com/fraware/verifierlab/blob/main/SECURITY.md).
