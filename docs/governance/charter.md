# Benchmark governance charter (draft)

**Status:** draft for VerifierLab public RC / shared EnvAssure–VerifierLab
beta governance. Not a funding or grant-administration charter.

**Applies to:** benchmark packs, primary estimands, hidden-label custody,
public defect adjudication for pack-listed verifiers, and plugin review status
appeals that affect published claims.

## 1. Purpose

Improve evidence quality and external challenge without weakening trust
boundaries. Primary results remain **stratified** by verifier, environment,
access model, attack, budget, split, and pack version. A universal aggregate
verifier leaderboard is **out of scope** for beta.

## 2. Benchmark Council (intended composition)

- Two core maintainers
- Two external researchers
- One domain expert
- One security or reproducibility specialist

Major changes require approval from at least one external member and one domain
or security member. Until seats are filled, maintainers publish interim
decisions under this charter and mark them `interim`.

Members disclose authorship, employment, funding, submissions, and competitive
interests ([conflicts](#7-conflicts-of-interest)).

## 3. External review

The council may require domain, security, statistics, external pilot, or
red-team review before accepting a benchmark change. Plugin `reference` status
requires both conformance and security review.

## 4. Hidden-label custody

- Name at least two custodians.
- Separate custodians from attack developers.
- Encrypt hidden assets; log access; rotate credentials after releases.
- Commit hidden assets before evaluation windows open.
- Release labels only through freeze → adjudicate → release-labels.
- Investigate anomalous performance for contamination; invalidate compromised
  pack versions.

Workers and public pack trees must never contain hidden labels.

## 5. Attack / adjudication separation

- Attack-plane code and fixtures must not import ground-truth providers or vault
  clients.
- No verifier author may be the **sole adjudicator** of defects in that verifier.
- Adjudicator plugins are never loaded into worker trust boundaries.

## 6. Versioning

| Bump | Triggers |
| ---- | -------- |
| **Major** | Construct, hidden reference, ground truth, primary metric, access model, or split semantics change |
| **Minor** | Compatible task/attack/probe/baseline/metadata addition |
| **Patch** | Docs, checksum repair, packaging correction, repair restoring documented intent |

Every published result records exact pack, core, adapter, profile, split,
StatsPlan, and (when used) container digests.

## 7. Conflicts of interest

Disclose and, when material, recuse from votes on packs, defects, or plugins
you authored or are paid to evaluate. Publish recusals with decisions.

## 8. Contamination

Treat unexplained holdout performance, label leakage, or shared hidden-asset
access as contamination suspects. Emergency handling may proceed privately for
security, then publish a post-embargo record and invalidate affected results.

## 9. Estimands

Packs declare a primary estimand and interval method in advance. Post-hoc metric
substitution on a frozen pack version is a major change (new version), not a
silent edit.

## 10. Appeals

Appeals may cover defect classification, adjudication, exclusion, result,
contamination finding, or plugin review status. Require new evidence. The
original reviewer cannot be the sole appeal reviewer. Publish non-security
appeals and outcomes.

## 11. Repair and reattack

Verifier repairs that close public defects require a recorded reattack result
before the defect status may move to `closed`. Environment semantic repairs
require replay or differential evidence.

## 12. Deprecation

Deprecated packs remain citeable by digest but must not be presented as current
primary evidence. `revoked` plugin status supersedes prior review levels.

## 13. Disclosure

- Product vulnerabilities: [SECURITY.md](https://github.com/fraware/verifierlab/blob/main/SECURITY.md)
- Public verifier defects: [docs/contributing/defects.md](../contributing/defects.md)
- Embargoed material stays out of public registries until disclosure state
  allows

## 14. Minutes and transparency artifacts

Intended tree:

```text
docs/governance/charter.md          # this document
docs/governance/council.md          # seats (TBA)
docs/governance/conflicts.md        # disclosure log (TBA)
docs/governance/decisions/          # recorded decisions
docs/governance/meeting-minutes/    # within ten business days
docs/governance/benchmark-changes/  # proposals and outcomes
docs/governance/appeals/            # non-security appeals
```

## 15. Explicit non-goals (this draft)

- Operating independent reproduction **grants** (funding, selection, payment)
- Claiming verifier soundness or leaderboard-style superiority from pack results
- Automatic installation or execution of registry plugins

## Related

- [ROADMAP.md](https://github.com/fraware/verifierlab/blob/main/ROADMAP.md)
- [docs/contributing/benchmark-packs.md](../contributing/benchmark-packs.md)
- [docs/methodology.md](../methodology.md)
- Shared community vocabulary: review statuses in `schemas/plugin-registry-v1.schema.json`
