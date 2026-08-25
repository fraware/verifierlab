# Final acceptance (Gate G7 / WP-22)

Machine-checkable acceptance for the `integration/final-assurance` line.
Package remains **`0.2.0rc2`**. Passing these gates means the **repository /
software programme** is G7-ready in-tree — not that scientific or deployment
maturity labels have been earned.

Executable suite: `tests/test_final_acceptance_gates.py`.

## Gates A–J

| Gate | Name | In-repo check |
| ---- | ---- | ------------- |
| A | Integration presence | Assurance, campaigns, execution, statistics, exploits modules import; flagship study bundle exists |
| B | Artifact schemas | Schema registry present; canonical digests; bundle verify path |
| C | Security fail-closed | Worker prune + probes modules; secure launcher refuses unsuitable hosts; worker secret scan |
| D | Methods modules | H/F/S, response surface, metamorphic, planted calibration, failure layers present |
| E | Quality hooks | Coverage partitions, property tests, fuzz corpus, claim-language lint |
| F | Adapter matrix honesty | Status vocabulary + EnvAssure fixture-only + contract version |
| G | Release workflow | Signed annotated tag gate; no unsigned fallback; provenance/SBOM/manifest steps |
| H | Docs + claim language | Architecture/claim-language/protection policy; README honest maturity |
| I | Scientific evidence refs | Flagship maturity `internally_verified` with derived blockers; not inflated |
| J | Deployment capability | Prediction/outcome/report APIs present; synthetic cannot mint calibrated |

## No-go regressions (NG-01…NG-15)

Encoded as tests in the same suite (fail closed):

| ID | Rule |
| -- | ---- |
| NG-01 | Local/process execution must not satisfy `security_grade_execution` / scientific qualification alone |
| NG-02 | Worker image tree must not ship GT/vault/adjudicator modules |
| NG-03 | Numeric scores do not imply accept without `ScoreDecisionMapping` |
| NG-04 | Validation PR merge prohibition recorded in integration ledger |
| NG-05 | Caller booleans cannot promote maturity (EvidenceResolver path) |
| NG-06 | Planted calibration hard-codes `supports_unknown_robustness_claim=false` |
| NG-07 | Response surface must not expose scalar robustness aggregation APIs |
| NG-08 | Fixture-only adapters never labeled `live-tested` |
| NG-09 | Migrations cannot upgrade maturity fields |
| NG-10 | EnvAssure indeterminate must be able to propagate (ref binding present) |
| NG-11 | Deployment synthetic fixtures marked non-deployment |
| NG-12 | External attestation rejects self-issued / mismatched subjects |
| NG-13 | Windows is not release-qualified in support matrix |
| NG-14 | Package version remains pre-stable (`0.2.0rc2`) until maintainer release |
| NG-15 | Claim-language lint clean on README/docs |

## G7 readiness statement (software)

**In-repo G7 software/acceptance hooks: READY** on this branch when
`tests/test_final_acceptance_gates.py` is green.

Still **not** claimed:

- `scientifically_qualified`
- `security_grade` (needs rootless/separate-domain runner evidence)
- `deployment_calibrated` (needs real prospective outcomes)
- Protected `main` enabled in GitHub (admin)
- Independent verification (external trust root + clean-room)

## External blockers (engineers / admins)

1. Enable GitHub branch protection per [repository-protection-policy.md](repository-protection-policy.md).
2. Provide rootless (or stronger) runner for live malicious probes.
3. Configure external attestation trust roots; run independent reconstruction.
4. Collect real field deployment outcomes (no backfill).
5. Maintainer-signed annotated tag + trusted PyPI publish when cutting a stable release (not from agent automation).

## Related

- [final-integration-ledger.md](final-integration-ledger.md)
- [claim-language.md](claim-language.md)
- [support-matrix.md](support-matrix.md)
