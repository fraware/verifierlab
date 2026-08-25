# Claim language (WP-20)

Approved phrasing for VerifierLab docs, READMEs, reports, and study bundles.
Package version remains `0.2.0rc2` on `integration/final-assurance`.

## Maturity labels (artifact-derived only)

Use only labels produced by `EvidenceResolver` / study artifacts:

| Label | When allowed |
| ----- | ------------ |
| `not_implemented` | Capability absent |
| `internally_verified` | Local evidence reconstructed; blockers may remain |
| `independently_verified` | External attestation against a non-self trust root |
| `scientifically_qualified` | Cumulative scientific gates all derived true |
| `security_grade` | Rootless/separate-domain probes + sealed boundary evidence |
| `deployment_calibrated` | Prospective predictions + real later outcomes |

Do **not** self-issue `independently_verified`, `scientifically_qualified`,
`security_grade`, or `deployment_calibrated` from fixture or process-local runs.

## Approved phrasing

- "Evidence under the stated budget, access model, and execution boundary."
- "No exploit recovered is failure to find — not a proof of soundness."
- "Flagship study maturity is `internally_verified` with machine-derived blockers."
- "EnvAssure remains fixture-only until the package is installable."
- "Windows is best-effort CI smoke, not release-qualified."
- "Stable software release ≠ scientific or deployment maturity."

## Banned overclaims (outside quoted non-claims / this file)

The claim-language lint fails if these appear as bare claims in docs/README:

- "proven robust" / "proof of robustness"
- "sound verifier" / "soundness guaranteed"
- "SOTA" / "state of the art" as a product claim
- "scientifically_qualified" as a current tree status without derived artifacts
- "security_grade=true" / "security grade achieved" without rootless evidence
- "deployment_calibrated" without prospective outcomes
- "production ready" / "fully secure"
- labeling fixture-only adapters as "live-tested"

Quoted examples of *what not to say*, code identifiers, and this policy file are
exempt when clearly marked.

## Flagship study (current)

`studies/flagship-2026/` reports maturity **`internally_verified`**. Honest
blockers include missing independent review/reconstruction and
`security_grade_execution` on unsuitable hosts. Do not inflate to
`scientifically_qualified` in README or marketing copy.

## Lint

```bash
python scripts/check_claim_language.py
pytest tests/test_claim_language_wp20.py -q
```
