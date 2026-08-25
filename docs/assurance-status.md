# Assurance maturity policy seed (not the qualification path)

**WP-00 seed.** This page records the PR #10 decision *table* only. It is **not**
the public qualification API and must not be cited as current study maturity.

Public qualification uses `EvidenceResolver` / `EvidenceFact` (WP-05) via
`valab assurance qualify` and study artifacts. Do not issue
`scientifically_qualified`, `security_grade`, or `deployment_calibrated` from
this module or from caller-supplied booleans. Current flagship status:
`internally_verified` — see `studies/flagship-2026/` and
[claim-language.md](claim-language.md).

VerifierLab maturity labels are conclusions about one exact proposition. They are not campaign options, release channels, badges, or self-declared metadata.

A maturity decision binds:

- the proposition being qualified;
- the applicability scope;
- explicit assumptions;
- the trust boundary;
- exact specification references;
- immutable evidence references;
- the predicates established from those artifacts.

The claim and evidence records are canonically serialized and digested. Changing the proposition, scope, assumptions, trust boundary, specification references, evidence references, or predicates changes the resulting qualification record.

## Levels

`not_implemented`

The proposition depends on functionality that is absent.

`implemented_unverified`

The functionality exists, but the minimum internal evidence chain is incomplete. Internal verification requires referenced immutable evidence, passing internal tests, exact budget evidence, a closed freeze-adjudicate-release lifecycle, and separation of hidden labels from the attack plane.

`internally_verified`

The internal evidence chain is complete, but independent review and independent reconstruction are absent or incomplete.

`independently_verified`

Independent review and reconstruction exist in addition to the complete internal chain. This level does not imply security-grade execution or scientific qualification.

`scientifically_qualified`

All lower-level obligations hold and the study additionally uses a security-grade execution boundary, a preregistered study, a budgeted strong attacker, a sealed hidden holdout, complete qualification estimands, and preserved negative results.

A process-local campaign cannot reach this level. Security-grade execution currently requires an isolated execution mode plus no worker network, a read-only worker root filesystem, no secret mounts, non-root workers, a separate adjudication trust domain, and hidden labels outside the attack plane.

`deployment_calibrated`

Scientific qualification exists and prospective predictions were registered before outcomes, deployment outcomes were collected, calibration analysis was completed, and the applicability regime was declared.

## Claim boundary

The current maturity module is a policy compiler. It does not inspect a run directory, validate a signature, prove isolation, verify a reviewer identity, or reconstruct evidence from raw artifacts. A caller must derive each true predicate from validated immutable evidence and include references to that evidence.

Therefore, constructing an `AssuranceEvidence` object with optimistic boolean values is not sufficient evidence for any real-world assurance claim. Integration code must fail closed when referenced artifacts are absent, inconsistent, mutable, unverifiable, or outside the declared trust boundary.

The intended end state is that campaign, lifecycle, execution, adjudication, statistical, review, and prospective-calibration artifacts are validated first and then compiled into these predicates. Until those derivations are implemented, the maturity module establishes the claim language and decision policy without elevating existing campaign outputs.

## Non-equivalence of levels

The levels are cumulative but they represent different epistemic obligations. A large attack campaign does not substitute for an immutable evidence chain. Independent review does not substitute for hidden-label isolation. Security isolation does not substitute for preregistration or complete estimands. A successful retrospective study does not substitute for prospective deployment calibration.

No aggregate score may average away a missing mandatory obligation. Missing mandatory evidence is a blocker, not a partial success.
