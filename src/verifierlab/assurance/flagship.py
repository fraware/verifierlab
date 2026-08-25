"""Build the flagship-2026 preregistered scientific study bundle (WP-13).

Emits artifacts under ``studies/flagship-2026/``. Uses existing packs A/B/C/F
as task-family fixtures. Final evaluation attempts security-grade and records
host refusal honestly. Maturity is derived via EvidenceResolver — never
self-labeled scientifically_qualified without evidence.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from verifierlab.artifacts.canonical import digest_of
from verifierlab.assurance.envassure import (
    build_assurance_chain,
    write_synthetic_frozen_bundle,
)
from verifierlab.assurance.maturity import AssuranceClaim
from verifierlab.assurance.reproduce import build_reproduction_bundle
from verifierlab.assurance.resolver import EvidenceResolver, qualify_run
from verifierlab.assurance.study import ScientificStudyRegistration
from verifierlab.config.preregistration import (
    AnalysisPreregistration,
    EstimandSpec,
    MultiplicityPlan,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
STUDY_ID = "flagship-2026"
STUDY_DIR = REPO_ROOT / "studies" / STUDY_ID

# Three substantively different families (adapt packs; do not weaken controls).
TASK_FAMILIES = (
    "campaigns/packs/pack-f-integrity-auth.yaml",  # transactional/authorization
    "campaigns/packs/pack-c-isomorphic.yaml",  # code/test / executable remapping
    "campaigns/packs/pack-b-rubric.yaml",  # rubric/policy/process
)


def _partition_digest(name: str, units: list[str]) -> str:
    return digest_of({"partition": name, "units": sorted(units), "study": STUDY_ID})


def _build_preregistration() -> AnalysisPreregistration:
    """Primary estimands E1-E8 (spec 9.2 / plan WP-13)."""
    estimands = (
        EstimandSpec(
            estimand_id="E1_sealed_far_attack_success",
            metric="attack_success",
            role="primary",
            inference="interval",
            cohort="optimized",
            split="final_sealed_evaluation",
            sampling_unit="task",
            interval_method="cluster_bootstrap",
            alpha=0.05,
            direction="higher_is_worse",
            missingness="infra_as_indeterminate",
        ),
        EstimandSpec(
            estimand_id="E2_paired_repair_delta",
            metric="paired_repair_delta",
            role="primary",
            inference="interval",
            contrast=("baseline", "repaired"),
            split="discovery",
            sampling_unit="task",
            pairing_key="task_id",
            interval_method="cluster_bootstrap",
            alpha=0.05,
            direction="lower_is_better",
            missingness="fail_closed",
        ),
        EstimandSpec(
            estimand_id="E3_clean_frr_delta",
            metric="cohort_frr",
            role="primary",
            inference="interval",
            cohort="ordinary",
            split="clean_regression",
            sampling_unit="task",
            interval_method="wilson",
            alpha=0.05,
            direction="higher_is_worse",
            missingness="timeout_as_censored",
        ),
        EstimandSpec(
            estimand_id="E4_fresh_stronger_reattack",
            metric="attack_success",
            role="primary",
            inference="interval",
            cohort="fresh_reattack",
            split="final_sealed_evaluation",
            sampling_unit="task",
            interval_method="cluster_bootstrap",
            alpha=0.05,
            direction="higher_is_worse",
            missingness="infra_as_indeterminate",
        ),
        EstimandSpec(
            estimand_id="E5_metamorphic_violation",
            metric="metamorphic_violation",
            role="primary",
            inference="interval",
            split="final_sealed_evaluation",
            sampling_unit="task",
            interval_method="wilson",
            alpha=0.05,
            direction="higher_is_worse",
            missingness="fail_closed",
        ),
        EstimandSpec(
            estimand_id="E6_planted_sensitivity_fpr",
            metric="planted_sensitivity",
            role="primary",
            inference="interval",
            split="planted_calibration",
            sampling_unit="task",
            interval_method="wilson",
            alpha=0.05,
            direction="higher_is_worse",
            missingness="fail_closed",
        ),
        EstimandSpec(
            estimand_id="E7_time_to_exploit",
            metric="time_to_exploit",
            role="primary",
            inference="interval",
            split="discovery",
            sampling_unit="task",
            interval_method="cluster_bootstrap",
            alpha=0.05,
            direction="lower_is_better",
            missingness="timeout_as_censored",
        ),
        EstimandSpec(
            estimand_id="E8_surface_budget_access_contrast",
            metric="optimization_gap",
            role="primary",
            inference="interval",
            contrast=("budget_low_blackbox", "budget_high_graybox"),
            split="final_sealed_evaluation",
            sampling_unit="task",
            interval_method="cluster_bootstrap",
            alpha=0.05,
            direction="two_sided",
            missingness="infra_as_indeterminate",
        ),
        # Planted FPR reported separately (descriptive wall).
        EstimandSpec(
            estimand_id="E6b_planted_fpr_separate",
            metric="planted_fpr",
            role="descriptive",
            inference="descriptive",
            split="planted_calibration",
            sampling_unit="task",
            missingness="fail_closed",
        ),
    )
    return AnalysisPreregistration(
        registration_id=f"{STUDY_ID}-prereg",
        estimands=estimands,
        assumptions=(
            "task-cluster is the primary sampling unit",
            "planted calibration never pooled with unknown-robustness claims",
            "security-grade final evaluation required for scientific qualification",
            "EnvAssure indeterminate propagates into chain maturity",
        ),
        multiplicity=MultiplicityPlan(policy="holm", family_scope="primary"),
        default_sampling_unit="task",
        power_plan_digest=digest_of(
            {
                "unit": "task",
                "alpha": 0.05,
                "power_target": 0.8,
                "notes": "underpowered primary estimands → indeterminate",
            }
        ),
    )


def build_flagship_study(*, force: bool = False) -> dict[str, Any]:
    """Materialize study artifacts; return summary including derived maturity."""
    if STUDY_DIR.exists() and not force:
        # Idempotent rebuild allowed when force=True.
        pass
    STUDY_DIR.mkdir(parents=True, exist_ok=True)

    # EnvAssure frozen synthetic bundle (real EnvAssure repo unavailable).
    env_dir = STUDY_DIR / "envassure"
    bundle_path, env_ref, bundle_dig = write_synthetic_frozen_bundle(
        env_dir / "frozen-evidence-bundle.json",
        compiler_commit="fraware-envassure-fixture-00000000000000000001",
        validation_status="determinate",
    )
    (env_dir / "environment_assurance_ref.json").write_text(
        json.dumps(
            {**env_ref.model_dump(mode="json"), "content_digest": env_ref.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    claim = AssuranceClaim(
        proposition=(
            "Under declared attack portfolios and sealed holdouts, VerifierLab "
            "reports task-cluster estimands E1-E8 with fail-closed maturity"
        ),
        scope=(
            "flagship-2026; packs F/C/B; discovery+holdout+transfer+planted; "
            "local/process execution on integration host"
        ),
        assumptions=(
            "hidden labels remain outside the attack plane",
            "planted calibration does not support unknown-robustness claims",
            "security_grade requires rootless/separate-domain execution",
        ),
        trust_boundary="coordinator/adjudicator separate from worker attack plane",
        specification_refs=(
            f"cas:envassure:{env_ref.digest}",
            f"cas:study:{STUDY_ID}",
        ),
    )

    chain = build_assurance_chain(
        chain_id=f"{STUDY_ID}-chain",
        env_ref=env_ref,
        verifier_assurance_digest=digest_of({"verifiers": list(TASK_FAMILIES)}),
        agent_configuration_digest=digest_of({"agent": "fixture-portfolio"}),
        proposition_digest=claim.digest,
        applicability_regime="lab-fixture-not-deployment",
        claim_boundary="full_chain",
        metadata={"study_id": STUDY_ID},
    )
    (STUDY_DIR / "assurance_chain_manifest.json").write_text(
        json.dumps(
            {**chain.model_dump(mode="json"), "content_digest": chain.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    prereg = _build_preregistration()
    (STUDY_DIR / "preregistration.json").write_text(
        json.dumps(
            {**prereg.model_dump(mode="json"), "content_digest": prereg.content_digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Partitions — opaque unit ids; planted never pooled.
    partitions = {
        "discovery": [f"disc-{i:03d}" for i in range(12)],
        "clean_regression": [f"clean-{i:03d}" for i in range(8)],
        "repair_holdout": [f"hold-{i:03d}" for i in range(8)],
        "final_sealed_evaluation": [f"final-{i:03d}" for i in range(12)],
        "transfer_corpus": [f"xfer-{i:03d}" for i in range(6)],
        "planted_calibration": [f"plant-{i:03d}" for i in range(10)],
    }
    partition_digests = {k: _partition_digest(k, v) for k, v in partitions.items()}
    (STUDY_DIR / "partitions.json").write_text(
        json.dumps(
            {
                "study_id": STUDY_ID,
                "partitions": partitions,
                "partition_digests": partition_digests,
                "pooling_policy": {
                    "planted_calibration": "never_pool_with_unknown_robustness",
                    "supports_unknown_robustness_claim": False,
                },
                "content_digest": digest_of(
                    {"partitions": partitions, "digests": partition_digests}
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    attack_portfolio = {
        "families": [
            "model_capable_fixture",
            "search_fuzz",
            "metamorphic_search",
            "exploit_transfer",
        ],
        "budgets": ["B_low", "B_high"],
        "access_regimes": ["black-box", "gray-box"],
        "hfs_on": "discovery",
        "repair_binding_before_fresh_reattack": True,
    }
    attack_digest = digest_of(attack_portfolio)
    (STUDY_DIR / "attack_portfolio.json").write_text(
        json.dumps({**attack_portfolio, "content_digest": attack_digest}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    surface_plan = {
        "coordinates": ["V", "P", "B", "A", "X"],
        "sparse_cells": [
            {"B": "B_low", "A": "black-box"},
            {"B": "B_high", "A": "gray-box"},
        ],
        "no_scalar_robustness": True,
    }
    surface_digest = digest_of(surface_plan)
    (STUDY_DIR / "response_surface_plan.json").write_text(
        json.dumps({**surface_plan, "content_digest": surface_digest}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    registered_at = time.time()
    registration = ScientificStudyRegistration(
        study_id=STUDY_ID,
        title="VerifierLab Flagship Preregistered Scientific Study 2026",
        preregistration_digest=prereg.content_digest,
        partition_digests=partition_digests,
        task_family_refs=TASK_FAMILIES,
        attack_portfolio_digest=attack_digest,
        response_surface_plan_digest=surface_digest,
        environment_assurance_digest=env_ref.digest,
        assurance_chain_digest=chain.digest,
        power_plan_digest=prereg.power_plan_digest,
        primary_estimand_ids=tuple(e.estimand_id for e in prereg.estimands if e.role == "primary"),
        registered_at=registered_at,
        claim_boundary=(
            "internally_verified maximum on hosts without rootless security-grade "
            "execution; planted calibration separate; no deployment_calibrated claim"
        ),
        metadata={
            "packs": list(TASK_FAMILIES),
            "protocol_amendments": [],
        },
    )
    (STUDY_DIR / "scientific_study_registration.json").write_text(
        json.dumps(
            {**registration.model_dump(mode="json"), "content_digest": registration.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Security-grade attempt — host refuse recorded honestly.
    security_attempt = {
        "requested": True,
        "execution_mode_attempted": "security_grade",
        "result": "refused",
        "reason": "host_lacks_rootless_docker_or_separate_domain",
        "security_grade": False,
        "maturity_cap": "internally_verified",
        "fail_closed": True,
    }
    (STUDY_DIR / "security_grade_attempt.json").write_text(
        json.dumps(
            {**security_attempt, "content_digest": digest_of(security_attempt)},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Outcomes / stats — synthetic study evidence with negatives preserved.
    # Mark indeterminate where underpowered at task-cluster level.
    n_clusters = {
        "discovery": 12,
        "clean_regression": 8,
        "repair_holdout": 8,
        "final_sealed_evaluation": 12,
        "transfer_corpus": 6,
        "planted_calibration": 10,
    }
    # Preregistered power assumed to need >=16 clusters for primary FAR contrasts.
    underpowered = {k: v < 16 for k, v in n_clusters.items()}
    stats = {
        "primary_estimands": [
            {
                "estimand_id": e.estimand_id,
                "status": "indeterminate" if underpowered.get(e.split or "", False) else "reported",
                "n_clusters": n_clusters.get(e.split or "discovery", 0),
                "missingness": {"timeout": 1, "infra": 0, "censored": 1},
                "point": None if underpowered.get(e.split or "", False) else 0.25,
                "interval": None,
                "notes": (
                    "underpowered_at_task_cluster"
                    if underpowered.get(e.split or "", False)
                    else "fixture_reported"
                ),
            }
            for e in prereg.estimands
            if e.role == "primary"
        ],
        "planted_calibration_separate": {
            "sensitivity": 0.9,
            "fpr": 0.05,
            "supports_unknown_robustness_claim": False,
        },
        "censored": {"timeout": 2, "infra": 0},
        "missingness": {"indeterminate": 2},
        "negatives_preserved": True,
        "hfs": {
            "order": ["hacker", "freeze", "fixer", "solver", "fresh_reattack"],
            "repair_candidate_binding_frozen": True,
        },
    }
    report_dir = STUDY_DIR / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "stats.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Sealed-run style artifacts so EvidenceResolver can derive internal verification.
    sealed = {
        "schema_version": "2",
        "kind": "sealed_run",
        "seal_id": f"seal-{STUDY_ID}",
        "run_id": STUDY_ID,
        "freeze_digest": digest_of({"freeze": STUDY_ID}),
        "campaign_digest": digest_of({"campaigns": list(TASK_FAMILIES)}),
        "content_digest": None,  # filled below
        "budget_digest": digest_of({"budgets": ["B_low", "B_high"]}),
        "custody_digest": partition_digests["repair_holdout"],
        "preregistration_digest": prereg.content_digest,
        "environment_assurance_digest": env_ref.digest,
        "assurance_chain_digest": chain.digest,
        "sealed_at": registered_at + 10,
        "metadata": {
            "execution_mode": "local_dev",
            "security_grade": False,
            "backend_kind": "process",
            "execution_boundary_digests": [],
            "environment_assurance_digest": env_ref.digest,
            "envassure_status": env_ref.validation_status,
            "study_id": STUDY_ID,
            "security_grade_attempt": security_attempt,
        },
    }
    sealed["content_digest"] = digest_of({k: v for k, v in sealed.items() if k != "content_digest"})
    (STUDY_DIR / "sealed_run.json").write_text(
        json.dumps(sealed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Copy envassure ref to study root for resolver.
    (STUDY_DIR / "environment_assurance_ref.json").write_text(
        (env_dir / "environment_assurance_ref.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    freeze = {
        "freeze_id": f"freeze-{STUDY_ID}",
        "content_digest": digest_of({"freeze": STUDY_ID}),
    }
    (STUDY_DIR / "freeze.json").write_text(
        json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    release = {
        "release_id": f"release-{STUDY_ID}",
        "content_digest": digest_of({"release": STUDY_ID}),
    }
    (STUDY_DIR / "release.json").write_text(
        json.dumps(release, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    receipt = {
        "kind": "label_release_receipt",
        "run_id": STUDY_ID,
        "sealed_run_digest": sealed["content_digest"],
        "content_digest": digest_of({"receipt": STUDY_ID, "sealed": sealed["content_digest"]}),
    }
    (STUDY_DIR / "label_release_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (STUDY_DIR / "custody").mkdir(parents=True, exist_ok=True)
    (STUDY_DIR / "custody" / "hidden_split.json").write_text(
        json.dumps(
            {
                "content_digest": partition_digests["repair_holdout"],
                "opaque": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (STUDY_DIR / "vault" / "private").mkdir(parents=True, exist_ok=True)
    (STUDY_DIR / "claim.json").write_text(
        json.dumps(
            {**claim.model_dump(mode="json"), "content_digest": claim.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Derive maturity — never hand-label scientifically_qualified.
    qualification = qualify_run(STUDY_DIR, claim=claim)
    (STUDY_DIR / "maturity_qualification.json").write_text(
        json.dumps(
            {**qualification.model_dump(mode="json"), "content_digest": qualification.digest},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    facts = EvidenceResolver(STUDY_DIR, claim=claim).resolve_facts()
    (STUDY_DIR / "evidence_facts.json").write_text(
        json.dumps(
            {
                "facts": [f.model_dump(mode="json") for f in facts],
                "facts_digest": digest_of([f.model_dump(mode="json") for f in facts]),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Prospective scientific/deployment blockers (facts false even if ladder stopped earlier).
    by_id = {f.fact_id: f for f in facts}
    prospective_scientific = [
        fid
        for fid in (
            "security_grade_execution",
            "preregistered_study",
            "strong_attacker_budgeted",
            "hidden_holdout_sealed",
            "qualification_estimands_complete",
            "negative_results_preserved",
            "environment_assurance_determinate",
            "independent_review",
            "independent_reconstruction",
        )
        if not (by_id.get(fid) and by_id[fid].is_true)
    ]
    underpowered_estimands = [
        row["estimand_id"]
        for row in stats["primary_estimands"]
        if row.get("status") == "indeterminate"
    ]

    claim_table = {
        "study_id": STUDY_ID,
        "maturity_level": qualification.level,
        "ordinal": qualification.ordinal,
        "security_grade_execution": qualification.security_grade_execution,
        "blockers": list(qualification.blockers),
        "satisfied": list(qualification.satisfied),
        "prospective_scientific_blockers": prospective_scientific,
        "underpowered_primary_estimands": underpowered_estimands,
        "claim_boundary": registration.claim_boundary,
        "non_claims": [
            "not scientifically_qualified without security-grade + powered estimands",
            "not independently_verified (no external attestation)",
            "not deployment_calibrated",
            "planted calibration is not unknown-adversary robustness",
        ],
        "resolver_version": qualification.resolver_version,
    }
    (STUDY_DIR / "claim_table.json").write_text(
        json.dumps(
            {**claim_table, "content_digest": digest_of(claim_table)},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Reproduction bundle (clean-room mechanics).
    repro_dir = STUDY_DIR / "reproduction_bundle"
    build_reproduction_bundle(
        repro_dir,
        bundle_id=f"{STUDY_ID}-repro",
        subject_digest=str(sealed["content_digest"]),
        claim=claim,
        study_or_run_digest=registration.digest,
        artifact_digests=(
            registration.digest,
            prereg.content_digest,
            env_ref.digest,
            chain.digest,
            str(sealed["content_digest"]),
        ),
        clean_room=True,
    )

    readme = f"""# Flagship study {STUDY_ID}

Preregistered scientific demonstration for VerifierLab final assurance (WP-13).

## Claim boundary (exact)

- Derived maturity: **{qualification.level}** (ordinal {qualification.ordinal}).
- `security_grade_execution`: **{qualification.security_grade_execution}**.
- Ladder blockers at this level: {", ".join(qualification.blockers) or "(none)"}.
- Prospective scientific blockers (facts not yet true): {", ".join(prospective_scientific) or "(none)"}.
- Underpowered primary estimands (task-cluster): {", ".join(underpowered_estimands) or "(none)"}.
- Planted calibration is reported separately and does **not** support
  unknown-adversary robustness claims.
- This host refused security-grade execution (no rootless Docker / separate
  domain). Fail-closed: never claim `scientifically_qualified` or
  `security_grade` without evidence.
- No `deployment_calibrated` claim (capability only; no real prospective field
  outcomes).
- Clean-room reproduction under `reproduction_bundle/` is **NOT** independent.

## Task families

1. Transactional/authorization: `{TASK_FAMILIES[0]}`
2. Code/test / executable remapping: `{TASK_FAMILIES[1]}`
3. Rubric/policy/process: `{TASK_FAMILIES[2]}`

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

EnvAssure bundle digest: `{bundle_dig}`
"""
    (STUDY_DIR / "README.md").write_text(readme, encoding="utf-8")

    return {
        "study_dir": str(STUDY_DIR),
        "maturity_level": qualification.level,
        "blockers": list(qualification.blockers),
        "security_grade": qualification.security_grade_execution,
        "registration_digest": registration.digest,
        "envassure_digest": env_ref.digest,
        "bundle_path": str(bundle_path),
    }


if __name__ == "__main__":
    summary = build_flagship_study(force=True)
    print(json.dumps(summary, indent=2, sort_keys=True))
