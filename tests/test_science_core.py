"""Property, adjudication, bootstrap, lifecycle, and artifact round-trip tests."""



from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from verifierlab.artifacts.canonical import canonicalize, digest_of
from verifierlab.artifacts.records import AssuranceReport, TrajectoryRecord, VerifierInvocation
from verifierlab.campaigns.lifecycle import LifecycleState, assert_transition, can_transition
from verifierlab.exploits.records import ExploitCase, build_exploit_case
from verifierlab.labels.adjudication import adjudicate
from verifierlab.labels.freeze import FreezeRecord
from verifierlab.reports.metrics import AccessModelPoolError, compute_metrics
from verifierlab.security import SandboxProfile, default_reference_profile
from verifierlab.statistics import (
    cluster_bootstrap,
    kaplan_meier_survival,
    paired_bootstrap,
    robustness_curve,
    time_to_exploit,
)


@given(

    st.dictionaries(

        st.text(min_size=1, max_size=8, alphabet="abcdef"),

        st.one_of(st.integers(min_value=-100, max_value=100), st.booleans(), st.none()),

        max_size=6,

    )

)

@settings(max_examples=40, deadline=None)

def test_canonicalize_digest_stable(obj: dict) -> None:

    a = digest_of(obj)

    b = digest_of(canonicalize(obj))

    assert a == b

    assert digest_of(obj) == a





def test_artifact_round_trips() -> None:

    traj = TrajectoryRecord(trajectory_id="t1", seed=1, steps=[{"op": "noop"}])

    assert TrajectoryRecord.model_validate(traj.model_dump(mode="json")).trajectory_id == "t1"



    inv = VerifierInvocation(

        invocation_id="i1",

        trajectory_digest="a" * 64,

        decision=True,

        accepted=True,

    )

    assert VerifierInvocation.model_validate(inv.model_dump(mode="json")).accepted is True



    fr = FreezeRecord(

        freeze_id="f1",

        run_id="r1",

        campaign_digest="b" * 64,

        commitment_digests=["c" * 64],

        frozen_at=1.0,

    )

    assert FreezeRecord.model_validate(fr.model_dump(mode="json")).freeze_id == "f1"



    case = build_exploit_case(

        unit_id="u1",

        trajectory={"steps": [{"op": "refund", "amount": 120}]},

        cohort="optimized",

        access_model="black-box",

    )

    assert ExploitCase.model_validate(case.model_dump(mode="json")).exploit_id == case.exploit_id



    report = AssuranceReport(

        run_id="r1",

        run_digest="d" * 64,

        access_model="black-box",

        metrics={"overall": {"n": 1}},

        exploit_count=0,

    )

    assert AssuranceReport.model_validate(report.model_dump(mode="json")).report_version == "1"





def test_adjudication_records_role_and_dimensions() -> None:

    adj = adjudicate(

        adjudication_id="a1",

        unit_id="u1",

        role="senior_labeler",

        decision="confirm_exploit",

        dimensions={"authorization": "fail", "amount": "over_limit"},

        exploit_id="e1",

        notes="unauthorized refund",

    )

    assert adj.role == "senior_labeler"

    assert adj.dimensions["authorization"] == "fail"

    roundtrip = type(adj).model_validate(adj.model_dump(mode="json"))

    assert roundtrip.decision == "confirm_exploit"





def test_bootstrap_and_robustness() -> None:
    cb = cluster_bootstrap([[1, 0], [1, 1], [0, 0]], samples=50, seed=1)
    assert 0.0 <= cb.low <= cb.estimate <= cb.high <= 1.0
    pb = paired_bootstrap([0.2, 0.3, 0.4], [0.1, 0.25, 0.35], samples=50, seed=2)
    assert pb.method == "paired_bootstrap"
    curve = robustness_curve([0.1, 0.9, 0.5], [True, False, True], thresholds=[0.0, 0.5, 1.0])
    assert len(curve) == 3
    assert all("far" in p and "frr" in p for p in curve)
    tte = time_to_exploit([1, 2, 3], exploited=[True, False, True])
    assert tte["n_events"] == 2
    km = kaplan_meier_survival([1, 2, 3], exploited=[True, False, True])
    assert km[0]["survival"] == 1.0





def test_access_model_pool_rejected() -> None:

    rows = [

        {

            "cohort": "ordinary",

            "access_model": "black-box",

            "verifier_accepted": True,

            "gt_valid": True,

        },

        {

            "cohort": "ordinary",

            "access_model": "white-box",

            "verifier_accepted": True,

            "gt_valid": False,

        },

    ]

    with pytest.raises(AccessModelPoolError):

        compute_metrics(rows, access_model="black-box")





def test_lifecycle_transitions() -> None:

    assert can_transition(LifecycleState.ATTACK, LifecycleState.FREEZE)

    assert not can_transition(LifecycleState.DRAFT, LifecycleState.DISCLOSURE)

    assert_transition(LifecycleState.FREEZE, LifecycleState.LABEL_RELEASE)

    with pytest.raises(ValueError, match="illegal"):

        assert_transition(LifecycleState.ATTACK, LifecycleState.DISCLOSURE)





def test_sandbox_profile_declarative() -> None:

    profile = default_reference_profile()

    assert profile["network"] is False

    assert profile["worker_credentials_eq_vault"] is False

    assert profile["profile"] == SandboxProfile.LOCAL_NO_NETWORK.value

    assert profile["integration_status"] == "declarative"





def test_inference_query_accounting() -> None:

    from verifierlab.attacks import create_strategy



    s = create_strategy("best_of_n", {"seed": 3, "n": 3})

    for _ in range(3):

        action = s.propose()

        s.observe({"score": 1.0, "reward": 0.0, "verifier_accepted": False})

        assert action.get("_strategy") == "best_of_n"

    cp = s.checkpoint()

    assert cp["queries"] == 3


