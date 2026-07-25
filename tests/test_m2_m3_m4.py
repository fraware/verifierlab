"""Exploit, minimization, transcript, stats, repair, disclosure tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from examples.refunds.verifier import grade, refund_is_valid

from verifierlab.disclosure import DisclosureRegistry, DisclosureState
from verifierlab.exploits import build_exploit_case, propose_clusters
from verifierlab.minimization import delta_debug, minimize_exploit
from verifierlab.repairs import compare_repair
from verifierlab.statistics import power_binomial, wilson_interval
from verifierlab.transcripts import audit_transcript


def test_exploit_and_cluster() -> None:
    traj = {"steps": [{"op": "refund", "amount": 120, "user_id": "eve"}]}
    case = build_exploit_case(
        unit_id="u1",
        trajectory=traj,
        cohort="optimized",
        access_model="black-box",
    )
    clusters = propose_clusters([case, case])
    assert clusters[0]["size"] == 2


def test_delta_debug_and_minimize() -> None:
    steps = [{"op": "noop"}, {"op": "refund", "amount": 120}, {"op": "noop"}]

    def interesting(subset: list) -> bool:
        return any(s.get("amount") == 120 for s in subset)

    minimized = delta_debug(steps, interesting)
    assert any(s.get("amount") == 120 for s in minimized)
    assert len(minimized) <= len(steps)

    out = minimize_exploit(
        {"steps": steps},
        verifier=grade,
        is_valid=refund_is_valid,
    )
    assert "minimized_steps" in out


def test_transcript_audit_blocks_labels() -> None:
    report = audit_transcript({"hidden_label": "x", "verifier_invocations": []})
    assert any(f.rule_id == "TRANSCRIPT.HIDDEN_LABEL" for f in report.findings)


def test_wilson_and_power() -> None:
    iv = wilson_interval(2, 10)
    assert 0.0 <= iv.low <= iv.estimate <= iv.high <= 1.0
    p = power_binomial(p0=0.05, p1=0.2, n=50)
    assert 0.0 <= p["power"] <= 1.0


def test_compare_repair_requires_fresh_attacker() -> None:
    trajs = [
        {"steps": [{"op": "refund", "amount": 120}]},
        {"steps": [{"op": "refund", "amount": 50, "user_id": "alice", "token": "valid"}]},
    ]

    def old_v(t: dict) -> bool:
        return grade(t)

    def new_v(t: dict) -> bool:
        # Repair: reject amount > 100 always.
        for s in t.get("steps") or []:
            if s.get("op") == "refund" and int(s.get("amount", 0)) > 100:
                return False
        return True

    out = compare_repair(
        old_verifier=old_v,
        new_verifier=new_v,
        regression_trajectories=trajs,
        is_valid=refund_is_valid,
        fresh_episodes=4,
    )
    assert out["mandatory_fresh_attacker"] is True
    assert "fresh_attack" in out


def test_disclosure_registry(tmp_path: Path) -> None:
    reg = DisclosureRegistry(tmp_path / "disc")
    rec = reg.create(disclosure_id="d1", exploit_id="e1", severity="high")
    assert rec.state == DisclosureState.DRAFT
    reg.transition("d1", DisclosureState.TRIAGED)
    reg.transition("d1", DisclosureState.PUBLIC_SUMMARY, public_summary="summary")
    view = reg.public_view("d1")
    assert view["public_summary"] == "summary"
    with pytest.raises(ValueError):
        reg.transition("d1", DisclosureState.DRAFT)
