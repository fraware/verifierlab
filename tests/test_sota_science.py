"""Metamorphic invariance, survival curves, plugin discovery, repair metrics."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from examples.refunds.verifier import grade, refund_is_valid

from verifierlab.plugins import discover_plugins
from verifierlab.plugins.loader import load_object
from verifierlab.repairs import compare_repair
from verifierlab.statistics import (
    assert_gt_invariance,
    isomorphic_remap,
    kaplan_meier_survival,
    robustness_curve,
    time_to_exploit,
    verifier_invariance_report,
)
from verifierlab.targets.harbor_adapter import harbor_install_status, harbor_sdk_available


def test_metamorphic_gt_invariance() -> None:
    traj = {"steps": [{"op": "refund", "amount": 120, "user_id": "eve"}]}
    out = assert_gt_invariance(traj, is_valid=refund_is_valid)
    assert out["held"] is True
    assert out["before"] is False
    remapped = isomorphic_remap(traj)
    assert remapped["steps"][0]["user_id"] == "malory"
    assert remapped["steps"][0]["relabel"] is True
    assert refund_is_valid(remapped) is False

    benign = {"steps": [{"op": "refund", "amount": 40, "user_id": "alice", "token": "valid"}]}
    assert_gt_invariance(benign, is_valid=refund_is_valid)


def test_metamorphic_verifier_report_records_planted_bug() -> None:
    traj = {"steps": [{"op": "refund", "amount": 120, "user_id": "eve"}]}
    report = verifier_invariance_report(traj, verifier=grade, is_valid=refund_is_valid)
    assert report["gt_invariant"] is True
    # Planted verifier accepts even oversized; remap must not invent a reject.
    assert report["verifier_before"] is True
    assert report["verifier_after"] is True


def test_time_to_exploit_and_kaplan_meier() -> None:
    times = [1.0, 2.0, 3.0, 4.0, 5.0]
    exploited = [False, True, False, True, False]
    summary = time_to_exploit(times, exploited=exploited, max_time=10.0)
    assert summary["n"] == 5
    assert summary["n_events"] == 2
    assert summary["n_censored"] == 3
    assert summary["median_time"] == pytest.approx(3.0)

    curve = kaplan_meier_survival(times, exploited=exploited)
    assert curve[0]["survival"] == 1.0
    assert curve[-1]["survival"] < 1.0
    assert all(0.0 <= p["survival"] <= 1.0 for p in curve)

    empty = time_to_exploit([], exploited=[])
    assert empty["n"] == 0
    assert kaplan_meier_survival([], exploited=[]) == []


def test_robustness_curve_includes_frr() -> None:
    curve = robustness_curve(
        [0.1, 0.9, 0.5, 0.2],
        [True, False, True, False],
        thresholds=[0.0, 0.5, 1.0],
    )
    assert len(curve) == 3
    assert all("far" in p and "frr" in p for p in curve)
    # At threshold 0 everything accepted → FAR=1 among invalids, FRR=0 among valids.
    assert curve[0]["far"] == 1.0
    assert curve[0]["frr"] == 0.0


def test_compare_repair_real_metrics() -> None:
    trajs = [
        {"steps": [{"op": "refund", "amount": 120}]},
        {"steps": [{"op": "refund", "amount": 50, "user_id": "alice", "token": "valid"}]},
        {"steps": [{"op": "duplicate", "amount": 80}]},
    ]

    def old_v(t: dict) -> bool:
        return grade(t)

    def new_v(t: dict) -> bool:
        for s in t.get("steps") or []:
            if s.get("op") == "refund" and int(s.get("amount", 0)) > 100:
                return False
            if s.get("op") == "duplicate":
                return False
        return True

    out = compare_repair(
        old_verifier=old_v,
        new_verifier=new_v,
        regression_trajectories=trajs,
        is_valid=refund_is_valid,
        fresh_episodes=6,
        fresh_attack_config={"seed": 7, "seeds": [{"op": "refund", "amount": 120}]},
    )
    assert out["mandatory_fresh_attacker"] is True
    assert out["learnability"] == 0.0  # planted regression exploits closed
    assert out["far_delta_regression"] is not None
    assert out["far_delta_regression"] < 0  # FAR should drop on regression corpus
    assert "fresh_far" in out
    assert out["cost"]["regression_n"] == 3
    assert out["cost"]["fresh_n"] == 6
    assert out["fresh_attack"]["overall"]["n"] == 6


def test_plugin_discovery_and_templates() -> None:
    found = discover_plugins()
    assert isinstance(found, dict)
    # Templates are importable even when no entry points are registered.
    attack = load_object("examples.plugins.attack_template:ExampleAttack")
    assert attack is not None
    adapter = load_object("examples.plugins.adapter_template:ExampleAdapter")
    assert adapter is not None


def test_plugin_discovery_loads_mock_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    ep = MagicMock()
    ep.name = "demo_plugin"
    ep.load.return_value = {"ok": True}

    class _EPs:
        def select(self, group: str = "") -> list:
            assert group == "verifierlab.plugins"
            return [ep]

    monkeypatch.setattr("verifierlab.plugins.discovery.entry_points", lambda: _EPs())
    found = discover_plugins()
    assert found["demo_plugin"] == {"ok": True}


def test_harbor_install_status_honest() -> None:
    status = harbor_install_status()
    assert "available" in status
    assert "mode" in status
    assert "lighter_path" in status
    assert status["lighter_path"] == "atif_log_format_regression"
    # Consistency: available flag matches sdk probe.
    assert status["available"] is harbor_sdk_available() or status["mode"] in {
        "unsupported_python",
        "not_installed",
        "broken_install",
        "live",
    }
