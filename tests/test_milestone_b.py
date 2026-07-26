"""Milestone B: Decision aliases, runner, pack CLI, voucher reservation."""

from __future__ import annotations

import asyncio
import json
import threading

from verifierlab.api import Decision, VerifierDecision
from verifierlab.api.decision import DecisionKind
from verifierlab.artifacts.canonical import digest_of
from verifierlab.budgets.budget import Budget, OverrunPolicy
from verifierlab.budgets.ledger import ProvenanceLedger
from verifierlab.campaigns.packs import (
    inspect_pack,
    lint_pack,
    packs_root,
    verify_pack,
    write_pack_sidecars,
)
from verifierlab.verifiers.broker import VerifierBroker
from verifierlab.verifiers.profile import VerifierProfile
from verifierlab.verifiers.runner import PythonVerifierRunner, prefers_subprocess_isolation

PACKS = packs_root()


def test_verifier_decision_alias() -> None:
    assert VerifierDecision is Decision
    d = VerifierDecision.from_raw("reject")
    assert d.kind is DecisionKind.REJECT
    assert d.accepted is False


def test_verifier_profile_public_contract_fields() -> None:
    from examples.refunds.verifier import grade

    profile = VerifierProfile.for_callable(grade)
    assert profile.applicability
    assert profile.access_surface.get("may_read_hidden_labels") is False
    assert "decision_space" in profile.applicability
    digest = profile.content_digest()
    again = VerifierProfile.for_callable(grade)
    assert again.content_digest() == digest


def test_prefers_subprocess_isolation() -> None:
    assert prefers_subprocess_isolation(kind="packaged") is True
    assert prefers_subprocess_isolation(kind="python", config={"isolation": "subprocess"})
    assert prefers_subprocess_isolation(kind="python", config={}) is False


def test_python_verifier_runner_sync_and_timeout() -> None:
    runner = PythonVerifierRunner.from_ref(
        "examples.refunds.verifier:grade",
        timeout_s=30.0,
        config={"packaged": True},
    )
    decision = runner.invoke(
        {
            "steps": [
                {"action": {"op": "refund", "amount": 40, "user_id": "alice", "token": "valid"}}
            ]
        }
    )
    assert decision.kind in {
        DecisionKind.ACCEPT,
        DecisionKind.REJECT,
        DecisionKind.ABSTAIN,
        DecisionKind.INDETERMINATE,
        DecisionKind.ERROR,
        DecisionKind.SCORE,
    }
    assert runner.source_digest
    assert runner.config_digest == digest_of({"packaged": True})


def test_python_verifier_runner_async() -> None:
    runner = PythonVerifierRunner.from_ref("examples.refunds.verifier:grade", timeout_s=30.0)

    async def _run() -> None:
        d = await runner.ainvoke({"steps": []})
        assert d.status in {"accept", "reject", "abstain", "indeterminate", "error"}

    asyncio.run(_run())


def test_broker_prefers_runner() -> None:
    runner = PythonVerifierRunner.from_ref("examples.refunds.verifier:grade", timeout_s=30.0)
    broker = VerifierBroker(
        profile=runner.profile or VerifierProfile.for_callable(runner.as_callable()),
        verifier=runner.as_callable(),
        access_model="black-box",
        runner=runner,
    )
    decision = broker.query({"steps": []})
    assert decision.profile_ref == broker.profile_digest
    assert len(broker.events) == 1


def test_concurrent_voucher_reservation_no_oversubscribe() -> None:
    """Parallel issuers receive disjoint slices; sum(vouchers) <= max_queries."""
    ledger = ProvenanceLedger(budget=Budget(max_queries=100, overrun_policy=OverrunPolicy.STOP))
    issued: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        n = ledger.reserve_query_voucher(100, pending_workers=8)
        with lock:
            issued.append(n)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(issued) <= 100
    assert ledger.reserved_queries == sum(issued)
    assert ledger.available_queries() == 100 - sum(issued)
    # Settle: charge actual spend equal to issued, release reservations.
    for n in issued:
        if n:
            ledger.merge_events(
                [{"kind": "queries", "amount": n, "total": n}],
                refund=False,
                reserved_queries=n,
            )
    assert ledger.queries == sum(issued)
    assert ledger.reserved_queries == 0
    assert ledger.queries <= 100


def test_pack_sidecars_a_through_e_lint() -> None:
    for letter in "abcde":
        matches = sorted(PACKS.glob(f"pack-{letter}-*.yaml"))
        assert matches, letter
        side = PACKS / f"pack-{letter}"
        assert (side / "profile.json").is_file()
        assert (side / "splits.json").is_file()
        assert (side / "expected-public-digests.json").is_file()
        assert (side / "planted-failure.json").is_file()
        assert (side / "adjudication-protocol.json").is_file()
        ok, diags, info = lint_pack(matches[0])
        assert ok, (letter, diags, info)
        ok2, diags2, _ = verify_pack(matches[0])
        assert ok2, (letter, diags2)
        inspected = inspect_pack(side)
        assert inspected["campaign_digest"]
        assert inspected["signing"]["mode"] == "content_addressed"


def test_write_pack_sidecars_idempotent() -> None:
    path = PACKS / "pack-a-outcome-vs-process.yaml"
    a = write_pack_sidecars(path, force=True)
    digest_a = json.loads((a / "expected-public-digests.json").read_text(encoding="utf-8"))[
        "campaign_digest"
    ]
    b = write_pack_sidecars(path, force=True)
    digest_b = json.loads((b / "expected-public-digests.json").read_text(encoding="utf-8"))[
        "campaign_digest"
    ]
    assert digest_a == digest_b


def test_cli_verifier_and_pack_help() -> None:
    from typer.testing import CliRunner

    from verifierlab.cli import app

    runner = CliRunner()
    for args in (
        ["verifier", "--help"],
        ["pack", "--help"],
        ["verifier", "inspect", "--help"],
        ["pack", "lint", "--help"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, (args, result.output)


def test_cli_pack_lint_and_verifier_inspect() -> None:
    from typer.testing import CliRunner

    from verifierlab.cli import app

    runner = CliRunner()
    pack = runner.invoke(
        app,
        ["pack", "lint", str(PACKS / "pack-a-outcome-vs-process.yaml"), "--format", "json"],
    )
    assert pack.exit_code == 0, pack.output
    payload = json.loads(pack.stdout)
    assert payload["ok"] is True

    inspected = runner.invoke(
        app,
        ["verifier", "inspect", "examples.refunds.verifier:grade", "--format", "json"],
    )
    assert inspected.exit_code == 0, inspected.output
    spec = json.loads(inspected.stdout)
    assert spec["name"]
    assert spec["callable_digest"]

    # Root inspect shares one implementation path.
    root = runner.invoke(
        app,
        ["inspect", "examples.refunds.verifier:grade", "--format", "json"],
    )
    assert root.exit_code == 0, root.output
    assert json.loads(root.stdout)["callable_digest"] == spec["callable_digest"]
