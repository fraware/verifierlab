"""Fake environment and planted oracle ground truth."""

from __future__ import annotations

import pytest

from verifierlab.labels.planted_fake import PlantedOracleGroundTruth
from verifierlab.targets.fake import (
    FakeEnvironment,
    fake_refund_verifier,
    propose_fake_action,
)


def test_fake_env_deterministic() -> None:
    env1 = FakeEnvironment(max_steps=2)
    env2 = FakeEnvironment(max_steps=2)
    o1 = env1.reset(seed=7)
    o2 = env2.reset(seed=7)
    assert o1 == o2
    env1.act({"op": "refund", "amount": 10})
    env2.act({"op": "refund", "amount": 10})
    assert env1.finalize() == env2.finalize()


def test_snapshot_restore() -> None:
    env = FakeEnvironment(max_steps=3)
    env.reset(seed=99)
    env.act({"op": "noop"})
    snap = env.snapshot()
    next_noise = env._rng.randint(0, 10_000)
    other = FakeEnvironment()
    other.restore(snap)
    assert other._step == 1
    assert other._actions == [{"op": "noop"}]
    assert other._rng.randint(0, 10_000) == next_noise


def test_planted_gt_commitment_not_boolean_guessable() -> None:
    traj = {
        "seed": 1,
        "steps": [{"op": "refund", "amount": 120}],
        "observation": {},
    }
    gt = PlantedOracleGroundTruth()
    commitment = gt.commit(traj, nonce="fixed-nonce")
    from verifierlab.artifacts.canonical import digest_of

    guess_true = digest_of({"schema_version": "1", "trajectory": traj, "valid": True})
    guess_false = digest_of({"schema_version": "1", "trajectory": traj, "valid": False})
    assert commitment != guess_true
    assert commitment != guess_false
    label = gt.label(commitment, after_freeze=True)
    assert label["valid"] is False
    assert label["dimensions"]["outcome"] == "fail"


def test_planted_gt_and_verifier_far() -> None:
    traj = {
        "seed": 1,
        "steps": [{"op": "refund", "amount": 120}],
        "observation": {},
    }
    gt = PlantedOracleGroundTruth()
    commitment = gt.commit(traj)
    with pytest.raises(PermissionError):
        gt.label(commitment, after_freeze=False)
    label = gt.label(commitment, after_freeze=True)
    assert label["valid"] is False
    assert fake_refund_verifier(traj) is True

    traj_odd = {"seed": 1, "steps": [{"op": "refund", "amount": 121}], "observation": {}}
    assert fake_refund_verifier(traj_odd) is False
    assert gt.commit(traj_odd)


def test_propose_fake_action_deterministic() -> None:
    assert propose_fake_action(42, 0) == propose_fake_action(42, 0)
