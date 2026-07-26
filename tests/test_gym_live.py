"""Expanded Gymnasium live matrix (Milestone C2)."""

from __future__ import annotations

import pytest

from verifierlab.targets.conformance import run_conformance
from verifierlab.targets.gym_adapter import (
    GymAdapter,
    GymnasiumEnvironment,
    capture_wrapper_stack,
    gymnasium_available,
)

pytestmark = pytest.mark.gym


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_live_tiny_discrete_environment_target() -> None:
    env = GymnasiumEnvironment.tiny_discrete(max_steps=4)
    obs = env.reset(seed=7)
    assert obs["seed"] == 7
    assert "observation" in obs
    assert "wrapper_stack" in obs
    step = env.act({"action": 1})
    assert "reward" in step
    assert "resources" in step
    snap = env.snapshot()
    env.act({"action": 0})
    env.restore(snap)
    traj = env.finalize()
    assert traj["framework"] == "gymnasium"
    assert traj["env_id"] == "TinyDiscrete-v0"
    assert isinstance(traj["steps"], list)
    assert "spaces" in traj
    env.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_live_gym_adapter_conformance() -> None:
    adapter = GymAdapter(env_id="TinyDiscrete-v0")
    assert adapter.integration_status == "live"
    cfg = adapter.capture_config()
    assert cfg["live_env"] is True
    assert cfg["legacy_gym_claimed"] is False
    result = run_conformance(adapter, seed=3)
    assert result.ok, result.as_dict()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_cartpole_when_available() -> None:
    try:
        env = GymnasiumEnvironment.from_id("CartPole-v1", max_steps=10)
    except Exception as exc:  # pragma: no cover - asset / backend issues
        pytest.skip(f"CartPole-v1 unavailable: {exc}")
    obs = env.reset(seed=1)
    assert "observation" in obs
    env.act({"action": 0})
    traj = env.finalize()
    assert traj["n_steps"] >= 1
    env.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_dict_spaces() -> None:
    env = GymnasiumEnvironment.dict_space_env(max_steps=6)
    obs = env.reset(seed=2)
    assert isinstance(obs["observation"], dict)
    assert "pos" in obs["observation"]
    step = env.act({"action": 1})
    assert "observation" in step
    assert env._spaces["observation_space"]["type"] == "Dict"
    env.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_terminated_vs_truncated() -> None:
    env = GymnasiumEnvironment.truncated_env(truncate_after=2, max_steps=8)
    env.reset(seed=0)
    step1 = env.act({"action": 0})
    assert step1["truncated"] is False or step1["terminated"] is False
    step2 = env.act({"action": 0})
    assert step2["truncated"] is True or step2["done"] is True
    env.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_invalid_action() -> None:
    env = GymnasiumEnvironment.tiny_discrete(max_steps=4)
    env.reset(seed=0)
    bad = env.act({"action": 99})
    assert bad.get("error") == "invalid_action"
    assert bad.get("info", {}).get("invalid_action") is True
    env.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_non_json_obs() -> None:
    env = GymnasiumEnvironment.non_json_obs_env(max_steps=4)
    obs = env.reset(seed=1)
    # Non-JSON values must be stringified for trajectory safety.
    assert isinstance(obs["observation"], str)
    env.act({"action": 1})
    traj = env.finalize()
    assert isinstance(traj["observation"], str)
    env.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_fixed_seed_replay() -> None:
    env = GymnasiumEnvironment.tiny_discrete(max_steps=6)
    env.reset(seed=42)
    env.act({"action": 1})
    env.act({"action": 0})
    snap = env.snapshot()
    traj_a = env.finalize()

    env2 = GymnasiumEnvironment.tiny_discrete(max_steps=6)
    env2.restore(snap)
    traj_b = env2.finalize()
    assert traj_a["steps"] == traj_b["steps"]
    assert traj_a["seed"] == traj_b["seed"] == 42
    env.close()
    env2.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_wrapper_stack_capture() -> None:
    env = GymnasiumEnvironment.tiny_discrete(max_steps=3)
    stack = capture_wrapper_stack(env._env)
    assert stack
    obs = env.reset(seed=0)
    assert obs["wrapper_stack"]
    traj = env.finalize()
    assert traj["wrapper_stack"]
    env.close()


def test_gym_adapter_missing_extra_raises() -> None:
    if gymnasium_available():
        pytest.skip("gymnasium installed; ImportError path not exercised")
    with pytest.raises(ImportError, match="gymnasium"):
        GymAdapter(env_id="TinyDiscrete-v0")
