"""Live Gymnasium adapter tests (skip when ``[gym]`` extra missing)."""

from __future__ import annotations

import pytest

from verifierlab.targets.conformance import run_conformance
from verifierlab.targets.gym_adapter import (
    GymAdapter,
    GymnasiumEnvironment,
    gymnasium_available,
)

pytestmark = pytest.mark.gym


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_live_tiny_discrete_environment_target() -> None:
    env = GymnasiumEnvironment.tiny_discrete(max_steps=4)
    obs = env.reset(seed=7)
    assert obs["seed"] == 7
    assert "observation" in obs
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
    env.close()


@pytest.mark.skipif(not gymnasium_available(), reason="gymnasium not installed")
def test_live_gym_adapter_conformance() -> None:
    adapter = GymAdapter(env_id="TinyDiscrete-v0")
    assert adapter.integration_status == "live"
    assert adapter.capture_config()["live_env"] is True
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


def test_gym_adapter_missing_extra_raises() -> None:
    if gymnasium_available():
        pytest.skip("gymnasium installed; ImportError path not exercised")
    with pytest.raises(ImportError, match="gymnasium"):
        GymAdapter(env_id="TinyDiscrete-v0")
