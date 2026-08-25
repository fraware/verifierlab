"""RLlib PR-tier conformance tests (skip when ray missing)."""

from __future__ import annotations

import pytest

from verifierlab.attacks.rl import ExternalTrainerAdapter, TabularQTrainer
from verifierlab.trainers.rllib_adapter import RLlibPPOAdapter, ray_rllib_available

pytestmark = [pytest.mark.rllib, pytest.mark.integration]


def test_tabular_trainer_implements_full_protocol() -> None:
    trainer = TabularQTrainer()
    assert isinstance(trainer, ExternalTrainerAdapter)
    trainer.initialize({"seed": 0})
    action = trainer.act({"step": 0, "balance": 500})
    assert "op" in action
    stats = trainer.train(
        {
            "obs": {"step": 0, "balance": 500},
            "action": action,
            "reward": 1.0,
            "next_obs": {"step": 1},
        }
    )
    assert "td_error" in stats
    # Aliases
    trainer.start({"seed": 1})
    trainer.learn(
        {"obs": {"step": 0, "balance": 500}, "action": action, "reward": 0.0, "next_obs": {}}
    )
    ckpt = trainer.checkpoint()
    trainer.freeze()
    with pytest.raises(RuntimeError, match="frozen"):
        trainer.train(
            {"obs": {"step": 0, "balance": 500}, "action": action, "reward": 0.0, "next_obs": {}}
        )
    eval_action = trainer.evaluate({"step": 0, "balance": 500})
    assert isinstance(eval_action, dict)
    trainer.restore(ckpt)
    trainer.close()


@pytest.mark.skipif(not ray_rllib_available(), reason="ray[rllib] not installed")
def test_rllib_ppo_tiny_episode() -> None:
    from verifierlab.targets.fake import fake_refund_verifier
    from verifierlab.targets.gym_adapter import GymnasiumEnvironment
    from verifierlab.verifiers.broker import VerifierBroker
    from verifierlab.verifiers.profile import VerifierProfile

    broker = VerifierBroker(
        profile=VerifierProfile.for_callable(fake_refund_verifier),
        verifier=fake_refund_verifier,
        access_model="black-box",
    )
    env = GymnasiumEnvironment.tiny_discrete(max_steps=4)
    adapter = RLlibPPOAdapter(env=env._env, broker=broker, max_queries=8, max_env_steps=8)
    assert adapter.integration_status == "live"
    assert adapter.capture_config()["not_a_capability_result"] is True
    adapter.initialize({})
    result = adapter.run_tiny_episode(seed=0, steps=3)
    assert result["claim"] == "integration_conformance"
    assert result["n_steps"] >= 1
    adapter.close()
    env.close()


def test_rllib_adapter_missing_ray_status() -> None:
    if ray_rllib_available():
        pytest.skip("ray installed")
    adapter = RLlibPPOAdapter()
    assert adapter.integration_status == "not-live"
