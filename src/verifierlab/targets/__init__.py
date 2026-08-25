"""Target adapters and worker-visible fake environments."""

from __future__ import annotations

from verifierlab.targets.fake import FakeEnvironment, fake_refund_verifier
from verifierlab.targets.trainer_adapter import TrainerAdapter, run_trainer_loop

__all__ = [
    "FakeEnvironment",
    "TrainerAdapter",
    "fake_refund_verifier",
    "run_trainer_loop",
]
