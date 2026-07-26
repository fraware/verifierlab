"""Persistent attacker runtime: checkpointed strategies + broker search (VAL-R07/R08)."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from verifierlab.api.protocols import AttackStrategy
from verifierlab.artifacts.canonical import digest_of
from verifierlab.attacks.registry import create_strategy, get_strategy_class

# Strategies that persist state across episodes and may issue candidate queries.
LEARNING_STRATEGIES = frozenset({"best_of_n", "beam", "evolutionary", "rl_tabular"})
BASELINE_STRATEGIES = frozenset({"ordinary", "random_fuzz", "structured_fuzz", "coverage_fuzz"})


def is_learning_strategy(name: str) -> bool:
    return str(name) in LEARNING_STRATEGIES


def attacker_store_path(run_dir: Path, strategy: str, seed: int) -> Path:
    """``run_dir/attackers/<strategy>/<seed>/``."""
    return Path(run_dir) / "attackers" / str(strategy) / str(int(seed))


class AttackerStore:
    """Filesystem checkpoint store for a single (strategy, seed) attacker."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._state_path = self.root / "state.json"
        self._meta_path = self.root / "meta.json"
        self._frozen_path = self.root / "FROZEN"

    @property
    def frozen(self) -> bool:
        return self._frozen_path.is_file()

    def freeze(self) -> None:
        self._frozen_path.write_text("frozen\n", encoding="utf-8")
        self._write_meta({"frozen": True})

    def load_state(self) -> dict[str, Any] | None:
        with self._lock:
            if not self._state_path.is_file():
                return None
            data: object = json.loads(self._state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise TypeError("attacker state must be a JSON object")
            return dict(data)

    def save_state(self, state: dict[str, Any]) -> str:
        with self._lock:
            if self.frozen:
                raise RuntimeError("attacker is frozen; refusing to save learning state")
            payload = dict(state)
            payload.setdefault("schema_version", "1")
            digest = digest_of(payload)
            payload["content_digest"] = digest
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tmp.replace(self._state_path)
            self._write_meta({"frozen": False, "content_digest": digest})
            return digest

    def _write_meta(self, extra: dict[str, Any]) -> None:
        meta = {}
        if self._meta_path.is_file():
            meta = json.loads(self._meta_path.read_text(encoding="utf-8"))
        meta.update(extra)
        self._meta_path.write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def json_safe_rng_state(state: Any) -> Any:
    """Convert ``random.Random.getstate()`` into JSON-friendly nested lists."""
    if isinstance(state, tuple):
        return [json_safe_rng_state(x) for x in state]
    if isinstance(state, list):
        return [json_safe_rng_state(x) for x in state]
    return state


def rng_state_from_json(state: Any) -> Any:
    """Inverse of :func:`json_safe_rng_state` for ``Random.setstate``."""
    if isinstance(state, list):
        # getstate shape: (version, internal_tuple, gauss_next)
        if len(state) == 3 and isinstance(state[1], list):
            return (state[0], tuple(state[1]), state[2])
        return tuple(rng_state_from_json(x) for x in state)
    return state


def restore_strategy(strategy: AttackStrategy, state: dict[str, Any] | None) -> None:
    """Restore strategy from a checkpoint payload when ``restore`` is available."""
    if not state:
        return
    payload = dict(state)
    if "rng_state" in payload and payload["rng_state"] is not None:
        payload["rng_state"] = rng_state_from_json(payload["rng_state"])
    # Nested trainer rng (rl_tabular).
    trainer = payload.get("trainer")
    if isinstance(trainer, dict) and trainer.get("rng_state") is not None:
        trainer = dict(trainer)
        trainer["rng_state"] = rng_state_from_json(trainer["rng_state"])
        payload["trainer"] = trainer
    restore = getattr(strategy, "restore", None)
    if callable(restore):
        restore(payload)


def bind_strategy_runtime(
    strategy: AttackStrategy,
    *,
    broker: Any | None = None,
    env: Any | None = None,
    learning: bool = True,
) -> None:
    """Attach broker/env and learning flag when the strategy supports them."""
    binder = getattr(strategy, "bind_runtime", None)
    if callable(binder):
        binder(broker=broker, env=env, learning=learning)
        return
    # Duck-typed fallback for strategies without bind_runtime.
    if hasattr(strategy, "_broker"):
        strategy._broker = broker
    if hasattr(strategy, "_env"):
        strategy._env = env
    if hasattr(strategy, "_learning"):
        strategy._learning = learning


class PersistentAttacker:
    """Initialize once per (campaign, strategy, seed); checkpoint across units."""

    def __init__(
        self,
        *,
        strategy_name: str,
        seed: int,
        config: dict[str, Any] | None = None,
        store: AttackerStore,
    ) -> None:
        self.strategy_name = strategy_name
        self.seed = int(seed)
        self.config = dict(config or {})
        self.config.setdefault("seed", self.seed)
        self.store = store
        self.strategy: AttackStrategy = create_strategy(strategy_name, self.config)
        prior = store.load_state()
        if prior is not None:
            restore_strategy(self.strategy, prior)
            self.strategy._restored = True  # type: ignore[attr-defined]
        self._episodes = int((prior or {}).get("episodes", 0))

    @classmethod
    def open(
        cls,
        run_dir: Path,
        *,
        strategy_name: str,
        seed: int,
        config: dict[str, Any] | None = None,
    ) -> PersistentAttacker:
        path = attacker_store_path(run_dir, strategy_name, seed)
        return cls(
            strategy_name=strategy_name,
            seed=seed,
            config=config,
            store=AttackerStore(path),
        )

    @property
    def frozen(self) -> bool:
        return self.store.frozen

    def freeze(self) -> None:
        """Freeze attacker: holdout eval must not further learn."""
        # Persist current state once more, then seal.
        if not self.store.frozen:
            self.checkpoint()
        self.store.freeze()

    def checkpoint(self) -> dict[str, Any]:
        state = dict(self.strategy.checkpoint())
        if "rng_state" in state and state["rng_state"] is not None:
            state["rng_state"] = json_safe_rng_state(state["rng_state"])
        trainer = state.get("trainer")
        if isinstance(trainer, dict) and trainer.get("rng_state") is not None:
            trainer = dict(trainer)
            trainer["rng_state"] = json_safe_rng_state(trainer["rng_state"])
            state["trainer"] = trainer
        state["episodes"] = self._episodes
        state["strategy_name"] = self.strategy_name
        state["seed"] = self.seed
        self.store.save_state(state)
        return state

    def note_episode(self) -> None:
        self._episodes += 1


def decision_score(decision: Any) -> float:
    """Public-channel score for candidate ranking (capability-aware).

    Prefer explicit ``score`` when present. Only fold ``accepted`` when the
    decision still exposes a hard label (not score_only).
    """
    accepted = getattr(decision, "accepted", None)
    score = getattr(decision, "score", None)
    if score is not None:
        base = float(score)
        # Hard label bonus only when the channel still exposes accept/reject.
        if accepted is True:
            return base + 1.0
        if accepted is False:
            return base - 0.1
        return base
    if accepted is True:
        return 1.0
    if accepted is False:
        return -0.1
    return 0.0


def evaluate_candidate_trajectory(
    env: Any,
    action: dict[str, Any],
    broker: Any,
    *,
    caller: str,
) -> tuple[float, Any]:
    """Snapshot env, apply ``action``, query broker, restore. Returns (score, decision).

    Meters ``ledger.add_candidates(1)`` and ``ledger.add_compute_units(1)`` when
    a ledger is attached (VALAB-04). Capability channel follows the broker
    access model (score_only → score).
    """
    snap = env.snapshot()
    try:
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        env.act(clean)
        if hasattr(env, "finalize"):
            traj = env.finalize()
        else:
            traj = {
                "steps": list(getattr(env, "_actions", [clean])),
                "observation": dict(getattr(env, "_observation", {})),
                "schema_version": "1",
            }
        ledger = getattr(broker, "ledger", None)
        if ledger is not None:
            if hasattr(ledger, "add_candidates"):
                ledger.add_candidates(1)
            if hasattr(ledger, "add_compute_units"):
                ledger.add_compute_units(1.0)
        decision = broker.query(traj, caller=caller)
        return decision_score(decision), decision
    finally:
        env.restore(snap)


def ensure_restore_supported(strategy_name: str) -> None:
    """Dev helper: learning strategies must implement restore()."""
    if not is_learning_strategy(strategy_name):
        return
    cls = get_strategy_class(strategy_name)
    if not hasattr(cls, "restore"):
        raise TypeError(f"learning strategy {strategy_name!r} must implement restore()")
