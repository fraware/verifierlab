"""Inspect AI adapter (``[inspect]`` extra).

**Live mode (requires ``inspect-ai``):** builds Tasks, runs ``eval()`` (typically
with ``mockllm/model`` for CI), reads ``EvalLog`` via ``inspect_ai.log``, and
maps samples/scores into native trajectories / :class:`TrajectoryRecord`.

**Log-format regression (no SDK):** ``inspect_log_to_native`` translates Inspect
eval-log JSON fixtures. That path is labeled ``log_format_regression`` — it is
not a fake in-process runner.

Install::

    pip install "verifierlab[inspect]"
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verifierlab.artifacts.records import TrajectoryRecord


def inspect_sdk_available() -> bool:
    """Return True when ``inspect_ai`` is importable."""
    try:
        import inspect_ai  # noqa: F401
    except ImportError:
        return False
    return True


def require_inspect_ai() -> Any:
    """Import ``inspect_ai`` or raise a clear install hint."""
    try:
        import inspect_ai
    except ImportError as exc:
        raise ImportError(
            "Inspect live adapter requires inspect-ai; "
            "install with: pip install 'verifierlab[inspect]'"
        ) from exc
    return inspect_ai


def load_inspect_eval_log(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load an Inspect eval-log JSON document from a path or dict.

    When ``inspect-ai`` is installed and ``source`` is a path, prefer
    ``inspect_ai.log.read_eval_log`` so ``.eval`` / ``.json`` logs use the
    official reader. Dict sources and plain JSON files remain supported without
    the SDK (log-format regression).
    """
    if isinstance(source, dict):
        return dict(source)
    path = Path(source)
    if inspect_sdk_available() and path.suffix in {".eval", ".json", ".jsonl"}:
        try:
            from inspect_ai.log import read_eval_log

            log = read_eval_log(str(path))
            return eval_log_to_dict(log)
        except Exception:
            # Fall through to raw JSON for fixtures / non-EvalLog files.
            pass
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"Inspect eval log must be a JSON object, got {type(data).__name__}")
    return data


def eval_log_to_dict(log: Any) -> dict[str, Any]:
    """Serialize an ``EvalLog`` (or compatible object) to a plain dict."""
    if isinstance(log, dict):
        return dict(log)
    dump = getattr(log, "model_dump", None)
    if callable(dump):
        return dict(dump(mode="json"))
    as_dict = getattr(log, "dict", None)
    if callable(as_dict):
        return dict(as_dict())
    raise TypeError(f"Cannot convert eval log of type {type(log).__name__} to dict")


def _score_accepted(score_blob: Any) -> bool | None:
    if not isinstance(score_blob, dict) or not score_blob:
        return None
    first = next(iter(score_blob.values()))
    if isinstance(first, dict) and "value" in first:
        val = first["value"]
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return float(val) >= 1.0
        if val == "C":
            return True
        if val == "I":
            return False
    return None


def inspect_log_to_native(log: dict[str, Any]) -> dict[str, Any]:
    """Translate an Inspect eval log into a native VerifierLab trajectory.

    Preserves sample inputs/outputs/scores as steps. Does **not** include
    ground-truth ``target`` values as ``gt_*`` / ``hidden_label`` fields — targets
    are kept under ``inspect_target`` for coordinator-side GT only.
    """
    samples = list(log.get("samples") or [])
    steps: list[dict[str, Any]] = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        score_blob = sample.get("scores") or {}
        accepted = _score_accepted(score_blob)
        step: dict[str, Any] = {
            "op": "inspect_sample",
            "sample_id": sample.get("id"),
            "epoch": sample.get("epoch", 1),
            "input": sample.get("input"),
            "output": sample.get("output"),
            "scores": score_blob,
        }
        if "target" in sample:
            step["inspect_target"] = sample["target"]
        if accepted is not None:
            step["verifier_accepted"] = accepted
        steps.append(step)

    eval_raw = log.get("eval")
    eval_spec: dict[str, Any] = eval_raw if isinstance(eval_raw, dict) else {}
    stats_raw = log.get("stats")
    stats: dict[str, Any] = stats_raw if isinstance(stats_raw, dict) else {}
    return {
        "schema_version": "1",
        "framework": "inspect",
        "inspect_version": log.get("version", 2),
        "status": log.get("status"),
        "task": eval_spec.get("task") or eval_spec.get("task_id"),
        "model": eval_spec.get("model"),
        "steps": steps,
        "scorer_log": {
            "results": log.get("results"),
            "n_samples": len(steps),
        },
        "resources": {
            "model_usage": stats.get("model_usage") or stats.get("usage"),
            "started_at": stats.get("started_at"),
            "completed_at": stats.get("completed_at"),
        },
        "raw_keys": sorted(log.keys()),
    }


def native_to_inspect_samples(trajectory: dict[str, Any]) -> list[dict[str, Any]]:
    """Rebuild Inspect-like sample dicts from a native trajectory (round-trip)."""
    samples: list[dict[str, Any]] = []
    for step in trajectory.get("steps") or []:
        if not isinstance(step, dict):
            continue
        sample: dict[str, Any] = {
            "id": step.get("sample_id", len(samples) + 1),
            "epoch": step.get("epoch", 1),
            "input": step.get("input", ""),
            "output": step.get("output"),
            "scores": step.get("scores") or {},
        }
        if "inspect_target" in step:
            sample["target"] = step["inspect_target"]
        samples.append(sample)
    return samples


def native_to_inspect_log(trajectory: dict[str, Any]) -> dict[str, Any]:
    """Produce a minimal Inspect eval-log JSON from a native trajectory."""
    return {
        "version": int(trajectory.get("inspect_version") or 2),
        "status": trajectory.get("status") or "success",
        "eval": {
            "task": trajectory.get("task") or "unknown",
            "model": trajectory.get("model") or "unknown",
        },
        "results": (trajectory.get("scorer_log") or {}).get("results"),
        "stats": {
            "model_usage": (trajectory.get("resources") or {}).get("model_usage"),
        },
        "samples": native_to_inspect_samples(trajectory),
    }


def native_to_trajectory_record(
    trajectory: dict[str, Any],
    *,
    trajectory_id: str = "inspect",
    seed: int = 0,
) -> TrajectoryRecord:
    """Map a native Inspect trajectory into a :class:`TrajectoryRecord`."""
    return TrajectoryRecord(
        trajectory_id=trajectory_id,
        seed=int(trajectory.get("seed", seed)),
        steps=list(trajectory.get("steps") or []),
        observation={
            "task": trajectory.get("task"),
            "model": trajectory.get("model"),
            "status": trajectory.get("status"),
        },
        metadata={
            "framework": "inspect",
            "scorer_log": trajectory.get("scorer_log") or {},
        },
    )


def build_minimal_task() -> Any:
    """Build a minimal real Inspect ``Task`` (requires ``inspect-ai``)."""
    require_inspect_ai()
    from inspect_ai import Task
    from inspect_ai.dataset import Sample
    from inspect_ai.scorer import match
    from inspect_ai.solver import generate

    return Task(
        dataset=[
            Sample(input="Should we approve a refund of $50? Answer yes or no.", target="yes"),
            Sample(input="Should we approve a refund of $500? Answer yes or no.", target="no"),
        ],
        solver=generate(),
        scorer=match(),
        name="verifierlab_minimal_refund",
    )


def run_inspect_eval(
    task: Any | None = None,
    *,
    model: str = "mockllm/model",
    log_dir: str | Path | None = None,
    **eval_kwargs: Any,
) -> list[Any]:
    """Run ``inspect_ai.eval`` on ``task`` (default: :func:`build_minimal_task`)."""
    require_inspect_ai()
    from inspect_ai import eval as inspect_eval

    resolved = task if task is not None else build_minimal_task()
    kwargs: dict[str, Any] = {"model": model, **eval_kwargs}
    if log_dir is not None:
        kwargs["log_dir"] = str(log_dir)
    logs = inspect_eval(resolved, **kwargs)
    return list(logs)


class InspectEnvironment:
    """Native :class:`~verifierlab.api.protocols.EnvironmentTarget` over Inspect.

    Live construction requires ``inspect-ai``. Episodes run a Task via
    ``eval()`` and expose the mapped trajectory through ``finalize()``.
    """

    def __init__(
        self,
        *,
        task: Any | None = None,
        model: str = "mockllm/model",
        version: str = "0.1",
    ) -> None:
        require_inspect_ai()
        self.task = task
        self.model = model
        self.version = version
        self._seed = 0
        self._native: dict[str, Any] | None = None
        self._logs: list[Any] = []

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._native = None
        self._logs = []
        return {"seed": seed, "framework": "inspect", "model": self.model}

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        # A single act triggers the Inspect eval (episode is one eval run).
        model = str(action.get("model") or self.model)
        self._logs = run_inspect_eval(self.task, model=model)
        log0 = self._logs[0] if self._logs else None
        log_dict = eval_log_to_dict(log0) if log0 is not None else {}
        self._native = inspect_log_to_native(log_dict)
        self._native["seed"] = self._seed
        n = len(self._native.get("steps") or [])
        return {
            "observation": {"n_samples": n, "status": self._native.get("status")},
            "reward": float(n > 0),
            "done": True,
            "resources": {"inspect_evals": 1, "samples": n},
        }

    def finalize(self) -> dict[str, Any]:
        if self._native is None:
            return {
                "schema_version": "1",
                "seed": self._seed,
                "steps": [],
                "framework": "inspect",
                "integration_status": "live",
            }
        out = dict(self._native)
        out["integration_status"] = "live"
        return out

    def snapshot(self) -> bytes:
        payload = {"seed": self._seed, "native": self._native}
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode("utf-8"))
        self._seed = int(state["seed"])
        self._native = state.get("native")


class InspectAdapter:
    """Map Inspect tasks/scorers/logs into native trajectory artifacts.

    Modes:

    * ``live`` — ``inspect-ai`` installed; can run Tasks / read EvalLog.
    * ``log_format_regression`` — fixture/path eval-log JSON without SDK.
    """

    name = "inspect"

    def __init__(
        self,
        *,
        task: str = "demo",
        version: str = "0.1",
        eval_log: dict[str, Any] | None = None,
        eval_log_path: str | Path | None = None,
        inspect_task: Any | None = None,
        model: str = "mockllm/model",
        run_on_reset: bool = False,
    ) -> None:
        self.task = task
        self.version = version
        self.model = model
        self._inspect_task = inspect_task
        self._run_on_reset = run_on_reset
        self._steps: list[dict[str, Any]] = []
        self._seed = 0
        self._native: dict[str, Any] | None = None
        self._mode = "unset"
        self._env: InspectEnvironment | None = None

        sdk = inspect_sdk_available()
        if eval_log_path is not None or eval_log is not None:
            source: str | Path | dict[str, Any] = (
                eval_log_path if eval_log_path is not None else eval_log  # type: ignore[assignment]
            )
            loaded = load_inspect_eval_log(source)
            self._native = inspect_log_to_native(loaded)
            if self._native.get("task"):
                self.task = str(self._native["task"])
            # Fixture / file translation is always log-format regression;
            # live Task execution uses inspect_task / InspectEnvironment.
            self._mode = "log_format_regression"
        elif sdk:
            self._env = InspectEnvironment(
                task=inspect_task,
                model=model,
                version=version,
            )
            self._mode = "live"
            if inspect_task is not None:
                self.task = getattr(inspect_task, "name", None) or self.task
        else:
            raise ImportError(
                "InspectAdapter requires either an eval_log / eval_log_path "
                "(log-format regression) or inspect-ai for live mode; "
                "install with: pip install 'verifierlab[inspect]'"
            )

    @property
    def integration_status(self) -> str:
        return self._mode

    def capture_config(self) -> dict[str, Any]:
        return {
            "framework": "inspect",
            "version": self.version,
            "task": self.task,
            "sdk_available": inspect_sdk_available(),
            "integration_status": self.integration_status,
            "mode": self._mode,
            "model": self.model,
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._steps = []
        if self._env is not None and self._run_on_reset:
            obs = self._env.reset(seed=seed)
            self._env.act({"model": self.model})
            self._native = self._env.finalize()
            return {**obs, "n_samples": len(self._native.get("steps") or [])}
        if self._env is not None:
            return self._env.reset(seed=seed)
        if self._native is not None:
            return {
                "seed": seed,
                "task": self.task,
                "n_samples": len(self._native.get("steps") or []),
            }
        return {"seed": seed, "task": self.task}

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        self._steps.append(dict(action))
        if self._env is not None and self._native is None:
            result = self._env.act(action)
            self._native = self._env.finalize()
            return result
        resources: dict[str, Any] = {"queries": 1}
        if self._native and isinstance(self._native.get("resources"), dict):
            resources = {**resources, **self._native["resources"]}
        return {
            "observation": {"step": len(self._steps)},
            "reward": 0.0,
            "resources": resources,
        }

    def finalize(self) -> dict[str, Any]:
        if self._native is not None:
            out = dict(self._native)
            out["seed"] = self._seed
            out["integration_status"] = self.integration_status
            if self._steps and self._env is None:
                out["steps"] = list(out.get("steps") or []) + list(self._steps)
            return out
        if self._env is not None:
            return self._env.finalize()
        raise RuntimeError("InspectAdapter has no trajectory; call reset/step first")

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "inspect"}
