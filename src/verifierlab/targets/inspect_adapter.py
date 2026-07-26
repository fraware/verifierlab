"""Inspect AI adapter (``[inspect]`` extra).

**Modes (explicit, do not collapse):**

* ``live_task`` — run a real Inspect ``Task`` via ``eval()`` (requires ``inspect-ai``).
  Alias: ``live``.
* ``scorer_verifier`` — map Inspect scorer outputs through configurable score
  policies into VerifierLab decisions (requires ``inspect-ai`` or precomputed
  score payloads).
* ``eval_log_import`` — translate Inspect eval-log JSON (fixture or
  ``read_eval_log``). Alias: ``log_format_regression``. Never labeled live.

**Score policies:** ``boolean``, ``numeric_threshold``, ``categorical_map``,
``multi_score_composition``, ``abstention_map``.

Hidden Inspect targets belong in adjudication only. Worker artifacts carry
sample IDs / commitments — not ground-truth labels.

Install::

    pip install "verifierlab[inspect]"
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from verifierlab.artifacts.records import TrajectoryRecord

InspectMode = Literal["live_task", "scorer_verifier", "eval_log_import"]

_MODE_ALIASES: dict[str, InspectMode] = {
    "live": "live_task",
    "live_task": "live_task",
    "scorer_verifier": "scorer_verifier",
    "eval_log_import": "eval_log_import",
    "log_format_regression": "eval_log_import",
}


def normalize_inspect_mode(mode: str) -> InspectMode:
    """Normalize mode names; reject unknown values."""
    key = str(mode).strip().lower()
    if key not in _MODE_ALIASES:
        raise ValueError(
            f"Unknown Inspect mode {mode!r}; expected one of "
            f"{sorted(set(_MODE_ALIASES.values()))} "
            f"(aliases: live→live_task, log_format_regression→eval_log_import)"
        )
    return _MODE_ALIASES[key]


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


@dataclass
class ScorePolicyResult:
    accepted: bool | None
    status: str
    score: float | None = None
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def _first_score_value(score_blob: Any) -> Any:
    if not isinstance(score_blob, dict) or not score_blob:
        return None
    first = next(iter(score_blob.values()))
    if isinstance(first, dict) and "value" in first:
        return first["value"]
    return first


@dataclass
class BooleanScorePolicy:
    """Map boolean / C/I style scores to accept/reject."""

    name: str = "boolean"

    def apply(self, score_blob: Any) -> ScorePolicyResult:
        val = _first_score_value(score_blob)
        if isinstance(val, bool):
            return ScorePolicyResult(
                accepted=val, status="ok", score=1.0 if val else 0.0, reason_codes=["boolean"]
            )
        if isinstance(val, (int, float)):
            # Inspect often emits 1.0 / 0.0 for correct/incorrect.
            ok = float(val) >= 1.0
            return ScorePolicyResult(
                accepted=ok, status="ok", score=float(val), reason_codes=["boolean_numeric"]
            )
        if val == "C":
            return ScorePolicyResult(accepted=True, status="ok", score=1.0, reason_codes=["C"])
        if val == "I":
            return ScorePolicyResult(accepted=False, status="ok", score=0.0, reason_codes=["I"])
        return ScorePolicyResult(
            accepted=None,
            status="abstain",
            reason_codes=["boolean_unmapped"],
            details={"value": val},
        )


@dataclass
class NumericThresholdScorePolicy:
    """Accept when numeric score >= threshold."""

    threshold: float = 1.0
    name: str = "numeric_threshold"

    def apply(self, score_blob: Any) -> ScorePolicyResult:
        val = _first_score_value(score_blob)
        if isinstance(val, bool):
            val = 1.0 if val else 0.0
        if not isinstance(val, (int, float)):
            return ScorePolicyResult(
                accepted=None,
                status="abstain",
                reason_codes=["numeric_unmapped"],
                details={"value": val},
            )
        ok = float(val) >= float(self.threshold)
        return ScorePolicyResult(
            accepted=ok,
            status="ok",
            score=float(val),
            reason_codes=["numeric_threshold"],
            details={"threshold": self.threshold},
        )


@dataclass
class CategoricalMapScorePolicy:
    """Map categorical score strings via an explicit dictionary."""

    mapping: dict[str, bool | None] = field(
        default_factory=lambda: {"C": True, "I": False, "A": None}
    )
    name: str = "categorical_map"

    def apply(self, score_blob: Any) -> ScorePolicyResult:
        val = _first_score_value(score_blob)
        key = str(val) if val is not None else ""
        if key not in self.mapping:
            return ScorePolicyResult(
                accepted=None,
                status="abstain",
                reason_codes=["categorical_unmapped"],
                details={"value": val},
            )
        mapped = self.mapping[key]
        status = "abstain" if mapped is None else "ok"
        return ScorePolicyResult(
            accepted=mapped,
            status=status,
            score=None if mapped is None else (1.0 if mapped else 0.0),
            reason_codes=["categorical_map"],
            details={"key": key},
        )


@dataclass
class MultiScoreCompositionPolicy:
    """Compose multiple named scores (all must accept by default)."""

    require_all: bool = True
    name: str = "multi_score_composition"

    def apply(self, score_blob: Any) -> ScorePolicyResult:
        if not isinstance(score_blob, dict) or not score_blob:
            return ScorePolicyResult(
                accepted=None, status="abstain", reason_codes=["multi_empty"]
            )
        results: list[bool | None] = []
        for key, blob in score_blob.items():
            sub = BooleanScorePolicy().apply({key: blob})
            results.append(sub.accepted)
        if any(r is None for r in results):
            return ScorePolicyResult(
                accepted=None,
                status="abstain",
                reason_codes=["multi_partial"],
                details={"results": results},
            )
        bools = [bool(r) for r in results]
        ok = all(bools) if self.require_all else any(bools)
        return ScorePolicyResult(
            accepted=ok,
            status="ok",
            score=float(sum(bools)) / float(len(bools)),
            reason_codes=["multi_score_composition"],
            details={"require_all": self.require_all, "n": len(bools)},
        )


@dataclass
class AbstentionMapScorePolicy:
    """Map values to accept / reject / abstain via three buckets."""

    accept: set[str] = field(default_factory=lambda: {"C", "pass", "true", "1"})
    reject: set[str] = field(default_factory=lambda: {"I", "fail", "false", "0"})
    abstain: set[str] = field(default_factory=lambda: {"A", "abstain", "unknown"})
    name: str = "abstention_map"

    def apply(self, score_blob: Any) -> ScorePolicyResult:
        val = _first_score_value(score_blob)
        key = str(val).strip().lower() if val is not None else ""
        if key in {a.lower() for a in self.accept}:
            return ScorePolicyResult(
                accepted=True, status="ok", score=1.0, reason_codes=["abstention_map_accept"]
            )
        if key in {r.lower() for r in self.reject}:
            return ScorePolicyResult(
                accepted=False, status="ok", score=0.0, reason_codes=["abstention_map_reject"]
            )
        if key in {a.lower() for a in self.abstain}:
            return ScorePolicyResult(
                accepted=None, status="abstain", reason_codes=["abstention_map_abstain"]
            )
        return ScorePolicyResult(
            accepted=None,
            status="abstain",
            reason_codes=["abstention_map_unmapped"],
            details={"value": val},
        )


ScorePolicy = (
    BooleanScorePolicy
    | NumericThresholdScorePolicy
    | CategoricalMapScorePolicy
    | MultiScoreCompositionPolicy
    | AbstentionMapScorePolicy
)


def build_score_policy(kind: str, **kwargs: Any) -> ScorePolicy:
    """Factory for configurable Inspect score policies."""
    key = str(kind).strip().lower()
    if key == "boolean":
        return BooleanScorePolicy(**kwargs)
    if key == "numeric_threshold":
        return NumericThresholdScorePolicy(**kwargs)
    if key == "categorical_map":
        return CategoricalMapScorePolicy(**kwargs)
    if key == "multi_score_composition":
        return MultiScoreCompositionPolicy(**kwargs)
    if key == "abstention_map":
        return AbstentionMapScorePolicy(**kwargs)
    raise ValueError(
        f"Unknown score policy {kind!r}; expected boolean|numeric_threshold|"
        "categorical_map|multi_score_composition|abstention_map"
    )


def apply_score_policy(score_blob: Any, policy: ScorePolicy | None = None) -> ScorePolicyResult:
    return (policy or BooleanScorePolicy()).apply(score_blob)


def _sample_commitment(sample_id: Any, epoch: Any) -> str:
    raw = f"{sample_id}:{epoch}".encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def load_inspect_eval_log(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load an Inspect eval-log JSON document from a path or dict."""
    if isinstance(source, dict):
        return dict(source)
    path = Path(source)
    if inspect_sdk_available() and path.suffix in {".eval", ".json", ".jsonl"}:
        try:
            from inspect_ai.log import read_eval_log

            log = read_eval_log(str(path))
            return eval_log_to_dict(log)
        except Exception:
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


def inspect_log_to_native(
    log: dict[str, Any],
    *,
    score_policy: ScorePolicy | None = None,
    include_hidden_targets: bool = False,
) -> dict[str, Any]:
    """Translate an Inspect eval log into a native VerifierLab trajectory.

    Worker-facing output uses sample IDs / commitments. Hidden ``target`` values
    are omitted unless ``include_hidden_targets=True`` (adjudication only).
    """
    policy = score_policy or BooleanScorePolicy()
    samples = list(log.get("samples") or [])
    steps: list[dict[str, Any]] = []
    adjudication_targets: list[dict[str, Any]] = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        score_blob = sample.get("scores") or {}
        policy_result = apply_score_policy(score_blob, policy)
        sample_id = sample.get("id")
        epoch = sample.get("epoch", 1)
        step: dict[str, Any] = {
            "op": "inspect_sample",
            "sample_id": sample_id,
            "epoch": epoch,
            "sample_commitment": _sample_commitment(sample_id, epoch),
            "input": sample.get("input"),
            "output": sample.get("output"),
            "scores": score_blob,
            "score_policy": policy.name,
            "score_status": policy_result.status,
        }
        if policy_result.score is not None:
            step["score"] = policy_result.score
        if policy_result.accepted is not None:
            step["verifier_accepted"] = policy_result.accepted
        if policy_result.reason_codes:
            step["reason_codes"] = list(policy_result.reason_codes)
        if "target" in sample:
            adjudication_targets.append(
                {
                    "sample_id": sample_id,
                    "epoch": epoch,
                    "sample_commitment": step["sample_commitment"],
                    "inspect_target": sample["target"],
                }
            )
            if include_hidden_targets:
                step["inspect_target"] = sample["target"]
        steps.append(step)

    eval_raw = log.get("eval")
    eval_spec: dict[str, Any] = eval_raw if isinstance(eval_raw, dict) else {}
    stats_raw = log.get("stats")
    stats: dict[str, Any] = stats_raw if isinstance(stats_raw, dict) else {}
    out: dict[str, Any] = {
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
            "score_policy": policy.name,
        },
        "resources": {
            "model_usage": stats.get("model_usage") or stats.get("usage"),
            "started_at": stats.get("started_at"),
            "completed_at": stats.get("completed_at"),
        },
        "raw_keys": sorted(log.keys()),
    }
    if include_hidden_targets:
        out["adjudication_targets"] = adjudication_targets
    return out


def native_to_inspect_samples(trajectory: dict[str, Any]) -> list[dict[str, Any]]:
    """Rebuild Inspect-like sample dicts from a native trajectory (round-trip)."""
    samples: list[dict[str, Any]] = []
    adj = {
        (t.get("sample_id"), t.get("epoch")): t.get("inspect_target")
        for t in (trajectory.get("adjudication_targets") or [])
        if isinstance(t, dict)
    }
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
        elif (step.get("sample_id"), step.get("epoch")) in adj:
            sample["target"] = adj[(step.get("sample_id"), step.get("epoch"))]
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
            "mode": trajectory.get("mode"),
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
    """Native environment target over Inspect (live_task)."""

    def __init__(
        self,
        *,
        task: Any | None = None,
        model: str = "mockllm/model",
        version: str = "0.1",
        score_policy: ScorePolicy | None = None,
    ) -> None:
        require_inspect_ai()
        self.task = task
        self.model = model
        self.version = version
        self.score_policy = score_policy or BooleanScorePolicy()
        self._seed = 0
        self._native: dict[str, Any] | None = None
        self._logs: list[Any] = []
        self._adjudication_targets: list[dict[str, Any]] = []

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._native = None
        self._logs = []
        self._adjudication_targets = []
        return {"seed": seed, "framework": "inspect", "model": self.model, "mode": "live_task"}

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        model = str(action.get("model") or self.model)
        self._logs = run_inspect_eval(self.task, model=model)
        log0 = self._logs[0] if self._logs else None
        log_dict = eval_log_to_dict(log0) if log0 is not None else {}
        full = inspect_log_to_native(
            log_dict, score_policy=self.score_policy, include_hidden_targets=True
        )
        self._adjudication_targets = list(full.pop("adjudication_targets", []))
        self._native = inspect_log_to_native(log_dict, score_policy=self.score_policy)
        self._native["seed"] = self._seed
        self._native["mode"] = "live_task"
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
                "mode": "live_task",
                "integration_status": "live_task",
            }
        out = dict(self._native)
        out["integration_status"] = "live_task"
        out["mode"] = "live_task"
        return out

    def adjudication_targets(self) -> list[dict[str, Any]]:
        return list(self._adjudication_targets)

    def snapshot(self) -> bytes:
        payload = {
            "seed": self._seed,
            "native": self._native,
            "adjudication_targets": self._adjudication_targets,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode())
        self._seed = int(state["seed"])
        self._native = state.get("native")
        self._adjudication_targets = list(state.get("adjudication_targets") or [])


class InspectAdapter:
    """Map Inspect tasks/scorers/logs into native trajectory artifacts."""

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
        mode: str | None = None,
        score_policy: ScorePolicy | str | dict[str, Any] | None = None,
    ) -> None:
        self.task = task
        self.version = version
        self.model = model
        self._inspect_task = inspect_task
        self._run_on_reset = run_on_reset
        self._steps: list[dict[str, Any]] = []
        self._seed = 0
        self._native: dict[str, Any] | None = None
        self._env: InspectEnvironment | None = None
        self._adjudication_targets: list[dict[str, Any]] = []

        if isinstance(score_policy, str):
            self._score_policy: ScorePolicy = build_score_policy(score_policy)
        elif isinstance(score_policy, dict):
            kind = str(score_policy.get("kind") or score_policy.get("name") or "boolean")
            kwargs = {k: v for k, v in score_policy.items() if k not in {"kind", "name"}}
            self._score_policy = build_score_policy(kind, **kwargs)
        elif score_policy is None:
            self._score_policy = BooleanScorePolicy()
        else:
            self._score_policy = score_policy

        sdk = inspect_sdk_available()
        requested = normalize_inspect_mode(mode) if mode else None

        if eval_log_path is not None or eval_log is not None:
            source: str | Path | dict[str, Any] = (
                eval_log_path if eval_log_path is not None else eval_log  # type: ignore[assignment]
            )
            loaded = load_inspect_eval_log(source)
            full = inspect_log_to_native(
                loaded, score_policy=self._score_policy, include_hidden_targets=True
            )
            self._adjudication_targets = list(full.pop("adjudication_targets", []))
            self._native = inspect_log_to_native(loaded, score_policy=self._score_policy)
            if self._native.get("task"):
                self.task = str(self._native["task"])
            self._mode: InspectMode = requested or "eval_log_import"
            if self._mode == "live_task":
                self._mode = "eval_log_import"
            if self._mode == "scorer_verifier":
                self._native["mode"] = "scorer_verifier"
                self._native["integration_status"] = "scorer_verifier"
            else:
                self._native["mode"] = "eval_log_import"
                self._native["integration_status"] = "eval_log_import"
        elif requested == "scorer_verifier" and not sdk:
            raise ImportError(
                "scorer_verifier mode requires inspect-ai or an eval_log / eval_log_path; "
                "install with: pip install 'verifierlab[inspect]'"
            )
        elif sdk:
            self._env = InspectEnvironment(
                task=inspect_task,
                model=model,
                version=version,
                score_policy=self._score_policy,
            )
            self._mode = requested or "live_task"
            if self._mode == "eval_log_import":
                raise ValueError("eval_log_import requires eval_log or eval_log_path")
            if inspect_task is not None:
                self.task = getattr(inspect_task, "name", None) or self.task
        else:
            raise ImportError(
                "InspectAdapter requires either an eval_log / eval_log_path "
                "(eval_log_import) or inspect-ai for live_task / scorer_verifier; "
                "install with: pip install 'verifierlab[inspect]'"
            )

    @property
    def integration_status(self) -> str:
        return self._mode

    @property
    def mode(self) -> str:
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
            "score_policy": self._score_policy.name,
            "hidden_targets": "adjudication_only",
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._steps = []
        if self._env is not None and self._run_on_reset:
            obs = self._env.reset(seed=seed)
            self._env.act({"model": self.model})
            self._native = self._env.finalize()
            self._adjudication_targets = self._env.adjudication_targets()
            return {**obs, "n_samples": len(self._native.get("steps") or [])}
        if self._env is not None:
            return self._env.reset(seed=seed)
        if self._native is not None:
            return {
                "seed": seed,
                "task": self.task,
                "n_samples": len(self._native.get("steps") or []),
                "mode": self._mode,
            }
        return {"seed": seed, "task": self.task, "mode": self._mode}

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        self._steps.append(dict(action))
        if self._env is not None and self._native is None:
            result = self._env.act(action)
            self._native = self._env.finalize()
            self._adjudication_targets = self._env.adjudication_targets()
            if self._mode == "scorer_verifier":
                self._native["mode"] = "scorer_verifier"
                self._native["integration_status"] = "scorer_verifier"
            return result
        resources: dict[str, Any] = {"queries": 1}
        if self._native and isinstance(self._native.get("resources"), dict):
            resources = {**resources, **self._native["resources"]}
        return {
            "observation": {"step": len(self._steps)},
            "reward": 0.0,
            "resources": resources,
        }

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        """EnvironmentTarget alias for :meth:`step`."""
        return self.step(action)

    def finalize(self) -> dict[str, Any]:
        if self._native is not None:
            out = dict(self._native)
            out["seed"] = self._seed
            out["mode"] = self._mode
            out["integration_status"] = self.integration_status
            if self._steps and self._env is None:
                out["steps"] = list(out.get("steps") or []) + list(self._steps)
            for step in out.get("steps") or []:
                if isinstance(step, dict):
                    step.pop("inspect_target", None)
            out.pop("adjudication_targets", None)
            return out
        if self._env is not None:
            return self._env.finalize()
        raise RuntimeError("InspectAdapter has no trajectory; call reset/step first")

    def adjudication_targets(self) -> list[dict[str, Any]]:
        if self._env is not None and not self._adjudication_targets:
            return self._env.adjudication_targets()
        return list(self._adjudication_targets)

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "inspect"}
