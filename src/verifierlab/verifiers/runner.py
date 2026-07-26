"""Subprocess boundary for packaged native verifiers (Milestone B).

``PythonVerifierRunner`` isolates verifier execution from the attack-plane
process: structured stdin/stdout JSON, timeouts, best-effort CPU/memory
limits, deterministic environment variables, source/config digests, and an
explicit ban on label/vault imports in the child.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from verifierlab.api.decision import Decision, DecisionKind
from verifierlab.api.verifier import get_verifier_spec, normalize_decision
from verifierlab.artifacts.canonical import digest_of, sha256_digest
from verifierlab.verifiers.profile import VerifierProfile

_CHILD_SCRIPT = textwrap.dedent(
    """
    import json
    import os
    import sys

    # Fail closed: refuse label / vault imports in the child process.
    _DENIED = ("verifierlab.labels", "verifierlab.labels.vault")

    class _DenyLabelImport:
        def find_spec(self, fullname, path=None, target=None):
            if fullname in _DENIED or fullname.startswith("verifierlab.labels."):
                raise ImportError(
                    f"packaged verifier child refused import of {fullname!r} "
                    "(no hidden-label access)"
                )
            return None

    sys.meta_path.insert(0, _DenyLabelImport())

    def _load(ref: str):
        import importlib
        if ":" in ref:
            module_name, attr = ref.split(":", 1)
        else:
            module_name, attr = ref.rsplit(".", 1)
        module = importlib.import_module(module_name)
        obj = module
        for part in attr.split("."):
            obj = getattr(obj, part)
        return obj

    def main() -> int:
        raw = sys.stdin.read()
        try:
            request = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as exc:
            json.dump(
                {
                    "status": "error",
                    "reason_codes": ["invalid_stdin_json", type(exc).__name__],
                    "raw": str(exc),
                },
                sys.stdout,
            )
            return 2
        ref = os.environ.get("VALAB_VERIFIER_REF") or request.get("ref")
        if not ref:
            json.dump(
                {
                    "status": "error",
                    "reason_codes": ["missing_verifier_ref"],
                },
                sys.stdout,
            )
            return 2
        trajectory = request.get("trajectory")
        if not isinstance(trajectory, dict):
            json.dump(
                {
                    "status": "error",
                    "reason_codes": ["missing_trajectory"],
                },
                sys.stdout,
            )
            return 2
        try:
            fn = _load(str(ref))
            raw_out = fn(trajectory)
        except Exception as exc:  # noqa: BLE001 — map to typed error
            json.dump(
                {
                    "status": "error",
                    "reason_codes": ["verifier_exception", type(exc).__name__],
                    "raw": str(exc),
                },
                sys.stdout,
            )
            return 1
        if hasattr(raw_out, "model_dump"):
            payload = raw_out.model_dump(mode="json")
        elif isinstance(raw_out, dict):
            payload = raw_out
        elif isinstance(raw_out, bool):
            payload = {"accepted": raw_out, "status": "accept" if raw_out else "reject"}
        elif isinstance(raw_out, (int, float)) and not isinstance(raw_out, bool):
            payload = {"score": float(raw_out)}
        elif isinstance(raw_out, str):
            payload = {"status": raw_out}
        else:
            payload = {
                "status": "error",
                "reason_codes": ["unrecognized_decision_type"],
                "raw": repr(raw_out),
            }
        json.dump(payload, sys.stdout)
        return 0

    if __name__ == "__main__":
        raise SystemExit(main())
    """
).lstrip()


def _resource_preexec(
    *,
    cpu_seconds: float | None,
    memory_bytes: int | None,
) -> Callable[[], None] | None:
    """Unix-only RLIMIT preexec; Windows returns None (timeout-only)."""
    if os.name == "nt":
        return None
    try:
        import resource
    except ImportError:
        return None

    def _apply() -> None:
        if cpu_seconds is not None and cpu_seconds > 0:
            soft = max(1, int(cpu_seconds))
            resource.setrlimit(resource.RLIMIT_CPU, (soft, soft))
        if memory_bytes is not None and memory_bytes > 0:
            soft = int(memory_bytes)
            # Address-space limit when available.
            limit_name = getattr(resource, "RLIMIT_AS", None)
            if limit_name is not None:
                resource.setrlimit(limit_name, (soft, soft))

    return _apply


def _deterministic_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal, deterministic child environment (no host secrets by default)."""
    env = {
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),  # Windows Python needs this
        "WINDIR": os.environ.get("WINDIR", ""),
    }
    # Preserve PYTHONPATH / virtualenv so packaged refs remain importable.
    for key in ("PYTHONPATH", "VIRTUAL_ENV", "PYTHONHOME", "CONDA_PREFIX"):
        if key in os.environ:
            env[key] = os.environ[key]
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    # Drop empty Windows placeholders on non-Windows.
    return {k: v for k, v in env.items() if v}


@dataclass
class PythonVerifierRunner:
    """Subprocess runner for packaged native Python verifiers.

    Trusted local ``@verifier`` callables may still be invoked in-process via
    :class:`~verifierlab.verifiers.broker.VerifierBroker`. Packaged / untrusted
    refs should prefer this runner.
    """

    ref: str
    timeout_s: float = 30.0
    cpu_seconds: float | None = None
    memory_bytes: int | None = None
    config: dict[str, Any] = field(default_factory=dict)
    env_extra: dict[str, str] = field(default_factory=dict)
    profile: VerifierProfile | None = None
    _source_digest: str | None = field(default=None, init=False, repr=False)
    _config_digest: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._config_digest = digest_of(dict(self.config))
        self._source_digest = self._compute_source_digest()
        if self.profile is None:
            self.profile = self._build_profile()

    def _compute_source_digest(self) -> str:
        try:
            from verifierlab.plugins.loader import load_object

            fn = load_object(self.ref)
            try:
                spec = get_verifier_spec(fn)
                return spec.callable_digest
            except AttributeError:
                return digest_of(
                    {
                        "module": getattr(fn, "__module__", "<unknown>"),
                        "qualname": getattr(fn, "__qualname__", self.ref),
                    }
                )
        except Exception:
            return sha256_digest(self.ref.encode("utf-8"))

    def _build_profile(self) -> VerifierProfile:
        try:
            from verifierlab.plugins.loader import load_object

            fn = load_object(self.ref)
            return VerifierProfile.for_callable(
                fn,
                name=self.ref,
                config=self.config,
                applicability={"isolation": "subprocess", "runner": "PythonVerifierRunner"},
                access_surface={"may_read_hidden_labels": False, "subprocess": True},
            )
        except Exception:
            return VerifierProfile(
                name=self.ref,
                implementation_digest=self._source_digest or sha256_digest(self.ref.encode()),
                config_digest=self._config_digest or digest_of({}),
                applicability={
                    "isolation": "subprocess",
                    "runner": "PythonVerifierRunner",
                    "decision_space": "binary",
                    "target_kinds": ["python", "native", "packaged"],
                    "requires_hidden_labels": False,
                },
                access_surface={
                    "inputs": ["trajectory", "observation"],
                    "may_read_hidden_labels": False,
                    "may_import_label_vault": False,
                    "may_read_ground_truth": False,
                    "stdout_protocol": "json_decision",
                    "subprocess": True,
                },
                decision_semantics={
                    "status_set": ["accept", "reject", "abstain", "indeterminate", "error"],
                    "fail_closed": True,
                },
            )

    @property
    def source_digest(self) -> str:
        return self._source_digest or ""

    @property
    def config_digest(self) -> str:
        return self._config_digest or digest_of({})

    def digests(self) -> dict[str, str]:
        return {
            "source_digest": self.source_digest,
            "config_digest": self.config_digest,
            "profile_digest": self.profile.content_digest() if self.profile else "",
        }

    def invoke(self, trajectory: dict[str, Any]) -> Decision:
        """Synchronously invoke the verifier in a subprocess."""
        request = {"trajectory": trajectory, "ref": self.ref}
        env = _deterministic_env(self.env_extra)
        env["VALAB_VERIFIER_REF"] = self.ref
        preexec = _resource_preexec(
            cpu_seconds=self.cpu_seconds if self.cpu_seconds is not None else self.timeout_s,
            memory_bytes=self.memory_bytes,
        )
        with tempfile.TemporaryDirectory(prefix="valab-verifier-") as tmp:
            script_path = Path(tmp) / "child.py"
            script_path.write_text(_CHILD_SCRIPT, encoding="utf-8")
            # Ensure repo / cwd imports resolve for examples.* refs.
            repo_root = Path(__file__).resolve().parents[3]
            py_path = env.get("PYTHONPATH", "")
            parts = [str(repo_root), str(Path.cwd())]
            if py_path:
                parts.append(py_path)
            env["PYTHONPATH"] = os.pathsep.join(parts)
            run_kwargs: dict[str, Any] = {
                "input": json.dumps(request, sort_keys=True),
                "capture_output": True,
                "text": True,
                "timeout": self.timeout_s,
                "env": env,
                "cwd": str(Path.cwd()),
                "check": False,
            }
            # preexec_fn is Unix-only; Windows relies on timeout (+ soft limits).
            if preexec is not None and os.name != "nt":
                run_kwargs["preexec_fn"] = preexec
            try:
                proc = subprocess.run(
                    [sys.executable, str(script_path)],
                    **run_kwargs,
                )
            except subprocess.TimeoutExpired as exc:
                return Decision(
                    kind=DecisionKind.ERROR,
                    accepted=None,
                    reason_codes=["timeout", "subprocess_timeout"],
                    raw=str(exc),
                )
            except OSError as exc:
                return Decision(
                    kind=DecisionKind.ERROR,
                    accepted=None,
                    reason_codes=["subprocess_os_error", type(exc).__name__],
                    raw=str(exc),
                )
        stdout = (proc.stdout or "").strip()
        if not stdout:
            return Decision(
                kind=DecisionKind.ERROR,
                accepted=None,
                reason_codes=["empty_stdout", f"exit_{proc.returncode}"],
                raw=(proc.stderr or "")[:2000],
            )
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return Decision(
                kind=DecisionKind.ERROR,
                accepted=None,
                reason_codes=["invalid_stdout_json", f"exit_{proc.returncode}"],
                raw=stdout[:2000],
            )
        decision = normalize_decision(payload)
        if proc.returncode not in (0, 1) and decision.kind is not DecisionKind.ERROR:
            return decision.model_copy(
                update={
                    "kind": DecisionKind.ERROR,
                    "accepted": None,
                    "reason_codes": [
                        *list(decision.reason_codes),
                        f"exit_{proc.returncode}",
                    ],
                }
            )
        return decision

    async def ainvoke(self, trajectory: dict[str, Any]) -> Decision:
        """Async adapter: run :meth:`invoke` in a worker thread."""
        return await asyncio.to_thread(self.invoke, trajectory)

    def as_callable(self) -> Callable[[dict[str, Any]], Decision]:
        """Return a broker-compatible sync callable."""

        def _call(trajectory: dict[str, Any]) -> Decision:
            return self.invoke(trajectory)

        _call.__name__ = f"subprocess:{self.ref}"
        _call.__qualname__ = _call.__name__
        _call.__module__ = __name__
        if self.profile is not None:
            # Lightweight marker for broker / inspect without full @verifier wrap.
            _call.__verifier_runner__ = self  # type: ignore[attr-defined]
        return _call

    @classmethod
    def from_ref(
        cls,
        ref: str,
        *,
        timeout_s: float = 30.0,
        config: dict[str, Any] | None = None,
        cpu_seconds: float | None = None,
        memory_bytes: int | None = None,
    ) -> PythonVerifierRunner:
        return cls(
            ref=ref,
            timeout_s=timeout_s,
            config=dict(config or {}),
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
        )


def prefers_subprocess_isolation(
    *,
    kind: str | None = None,
    config: dict[str, Any] | None = None,
) -> bool:
    """Whether a campaign verifier target should use :class:`PythonVerifierRunner`."""
    cfg = dict(config or {})
    isolation = str(cfg.get("isolation") or cfg.get("runner") or "").lower()
    if isolation in {"subprocess", "python_verifier_runner", "packaged"}:
        return True
    if bool(cfg.get("packaged")):
        return True
    kind_l = str(kind or "").lower()
    return kind_l in {"packaged", "subprocess", "python_packaged"}


__all__ = [
    "PythonVerifierRunner",
    "prefers_subprocess_isolation",
]
