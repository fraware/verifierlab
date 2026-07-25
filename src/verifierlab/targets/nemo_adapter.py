"""NeMo Gym-style resource/verifier HTTP adapter (``[nemo]`` extra).

Implements a **real HTTP client** for NeMo Gym resources-server endpoints
(``POST /seed_session``, ``POST /verify``, tool ``POST /<name>``) as documented
by NVIDIA NeMo Gym. CI does not need the NVIDIA stack: a stdlib reference
server in this package speaks the same protocol.

Fixture JSON translation remains available as **log-format regression** only.

Install (no NVIDIA deps; reference server is stdlib)::

    pip install "verifierlab[nemo]"
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from verifierlab.artifacts.records import TrajectoryRecord


def load_nemo_endpoint_payload(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load a NeMo Gym-style endpoint response from a path or dict."""
    if isinstance(source, dict):
        return dict(source)
    path = Path(source)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"NeMo payload must be a JSON object, got {type(data).__name__}")
    return data


def nemo_payload_to_native(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate resource/verifier endpoint JSON into a native trajectory."""
    resources_raw = payload.get("resources")
    resources: dict[str, Any] = resources_raw if isinstance(resources_raw, dict) else {}
    verifications = payload.get("verifications") or payload.get("verifier_results") or []
    steps: list[dict[str, Any]] = []

    for item in payload.get("episodes") or payload.get("rollouts") or []:
        if not isinstance(item, dict):
            continue
        steps.append(
            {
                "op": "nemo_rollout",
                "episode_id": item.get("id") or item.get("episode_id"),
                "actions": item.get("actions") or item.get("steps") or [],
                "observation": item.get("observation") or item.get("obs"),
                "reward": item.get("reward"),
            }
        )

    for idx, ver in enumerate(verifications):
        if not isinstance(ver, dict):
            continue
        steps.append(
            {
                "op": "nemo_verify",
                "verification_id": ver.get("id", idx),
                "accepted": ver.get("accepted", ver.get("passed")),
                "score": ver.get("score"),
                "endpoint": ver.get("endpoint"),
            }
        )

    if not steps and payload.get("action") is not None:
        steps.append(
            {
                "op": "nemo_action",
                "action": payload.get("action"),
                "observation": payload.get("observation"),
                "reward": payload.get("reward"),
            }
        )

    return {
        "schema_version": "1",
        "framework": "nemo_gym",
        "endpoint": payload.get("endpoint") or payload.get("resource_uri"),
        "steps": steps,
        "resources": {
            "endpoint_calls": resources.get("endpoint_calls") or len(steps) or 1,
            "gpu_seconds": resources.get("gpu_seconds"),
            "tokens": resources.get("tokens"),
        },
        "raw_keys": sorted(payload.keys()),
    }


def native_to_nemo_payload(trajectory: dict[str, Any]) -> dict[str, Any]:
    """Rebuild a NeMo-style endpoint payload from a native trajectory (round-trip)."""
    episodes: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    for step in trajectory.get("steps") or []:
        if not isinstance(step, dict):
            continue
        op = step.get("op")
        if op == "nemo_rollout":
            episodes.append(
                {
                    "id": step.get("episode_id"),
                    "actions": step.get("actions") or [],
                    "observation": step.get("observation"),
                    "reward": step.get("reward"),
                }
            )
        elif op == "nemo_verify":
            verifications.append(
                {
                    "id": step.get("verification_id"),
                    "accepted": step.get("accepted"),
                    "score": step.get("score"),
                    "endpoint": step.get("endpoint"),
                }
            )
        elif op == "nemo_action":
            episodes.append(
                {
                    "actions": [step.get("action")],
                    "observation": step.get("observation"),
                    "reward": step.get("reward"),
                }
            )
    return {
        "endpoint": trajectory.get("endpoint"),
        "resources": trajectory.get("resources") or {},
        "episodes": episodes,
        "verifications": verifications,
    }


def _http_json(
    method: str, url: str, body: dict[str, Any] | None = None, *, timeout: float = 10.0
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"NeMo HTTP {method} {url} failed: {exc.code} {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"NeMo HTTP {method} {url} unreachable: {exc}") from exc
    if not raw:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise TypeError(f"NeMo endpoint must return a JSON object, got {type(parsed).__name__}")
    return parsed


class NeMoGymClient:
    """HTTP client for NeMo Gym-style resources / verifier servers."""

    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session_id: str | None = None
        self._calls = 0

    def health(self) -> dict[str, Any]:
        return _http_json("GET", f"{self.base_url}/health", timeout=self.timeout)

    def seed_session(self, body: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = dict(body or {})
        if "session_id" not in payload:
            payload["session_id"] = str(uuid.uuid4())
        result = _http_json("POST", f"{self.base_url}/seed_session", payload, timeout=self.timeout)
        self.session_id = str(result.get("session_id") or payload["session_id"])
        self._calls += 1
        return result

    def call_tool(self, tool: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = dict(body or {})
        if self.session_id and "session_id" not in payload:
            payload["session_id"] = self.session_id
        result = _http_json(
            "POST", f"{self.base_url}/{tool.lstrip('/')}", payload, timeout=self.timeout
        )
        self._calls += 1
        return result

    def verify(self, body: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = dict(body or {})
        if self.session_id and "session_id" not in payload:
            payload["session_id"] = self.session_id
        result = _http_json("POST", f"{self.base_url}/verify", payload, timeout=self.timeout)
        self._calls += 1
        return result


class _NeMoRefHandler(BaseHTTPRequestHandler):
    """Minimal NeMo Gym-compatible resources server (stdlib)."""

    server: NeMoReferenceServer

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw.decode("utf-8") or "{}")
        return data if isinstance(data, dict) else {}

    def _write_json(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/health":
            self._write_json(200, {"status": "ok", "server": "verifierlab-nemo-ref"})
            return
        self._write_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        body = self._read_json()
        sessions = self.server.sessions

        if path == "/seed_session":
            sid = str(body.get("session_id") or uuid.uuid4())
            sessions[sid] = {
                "balance": float(body.get("balance", 500.0)),
                "actions": [],
                "task": body.get("task") or "refund",
            }
            self._write_json(200, {"session_id": sid, "status": "ok"})
            return

        if path == "/act":
            sid = str(body.get("session_id") or "")
            state = sessions.get(sid)
            if state is None:
                self._write_json(400, {"error": "unknown_session"})
                return
            action = body.get("action") if isinstance(body.get("action"), dict) else body
            amount = float(action.get("amount", 0) if isinstance(action, dict) else 0)
            state["balance"] = float(state["balance"]) - amount
            state["actions"].append(action)
            self._write_json(
                200,
                {
                    "observation": {"balance": state["balance"]},
                    "reward": amount,
                    "session_id": sid,
                },
            )
            return

        if path == "/verify":
            sid = str(body.get("session_id") or "")
            state = sessions.get(sid)
            if state is None:
                self._write_json(400, {"error": "unknown_session", "reward": 0.0})
                return
            # Reference policy: approve only if last refund amount <= 100.
            actions = list(state.get("actions") or [])
            last_amount = 0.0
            if actions:
                last = actions[-1]
                if isinstance(last, dict):
                    last_amount = float(last.get("amount", 0))
            accepted = last_amount <= 100.0
            reward = 1.0 if accepted else 0.0
            self._write_json(
                200,
                {
                    "reward": reward,
                    "info": {
                        "accepted": accepted,
                        "last_amount": last_amount,
                        "balance": state.get("balance"),
                        "n_actions": len(actions),
                    },
                    "session_id": sid,
                },
            )
            return

        self._write_json(404, {"error": "not_found", "path": path})


class NeMoReferenceServer(ThreadingHTTPServer):
    """Threading HTTP server exposing NeMo Gym-style endpoints."""

    allow_reuse_address = True

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
        super().__init__((host, port), _NeMoRefHandler)

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host!s}:{int(port)}"

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="nemo-ref", daemon=True)
        thread.start()
        return thread


class NeMoGymAdapter:
    """Live HTTP adapter for NeMo Gym-style resource/verifier endpoints.

    Prefer ``base_url=`` pointing at a running resources server (or
    :class:`NeMoReferenceServer`). Fixture payload mode is log-format regression.
    """

    name = "nemo_gym"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        version: str = "0.1",
        base_url: str | None = None,
        payload: dict[str, Any] | None = None,
        payload_path: str | Path | None = None,
        own_server: bool = False,
    ) -> None:
        self.version = version
        self._steps: list[dict[str, Any]] = []
        self._seed = 0
        self._native: dict[str, Any] | None = None
        self._client: NeMoGymClient | None = None
        self._server: NeMoReferenceServer | None = None
        self._mode = "unset"
        self.endpoint = endpoint or "nemo-gym"

        if payload_path is not None or payload is not None:
            loaded = load_nemo_endpoint_payload(
                payload_path if payload_path is not None else payload  # type: ignore[arg-type]
            )
            self._native = nemo_payload_to_native(loaded)
            if self._native.get("endpoint"):
                self.endpoint = str(self._native["endpoint"])
            self._mode = "log_format_regression"
            return

        url = base_url
        if url is None or own_server:
            self._server = NeMoReferenceServer()
            self._server.start_background()
            url = self._server.base_url
            own_server = True
        assert url is not None
        self.endpoint = url
        self._client = NeMoGymClient(url)
        self._mode = "live"
        self._own_server = own_server

    @property
    def integration_status(self) -> str:
        return self._mode

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def capture_config(self) -> dict[str, Any]:
        return {
            "framework": "nemo_gym",
            "version": self.version,
            "endpoint": self.endpoint,
            "integration_status": self.integration_status,
            "mode": self._mode,
            "live_http": self._client is not None,
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._steps = []
        if self._client is not None:
            seeded = self._client.seed_session({"task": "refund", "balance": 500.0, "seed": seed})
            return {"seed": seed, "endpoint": self.endpoint, "session_id": seeded.get("session_id")}
        return {"seed": seed, "endpoint": self.endpoint}

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        self._steps.append(dict(action))
        if self._client is not None:
            op = action.get("op") or action.get("tool") or "act"
            if op == "verify":
                result = self._client.verify(action)
                reward = float(result.get("reward", 0.0))
                return {
                    "observation": result.get("info") or result,
                    "reward": reward,
                    "resources": {"endpoint_calls": self._client._calls},
                    "verifier_endpoint": f"{self.endpoint}/verify",
                }
            tool = "act" if op in {"act", "noop", "refund"} else str(op)
            body = dict(action)
            if tool == "act" and "action" not in body:
                body = {"action": {k: v for k, v in action.items() if k not in {"op", "tool"}}}
                if body["action"].get("amount") is None and action.get("op") == "noop":
                    body["action"] = {"op": "noop", "amount": 0}
            result = self._client.call_tool(tool, body)
            return {
                "observation": result.get("observation") or result,
                "reward": float(result.get("reward", 0.0)),
                "resources": {"endpoint_calls": self._client._calls},
                "verifier_endpoint": f"{self.endpoint}/verify",
            }
        resources: dict[str, Any] = {"endpoint_calls": 1}
        if self._native and isinstance(self._native.get("resources"), dict):
            resources = {
                **resources,
                **{k: v for k, v in self._native["resources"].items() if v is not None},
            }
        return {
            "observation": {"step": len(self._steps)},
            "reward": 0.0,
            "resources": resources,
            "verifier_endpoint": f"{self.endpoint}/verify",
        }

    def finalize(self) -> dict[str, Any]:
        if self._client is not None:
            verify = self._client.verify({})
            raw_info = verify.get("info")
            info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
            accepted = info.get("accepted")
            steps = [
                *self._steps,
                {
                    "op": "nemo_verify",
                    "verification_id": "final",
                    "accepted": accepted,
                    "score": verify.get("reward"),
                    "endpoint": f"{self.endpoint}/verify",
                },
            ]
            return {
                "schema_version": "1",
                "seed": self._seed,
                "endpoint": self.endpoint,
                "framework": "nemo_gym",
                "integration_status": "live",
                "steps": steps,
                "resources": {"endpoint_calls": self._client._calls},
                "verify": verify,
            }
        if self._native is not None:
            out = dict(self._native)
            out["seed"] = self._seed
            out["integration_status"] = self.integration_status
            if self._steps:
                out["steps"] = list(out.get("steps") or []) + list(self._steps)
            return out
        raise RuntimeError("NeMoGymAdapter has no trajectory")

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "nemo_gym"}

    def to_trajectory_record(self) -> TrajectoryRecord:
        traj = self.finalize()
        return TrajectoryRecord(
            trajectory_id=str(traj.get("endpoint") or "nemo"),
            seed=int(traj.get("seed", self._seed)),
            steps=list(traj.get("steps") or []),
            observation={"endpoint": traj.get("endpoint")},
            metadata={"framework": "nemo_gym", "resources": traj.get("resources") or {}},
        )
