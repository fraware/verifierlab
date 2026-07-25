"""OpenEnv adapter (``[openenv]`` extra).

Implements the published OpenEnv HTTP simulation protocol
(``POST /reset``, ``POST /step``, ``GET /state``, ``GET /health``) with:

* an in-repo **reference environment** and stdlib HTTP server (always available)
* a real HTTP client that drives that protocol (same interface production
  OpenEnv servers expose)
* optional wrap of the ``openenv`` package when installed

The PyPI ``openenv`` package is heavy (gradio, openai, …). Conformance tests use
the reference server so CI does not require it; live SDK tests skip when absent.

Install reference path (no extra deps)::

    # always available in base

Optional SDK::

    pip install "verifierlab[openenv]"
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from verifierlab.artifacts.records import TrajectoryRecord


def openenv_sdk_available() -> bool:
    """Return True when the ``openenv`` package is importable."""
    try:
        import openenv  # noqa: F401
    except ImportError:
        return False
    return True


def require_openenv() -> Any:
    """Import ``openenv`` or raise a clear install hint."""
    try:
        import openenv
    except ImportError as exc:
        raise ImportError(
            "OpenEnv SDK wrap requires the openenv package; "
            "install with: pip install 'verifierlab[openenv]'. "
            "The reference HTTP protocol adapter works without it."
        ) from exc
    return openenv


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
        raise RuntimeError(f"OpenEnv HTTP {method} {url} failed: {exc.code} {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"OpenEnv HTTP {method} {url} unreachable: {exc}") from exc
    if not raw:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise TypeError(f"OpenEnv endpoint must return a JSON object, got {type(parsed).__name__}")
    return parsed


class ReferenceOpenEnv:
    """In-process OpenEnv-compatible discrete environment (no external deps)."""

    def __init__(self, *, max_steps: int = 8) -> None:
        self.max_steps = max_steps
        self.episode_id = ""
        self.step_count = 0
        self._state = 0
        self._done = False
        self._seed = 0

    def reset(self, *, seed: int | None = None, episode_id: str | None = None) -> dict[str, Any]:
        self._seed = int(seed or 0)
        self.episode_id = episode_id or str(uuid.uuid4())
        self.step_count = 0
        self._state = 0
        self._done = False
        return {
            "observation": {"state": self._state, "message": "ready"},
            "reward": None,
            "done": False,
        }

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            return {
                "observation": {"state": self._state, "message": "already_done"},
                "reward": 0.0,
                "done": True,
            }
        delta = int(action.get("action", action.get("value", 1)))
        self._state = (self._state + delta) % 4
        self.step_count += 1
        terminated = self._state == 3 or self.step_count >= self.max_steps
        self._done = terminated
        reward = 1.0 if self._state == 3 else 0.0
        return {
            "observation": {"state": self._state, "message": f"echo:{delta}"},
            "reward": reward,
            "done": terminated,
        }

    def state(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "step_count": self.step_count,
            "seed": self._seed,
            "done": self._done,
            "state": self._state,
        }


class _OpenEnvRefHandler(BaseHTTPRequestHandler):
    server: OpenEnvReferenceServer

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
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/health":
            self._write_json(200, {"status": "ok", "server": "verifierlab-openenv-ref"})
            return
        if path == "/state":
            self._write_json(200, self.server.env.state())
            return
        self._write_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        body = self._read_json()
        if path == "/reset":
            seed = body.get("seed")
            episode_id = body.get("episode_id")
            result = self.server.env.reset(
                seed=int(seed) if seed is not None else None,
                episode_id=str(episode_id) if episode_id else None,
            )
            self._write_json(200, result)
            return
        if path == "/step":
            action = body.get("action") if isinstance(body.get("action"), dict) else body
            if not isinstance(action, dict):
                action = {"action": 0}
            result = self.server.env.step(action)
            self._write_json(200, result)
            return
        self._write_json(404, {"error": "not_found", "path": path})


class OpenEnvReferenceServer(ThreadingHTTPServer):
    """HTTP server exposing OpenEnv simulation endpoints for a reference env."""

    allow_reuse_address = True

    def __init__(self, host: str = "127.0.0.1", port: int = 0, *, max_steps: int = 8) -> None:
        self.env = ReferenceOpenEnv(max_steps=max_steps)
        super().__init__((host, port), _OpenEnvRefHandler)

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host!s}:{int(port)}"

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="openenv-ref", daemon=True)
        thread.start()
        return thread


class OpenEnvHttpClient:
    """HTTP client for the OpenEnv simulation protocol (``/reset`` ``/step`` ``/state``)."""

    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def health(self) -> dict[str, Any]:
        return _http_json("GET", f"{self.base_url}/health", timeout=self.timeout)

    def reset(self, *, seed: int | None = None, **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = dict(kwargs)
        if seed is not None:
            body["seed"] = seed
        return _http_json("POST", f"{self.base_url}/reset", body, timeout=self.timeout)

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        return _http_json("POST", f"{self.base_url}/step", {"action": action}, timeout=self.timeout)

    def state(self) -> dict[str, Any]:
        return _http_json("GET", f"{self.base_url}/state", timeout=self.timeout)


class OpenEnvEnvironment:
    """Native :class:`~verifierlab.api.protocols.EnvironmentTarget` over OpenEnv HTTP."""

    def __init__(
        self,
        client: OpenEnvHttpClient,
        *,
        env_name: str = "reference",
        max_steps: int = 200,
    ) -> None:
        self._client = client
        self.env_name = env_name
        self.max_steps = max_steps
        self._seed = 0
        self._step_count = 0
        self._done = False
        self._actions: list[dict[str, Any]] = []
        self._last_obs: Any = None
        self._episode_reward = 0.0

    @classmethod
    def from_reference(
        cls, *, max_steps: int = 8
    ) -> tuple[OpenEnvEnvironment, OpenEnvReferenceServer]:
        """Start a reference server and return ``(env, server)``; caller must shut down."""
        server = OpenEnvReferenceServer(max_steps=max_steps)
        server.start_background()
        client = OpenEnvHttpClient(server.base_url)
        return cls(client, env_name="verifierlab-reference", max_steps=max_steps), server

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._step_count = 0
        self._done = False
        self._actions = []
        self._episode_reward = 0.0
        result = self._client.reset(seed=seed)
        obs = result.get("observation")
        self._last_obs = obs
        return {
            "seed": seed,
            "env_name": self.env_name,
            "observation": obs,
            "info": {"state": self._client.state()},
        }

    def act(self, action: dict[str, Any]) -> dict[str, Any]:
        if self._done:
            raise RuntimeError("episode already finished")
        clean = {k: v for k, v in action.items() if not str(k).startswith("_")}
        self._actions.append(dict(clean))
        result = self._client.step(clean)
        obs = result.get("observation")
        reward = float(result.get("reward") or 0.0)
        done = bool(result.get("done"))
        self._last_obs = obs
        self._step_count += 1
        self._episode_reward += reward
        if done or self._step_count >= self.max_steps:
            self._done = True
        return {
            "observation": obs,
            "reward": reward,
            "done": self._done,
            "terminated": done,
            "truncated": False,
            "info": {},
            "resources": {"steps": 1, "env_steps": self._step_count},
        }

    def finalize(self) -> dict[str, Any]:
        self._done = True
        return {
            "schema_version": "1",
            "seed": self._seed,
            "env_name": self.env_name,
            "steps": list(self._actions),
            "observation": self._last_obs
            if isinstance(self._last_obs, dict)
            else {"value": self._last_obs},
            "episode_reward": self._episode_reward,
            "n_steps": self._step_count,
            "framework": "openenv",
            "integration_status": "live",
            "state": self._client.state(),
        }

    def snapshot(self) -> bytes:
        payload = {
            "seed": self._seed,
            "step_count": self._step_count,
            "done": self._done,
            "actions": self._actions,
            "last_obs": self._last_obs,
            "episode_reward": self._episode_reward,
            "env_name": self.env_name,
            "max_steps": self.max_steps,
            "remote_state": self._client.state(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def restore(self, snapshot: bytes) -> None:
        state = json.loads(snapshot.decode("utf-8"))
        self._seed = int(state["seed"])
        self._step_count = int(state["step_count"])
        self._done = bool(state["done"])
        self._actions = list(state["actions"])
        self._last_obs = state["last_obs"]
        self._episode_reward = float(state["episode_reward"])
        self.env_name = str(state["env_name"])
        self.max_steps = int(state["max_steps"])
        # Replay through HTTP protocol for best-effort fidelity.
        self._client.reset(seed=self._seed)
        for action in self._actions:
            self._client.step(action)

    def to_trajectory_record(self) -> TrajectoryRecord:
        traj = self.finalize()
        obs_raw = traj.get("observation")
        observation: dict[str, Any] = obs_raw if isinstance(obs_raw, dict) else {}
        return TrajectoryRecord(
            trajectory_id=self.env_name,
            seed=self._seed,
            steps=list(traj.get("steps") or []),
            observation=observation,
            metadata={"framework": "openenv", "state": traj.get("state")},
        )


class OpenEnvAdapter:
    """EnvAdapter over the OpenEnv HTTP protocol (reference server by default)."""

    name = "openenv"

    def __init__(
        self,
        *,
        env_name: str = "reference",
        version: str = "0.1",
        base_url: str | None = None,
        max_steps: int = 8,
    ) -> None:
        self.env_name = env_name
        self.version = version
        self.max_steps = max_steps
        self._steps: list[dict[str, Any]] = []
        self._seed = 0
        self._server: OpenEnvReferenceServer | None = None
        self._env: OpenEnvEnvironment | None = None
        self._sdk = None
        if openenv_sdk_available():
            try:
                import openenv as _openenv

                self._sdk = _openenv
            except ImportError:
                self._sdk = None

        if base_url is not None:
            client = OpenEnvHttpClient(base_url)
            self._env = OpenEnvEnvironment(client, env_name=env_name, max_steps=max_steps)
            self._mode = "live"
        else:
            env, server = OpenEnvEnvironment.from_reference(max_steps=max_steps)
            self._env = env
            self._server = server
            self.env_name = env.env_name
            self._mode = "live"

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
            "framework": "openenv",
            "version": self.version,
            "env_name": self.env_name,
            "sdk_available": self._sdk is not None,
            "integration_status": self.integration_status,
            "mode": self._mode,
            "protocol": "http_simulation",
        }

    def reset(self, *, seed: int) -> dict[str, Any]:
        self._seed = seed
        self._steps = []
        assert self._env is not None
        return self._env.reset(seed=seed)

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        self._steps.append(dict(action))
        assert self._env is not None
        # Map conformance noop to a discrete action.
        clean = dict(action)
        if clean.get("op") == "noop" and "action" not in clean:
            clean = {"action": 1}
        result = self._env.act(clean)
        return {
            "observation": result.get("observation"),
            "reward": result.get("reward", 0.0),
            "resources": result.get("resources", {"steps": 1}),
            "terminated": result.get("terminated", False),
            "truncated": result.get("truncated", False),
            "done": result.get("done", False),
        }

    def finalize(self) -> dict[str, Any]:
        assert self._env is not None
        traj = self._env.finalize()
        if not traj.get("steps"):
            traj["steps"] = list(self._steps)
        return traj

    def map_timeout(self, exc: Exception) -> dict[str, Any]:
        return {"status": "timeout", "error": str(exc), "framework": "openenv"}
