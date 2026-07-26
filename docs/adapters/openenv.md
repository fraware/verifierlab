# OpenEnv adapter

## Supported versions

- Extra: `[openenv]` (optional heavy SDK)
- `openenv>=0.4,<0.5` when claiming live SDK path
- HTTP `/reset` `/step` `/state` `/health` `/identity` `/schemas` reference path
  works without the SDK

## Live vs fixture

**Live** against the in-repo reference HTTP server (always). Prefer the official
client when the `openenv` package installs cleanly; raw HTTP remains the
compatibility path (timeout/retry).

Captured: identity, reset/step/state, episode ID, schemas, health, timeout/retry,
trajectory, snapshot capability.

## Boundary

Episode state and schemas are captured as public artifacts. Adjudication holds
hidden validity. Timeouts/retries must not leak labels to workers.

## Mapping

| OpenEnv | VerifierLab |
| --- | --- |
| `/reset` `/step` `/state` | EnvironmentTarget HTTP protocol |
| Health / identity / schemas | Adapter metadata |
| Snapshot / trajectory | Trajectory capture |

## Unsupported semantics

- Hugging Face Spaces / Docker provider automation as a product claim
- Treating a fixture HTTP path as a hosted OpenEnv deployment

## Conformance command

```bash
uv sync --extra openenv
uv run pytest -m openenv -q
```

## CI status

Release-qualified hard-fail in `adapters.yml`.

## Example

```bash
cd examples/v4_openenv
pip install 'verifierlab[openenv]'  # optional
./run.sh && ./verify.sh
```

Optional containerized smoke via the CLI image after publish.

## Troubleshooting

- SDK install failures: use the HTTP reference path; matrix must say live reference / not SDK-live
- Health check failures: confirm reference server bind address and timeout config
