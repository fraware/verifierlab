# NeMo Gym HTTP adapter

## Supported versions

- Extra: `[nemo]` (no NVIDIA stack required for the reference path)
- In-repo HTTP client + stdlib reference resources server

## Live vs fixture

**Fixture / reference-server live.** CI exercises the client against a local
reference HTTP server. Not an NVIDIA training-container claim.

## Boundary

HTTP trajectories are public worker artifacts. Hidden validity stays in
adjudication.

## Mapping

| NeMo Gym HTTP | VerifierLab |
| --- | --- |
| Resources server | Reference environment |
| Client reset/step | EnvironmentTarget |

## Unsupported semantics

- NVIDIA training containers / Ray loops
- NeMo product hosting

## Conformance command

```bash
uv sync --extra nemo
uv run pytest tests/test_adapter_fixtures.py -q
```

## CI status

Fixture path covered by adapter fixture jobs; see `docs/adapters.md`.

## Example

Reference server tests in the adapter fixture suite.

## Troubleshooting

- Port conflicts: choose a free bind port for the reference server
- Do not label NVIDIA-container absence as an adapter failure
