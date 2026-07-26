# Harbor adapter

## Supported versions

- Extra: `[harbor]`
- `harbor>=0.17,<0.21`
- Requires Python `>=3.12`

## Live vs fixture

**Fixture-or-live.** ATIF parse/validate paths are fixture-friendly; live Harbor
SDK paths run when installed. Not currently a hard-fail release gate.

## Boundary

Stateful Harbor episodes must not expose adjudicator secrets to attack workers.

## Mapping

| Harbor | VerifierLab |
| --- | --- |
| ATIF types | Transcript / episode import |
| Stateful episode | EnvironmentTarget-compatible session |

## Unsupported semantics

- In-process Harbor sandbox/agent orchestration as a VerifierLab claim

## Conformance command

```bash
uv sync --extra harbor   # Python >=3.12
uv run pytest -m harbor -q
```

## CI status

Optional soft-fail in `adapters.yml` (`release_required: false`).

## Example

Fixture regression under `tests/test_adapter_fixtures.py`.

## Troubleshooting

- Python 3.11 hosts: Harbor extra is marker-gated; use 3.12+
- Missing harbor: tests skip with an explicit reason (never stub pass)
