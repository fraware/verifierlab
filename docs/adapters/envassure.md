# EnvAssure adapter

## Supported versions

- Extra: `[envassure]`
- Declared pin: none on the 0.2.0rc line (extra is empty until PyPI publish).
  Intended later: `envassure>=0.2.0b1,<0.3`.
- **Note:** as of the 0.2.0rc line the package is **not yet published** on PyPI.
  The extra name is reserved; a hard pin would break `uv lock` (all-extras).

## Live vs fixture

**Not live** until `envassure` is installable. Protocol/fixture tests under
`tests/integration/envassure/` always run and report `integration_status=not-live`.
Never claim live from fixtures. Live CI hard-fails only when the package installs.

## Boundary

Attackers receive actor observations + public verifier feedback only. Evaluator
state stays in adjudication (`adjudication_evaluator_state()`).

## Mapping

| EnvAssure | VerifierLab |
| --- | --- |
| EnvAssure target API | `EnvAssureTarget` / `EnvAssureAdapter` |
| Evaluator state | Adjudication-only |
| Actor observation | Worker-visible |

## Unsupported semantics

- Any live CI claim before the installability gate is green

## Conformance command

```bash
# Fixture/protocol (always):
uv run pytest tests/integration/envassure -q

# Live (only when package installable):
uv sync --extra envassure
uv run pytest -m envassure -q
```

## CI status

Soft-fail install in `adapters.yml` when unpublishable; fixture suite still runs.
Hard-fail live only when installable.

## Example

```bash
cd examples/v5_envassure
./run.sh && ./verify.sh
```

## Troubleshooting

- If the package is missing on PyPI/index: keep matrix status `not-live`
- Worker artifacts containing `evaluator_state` / `planted_label`: file a P0 leak bug
