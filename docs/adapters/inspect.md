# Inspect adapter

## Supported versions

- Extra: `[inspect]`
- `inspect-ai>=0.3.200,<0.4`

## Live vs fixture

**Modes (explicit, do not collapse):**

| Mode | Status | Notes |
| --- | --- | --- |
| `live_task` (alias `live`) | Live when `inspect-ai` installed | Real Task + `eval()` (mockllm in CI) |
| `scorer_verifier` | Live or log-backed | Score policies → verifier decisions |
| `eval_log_import` (alias `log_format_regression`) | Fixture / regression | Never labeled live |

Score policies: `boolean`, `numeric_threshold`, `categorical_map`,
`multi_score_composition`, `abstention_map`.

## Boundary

Hidden Inspect targets belong in adjudication only. Worker artifacts carry
sample IDs / commitments — not ground-truth labels.

## Mapping

| Inspect surface | VerifierLab |
| --- | --- |
| Task / eval | `live_task` via `inspect_adapter` |
| Scorer | `scorer_verifier` + score policies |
| Eval log | `eval_log_import` |

## Unsupported semantics

- Hosting Inspect’s full product surface
- Treating fixture-only eval-log import as live

## Conformance command

```bash
uv sync --extra inspect
uv run pytest -m inspect -q
```

## CI status

Release-qualified hard-fail in `adapters.yml`. Live paths skip-if-missing with
clear markers when `inspect-ai` is absent.

## Example

```bash
cd examples/v3_inspect
pip install 'verifierlab[inspect]'
./run.sh && ./verify.sh
```

## Troubleshooting

- Missing SDK: install `verifierlab[inspect]`; live tests skip with an explicit reason
- Log import failures: validate eval-log schema version against fixture suite
- Seeing `inspect_target` in worker finalize: file a bug — targets are adjudication-only
