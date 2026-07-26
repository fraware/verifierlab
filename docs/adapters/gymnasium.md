# Gymnasium adapter

## Supported versions

- Extra: `[gym]`
- `gymnasium>=0.29,<1.3`

## Live vs fixture

**Live** when `gymnasium` is installed. Release-qualified path uses gymnasium
only; legacy `gym` is **not** a beta claim (compat import removed from the
qualified path).

Matrix coverage: custom deterministic env, CartPole (skip if missing), Dict
spaces, terminated/truncated, invalid action, non-JSON obs, fixed-seed replay,
wrapper stack capture.

## Boundary

Env observations/actions flow through the worker. Hidden labels remain
adjudication-only. Trainer loops must meter verifier queries via the broker.

## Mapping

| Gymnasium | VerifierLab |
| --- | --- |
| `gymnasium.Env` | `EnvironmentTarget` via `gym_adapter` |
| `terminated` / `truncated` | Episode end mapping |
| spaces / wrapper stack | Captured in trajectory / profile metadata |

## Unsupported semantics

- Full RL training stacks (Ray/RLlib) are out of scope for `[gym]` (see `[rllib]`)
- Does not claim Gymnasium multi-agent APIs
- Does not claim legacy `gym`

## Conformance command

```bash
uv sync --extra gym
uv run pytest -m gym -q
uv run pytest tests/test_adapter_conformance.py -q
```

## CI status

Release-qualified hard-fail in `adapters.yml`.

## Example

```bash
cd examples/v2_gymnasium
pip install 'verifierlab[gym]'
./run.sh && ./verify.sh
```

## Troubleshooting

- `ImportError: gymnasium`: `pip install 'verifierlab[gym]'`
- Dict spaces / invalid actions: covered by `tests/test_gym_live.py`
