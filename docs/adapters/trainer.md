# Trainer adapter

## Supported versions

- Extra: `[rl]` / `[trainer]` (alias; heavy trainer SDKs remain optional)
- Base package includes broker-wired `TrainerAdapter` surfaces

## Live vs fixture

**Live** for the broker-only trainer step loop. Heavy external trainer SDKs are
not implied by installing the alias extra today.

## Boundary

Rewards / verifier feedback only via the metered broker. No hidden adjudication
channel for trainers. GT isolation is mandatory.

## Mapping

| Trainer surface | VerifierLab |
| --- | --- |
| `start` / `learn` / `save` / `load` | Current adapter aliases |
| Broker query | Metered verifier feedback |

## Unsupported semantics

- Full RLlib/Ray capability results (see RLlib page; post-qualification)
- Claiming SOTA RL agent performance

## Conformance command

```bash
uv run pytest tests/test_adapters_scale.py -q
uv run pytest tests/test_adapter_conformance.py -q
```

## CI status

Covered by VALAB-09 adapter matrix / fixture jobs.

## Example

Trainer adapter unit/integration tests under `tests/`.

## Troubleshooting

- Missing heavy SDK: expected; install future `[rllib]` only after qualification
- Budget overruns: inspect provenance ledger / voucher merge events
