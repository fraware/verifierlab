# RLlib adapter

## Supported versions

- Extra: `[rllib]` with exact pin `ray[rllib]==2.48.0`
- Image: `ghcr.io/fraware/verifierlab-rllib` — **partial qualification**
  (integration conformance, not a capability claim)

## Live vs fixture

**Live when Ray is installed.** PR-tier tiny tests skip if `ray` is missing.
Presented as **integration conformance**, not a capability / SOTA result.

Protocol: `initialize` / `train` / `act` / `checkpoint` / `restore` / `freeze` /
`evaluate` / `close` (aliases: `start` / `learn` / `save` / `load`).

## Boundary

Ray/RLlib + broker-wired env only (`BrokerRewardEnv`). Must not contain
adjudicator secrets. Rewards only via broker; freeze before holdout.

## Mapping

| RLlib | VerifierLab |
| --- | --- |
| PPO (first) | `trainers.rllib_adapter.RLlibPPOAdapter` |
| Env rewards | `trainers.rllib_env.BrokerRewardEnv` |
| Checkpoint / restore / freeze | Trainer protocol |

## Unsupported semantics

- Capability / SOTA claims from conformance tiers
- Shipping the RLlib image as fully release-qualified before end-to-end smoke

## Conformance command

```bash
uv sync --extra rllib
uv run pytest -m rllib -q
```

## CI status

Optional soft-fail in `adapters.yml` (skip/soft when Ray missing). Image marked
`partial-qualification`.

## Example

```bash
cd examples/v6_rllib
pip install 'verifierlab[rllib]'
./run.sh && ./verify.sh
```

## Troubleshooting

- Seeing stub exit 2 on older images: rebuild after Milestone C landing
- Budget errors: exact query/env-step budgets are enforced by `BrokerRewardEnv`
