# Contributing environments

How to add environment targets used by campaigns and packs.

## Goals

- Provide reset/step (or equivalent) with deterministic seeding where claimed.
- Capture trajectory metadata needed for reproduction.
- Keep hidden reference material out of worker-visible state.

## Paths

- In-tree fakes / tutorials: `verifierlab.targets.fake`
- Gymnasium: `verifierlab.targets.gym_adapter` behind `[gym]`
- OpenEnv / HTTP: `verifierlab.targets.openenv_adapter`
- Other adapters: see [adapters overview](../adapters.md)

## Required checks

- [ ] Termination vs truncation semantics documented and tested when applicable.
- [ ] Invalid actions and non-JSON observations handled explicitly (no silent coerce).
- [ ] Seeds and wrapper stacks recorded when replay is claimed.
- [ ] Worker fixtures have no hidden labels.
- [ ] Live vs fixture status is honest in docs and matrix rows.

## Do not

- Embed adjudication ground truth in environment observations shipped to attackers.
- Mark fixture protocol tests as live integration.
- Add heavy SDKs to the base install — use extras.

## Related

- [docs/adapters.md](../adapters.md)
- [docs/getting-started.md](../getting-started.md)
- [Adapters guide](adapters.md)
