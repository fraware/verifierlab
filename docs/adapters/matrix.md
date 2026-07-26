# Adapter matrix

Generated from `registry/adapter-matrix-v1.json`.
Do not hand-edit this page; run `python scripts/generate_adapter_matrix.py`.

Fixture-only paths are never labeled live. EnvAssure is not-live until the package is installable. RLlib is integration conformance only.

| Adapter | Extra | Status | Live vs fixture | Versions | CI | Limitations |
| ------- | ----- | ------ | --------------- | -------- | -- | ----------- |
| native | (base) | live | live | python `>=3.11,<3.14` | required | No OS sandbox / soundness claim |
| gymnasium | `[gym]` | live | live | gymnasium `>=0.29,<1.3` | release-qualified | Legacy gym; full RL stacks |
| inspect | `[inspect]` | live | live_task/scorer_verifier live when SDK present; eval_log_import fixture | inspect-ai `>=0.3.200,<0.4` | release-qualified | Fixture labeled as live |
| openenv | `[openenv]` | live-or-fixture | live HTTP reference; prefer official client when present | openenv `>=0.4,<0.5` | release-qualified | Hosted Spaces automation |
| harbor | `[harbor]` | fixture-or-live | ATIF fixture always; live SDK on Py>=3.12 | harbor `>=0.17,<0.21`, python `>=3.12` | optional | Full Harbor orchestration |
| nemo | `[nemo]` | live | live vs in-repo reference HTTP server | — | fixture | NVIDIA training containers |
| trainer | `[trainer]` | live | live (broker-metered trainer loop in base) | — | fixture | Heavy external SDKs |
| envassure | `[envassure]` | not-live | not-live | envassure `>=0.2.0b1,<0.3` | hard-fail-when-installable | Fixture-as-live |
| rllib | `[rllib]` | partial | live-when-ray-installed (integration conformance) | ray[rllib] `==2.48.0` | skip-if-missing | Capability / SOTA results |

## Notes

- **gymnasium:** Legacy gym is not a beta claim.
- **inspect:** eval_log_import is fixture/regression and never labeled live.
- **openenv:** HTTP reference path works without the heavy SDK.
- **nemo:** Live against in-repo reference HTTP server.
- **trainer:** [rl]/[trainer] reserved for heavy SDKs; base loop is live.
- **envassure:** Package not yet published on PyPI; protocol/fixture tests only. Never claim live from fixtures.
- **rllib:** Integration conformance only — not a capability claim. Image is partial-qualification.
