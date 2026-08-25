# Adapter matrix

Generated from `registry/adapter-matrix-v1.json`.
Do not hand-edit this page; run `python scripts/generate_adapter_matrix.py`.

Statuses are live-tested / protocol-reference-tested / fixture-only / unsupported. Fixture-only paths are never labeled live-tested. EnvAssure remains fixture-only (not installable) until the package is on PyPI.

Adapter contract `verifierlab.adapter.contract` v1.0.

| Adapter | Extra | Status | Live vs fixture | Versions | CI | Limitations |
| ------- | ----- | ------ | --------------- | -------- | -- | ----------- |
| native | (base) | live-tested | live-tested | python `>=3.11,<3.14` | required | No OS sandbox / soundness claim |
| gymnasium | `[gym]` | live-tested | live-tested | gymnasium `>=0.29,<1.3` | release-qualified | Legacy gym; full RL stacks |
| inspect | `[inspect]` | live-tested | live_task/scorer_verifier live-tested when SDK present; eval_log_import fixture-only | inspect-ai `>=0.3.200,<0.4` | release-qualified | Do not label fixture eval_log_import as live-tested |
| openenv | `[openenv]` | protocol-reference-tested | protocol-reference-tested (HTTP reference; prefer official client when present) | openenv `>=0.4,<0.5` | release-qualified | Hosted Spaces automation |
| harbor | `[harbor]` | fixture-only | fixture-only (ATIF fixture always; optional SDK path on Py>=3.12 is not a matrix live claim) | harbor `>=0.17,<0.21`, python `>=3.12` | optional | Full Harbor orchestration |
| nemo | `[nemo]` | protocol-reference-tested | protocol-reference-tested (in-repo reference HTTP server) | — | fixture | NVIDIA training containers |
| trainer | `[trainer]` | live-tested | live-tested (broker-metered trainer loop in base) | — | fixture | Heavy external SDKs |
| envassure | `[envassure]` | fixture-only | fixture-only | envassure `>=0.2.0b1,<0.3` | hard-fail-when-installable | Fixture-as-live |
| rllib | `[rllib]` | protocol-reference-tested | protocol-reference-tested when ray installed (integration conformance; skip-if-missing) | ray[rllib] `==2.48.0` | skip-if-missing | Capability / leaderboard-style results |
| objectstore | `[objectstore]` | live-tested | live-tested with boto3 (scoped prefix CAS); local filesystem stand-in always | boto3 `>=1.34` | optional | Default remains filesystem CAS |

## Notes

- **gymnasium:** Legacy gym is not a release claim.
- **inspect:** eval_log_import is fixture/regression and never labeled live-tested.
- **openenv:** HTTP reference path works without the heavy SDK.
- **nemo:** Exercised against in-repo reference HTTP server, not NVIDIA training containers.
- **trainer:** [rl]/[trainer] reserved for heavy SDKs; base loop is live-tested.
- **envassure:** Package not yet published on PyPI; protocol/fixture tests only. Never claim live-tested from fixtures.
- **rllib:** Integration conformance only — not a capability claim. Image is partial-qualification.
- **objectstore:** Scoped-prefix object-store CAS tests cover security-grade key isolation.
