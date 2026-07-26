# Maintainers

VerifierLab is maintained by the `fraware` organization and volunteer
contributors. This file lists **subsystem ownership** for reviews and escalation.
GitHub handles marked TBA will be filled as the maintainer set grows; until then
`@fraware` remains the default CODEOWNERS assignee.

## Dual-review policy

Pull requests that touch any of the following require **two approving reviews**
(enforced via branch protection when available; always expected by policy):

| Surface | Paths (representative) |
| ------- | ---------------------- |
| Decisions / typed status | `src/verifierlab/api/decision.py`, decision schemas |
| Labels / vault / freeze / adjudication | `src/verifierlab/labels/` |
| Budgets / metering ledgers | `src/verifierlab/budgets/` |
| Statistics / intervals / StatsPlan | `src/verifierlab/statistics/` |
| Sandbox / Docker isolation | `src/verifierlab/security/sandbox.py`, `security/docker_runner.py` |
| Cryptography / vault keys / secrets | `src/verifierlab/labels/vault.py`, `labels/keyring.py`, `security/secrets.py` |

Reviewers should not approve their own commits. For trust-critical paths, at
least one reviewer should be from Security or a different subsystem than the
author.

## Subsystem owners

| Subsystem | Scope | Owner (GitHub) | Backup |
| --------- | ----- | -------------- | ------ |
| Runtime / campaigns | engine, episode, lifecycle, workers | `@fraware` | TBA |
| Verifiers / broker | profiles, capabilities, broker, runners | `@fraware` | TBA |
| Labels / adjudication | vault, freeze, release, adjudication | `@fraware` | TBA |
| Budgets | budget models, ledgers, vouchers | `@fraware` | TBA |
| Attacks | attack registry, persistent runtime, families | `@fraware` | TBA |
| Adapters / targets | Gym, Inspect, OpenEnv, Harbor, NeMo, trainer | `@fraware` | TBA |
| Statistics | StatsPlan, intervals, power | `@fraware` | TBA |
| Reports | HTML/JSON/CSV builders, a11y | `@fraware` | TBA |
| Security | sandbox, secrets, threat model | `@fraware` | TBA |
| Release / CI | workflows, packaging, images, manifests | `@fraware` | TBA |
| Docs / community | docs site, ROADMAP, registries, good-first | `@fraware` | TBA |
| Benchmarks / packs | packs A–F, governance liaison | `@fraware` | TBA |

## Escalation

1. Open a GitHub issue or discussion tagged with the subsystem.
2. For security-sensitive reports, follow [SECURITY.md](SECURITY.md) — do not
   file public issues.
3. Benchmark construct changes follow [docs/governance/charter.md](docs/governance/charter.md).

## Becoming a maintainer

- Sustained high-quality contributions in a subsystem.
- Willingness to review PRs and uphold dual-review and DCO rules.
- Nomination by an existing maintainer; recorded in this file and CODEOWNERS.

## Related

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [.github/CODEOWNERS](.github/CODEOWNERS)
- [ROADMAP.md](ROADMAP.md)
- [docs/governance/charter.md](docs/governance/charter.md)
