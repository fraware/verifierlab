# Attack engines

VerifierLab ships built-in strategies that observe the **public verifier
channel only**. Optimized strategies must tag cohort `optimized`. Ordinary
baseline tags `ordinary`. Metrics never pool cohorts without stratification.

## Built-ins

| Strategy | Cohort | Role |
| -------- | ------ | ---- |
| `ordinary` | `ordinary` | Non-optimized baseline actions |
| Random / structured fuzz | `optimized` | Seeded action mutation |
| Coverage-guided fuzz | `optimized` | Prefer novel observations |
| Evolutionary search | `optimized` | Persistent population + broker fitness |
| Inference-time (best-of-N / beam) | `optimized` | Candidate-level verifier queries |
| Local tabular RL (`rl_tabular`) | `optimized` | Persistent Q-table across episodes |

Heavy external trainers remain optional/external—see [limitations.md](limitations.md).

## Persistent attacker runtime

`verifierlab.attacks.runtime` initializes an attacker once per
`(campaign, strategy, seed)`, checkpoints under
`run_dir/attackers/<strategy>/<seed>/`, and separates learning episodes from
holdout evaluation when splits are declared. Candidate-level broker queries are
metered (BoN/beam charge N queries).

## Feedback contract

Attack `observe` paths receive public feedback stripped of ground-truth fields
(`public_attack_feedback`). Strategies must not depend on `gt_valid` before
label release. Workers never import GT providers.

## Access capabilities

Broker capabilities gate what an attacker may read:

| Model | Typical capability |
| ----- | ------------------ |
| black-box | Decision / score only |
| gray-box | Allowlisted reason codes / rubric categories |
| white-box | Read-only verifier profile mount |
| adaptive / transfer | Explicit round / source artifacts |

Disallowed reads raise `AccessDenied`.

## Packs and taxonomy

Campaign packs under `campaigns/packs/` (A–F) plant exploit themes and assert
recovery into taxonomy classes (`ExploitClass`). Heuristic classification for
planted refund-style trajectories lives in `verifierlab.exploits.taxonomy`.

## Plugins

Register custom strategies / environments via `verifierlab.plugins` entry
points (`valab plugins list`). Keep untrusted plugin code behind process
isolation; optional `verifierlab[sandbox]` + `docker_runner` enforces no
network / RO mounts / resource limits when Docker is available.

## Minimization and repair

- Delta-debug minimization preserves **public accept + hidden invalidity**
  (and optional multidimensional intent clauses); see the preservation report.
- Repair evaluation uses `run_repair_campaign` / `compare_repair`: immutable
  old/new verifier profiles, regression + holdout, fresh seeds, equalized
  budget, and paired FAR/FRR stats — not a one-shot scripted loop.

## Related

- [Methodology](methodology.md)
- [Labels and statistics](labels-and-stats.md)
- [Concepts](concepts.md)
- [Getting started](getting-started.md)
