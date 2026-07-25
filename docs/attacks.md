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
| Evolutionary search | `optimized` | Population-based search |
| Inference-time (best-of-N / beam) | `optimized` | Select among candidate actions |
| Local tabular RL (`rl_tabular`) | `optimized` | Lightweight Q-learning in base |

Heavy external trainers remain optional/external—see [limitations.md](limitations.md).

## Feedback contract

Attack `observe` paths receive public feedback stripped of ground-truth fields
(`public_attack_feedback`). Strategies must not depend on `gt_valid` before
label release.

## Packs and taxonomy

Campaign packs under `campaigns/packs/` plant exploit themes and assert recovery
into taxonomy classes (`ExploitClass`). Heuristic classification for planted
refund-style trajectories lives in `verifierlab.exploits.taxonomy`.

## Minimization and repair

- Delta-debug minimization preserves the accept∧invalid predicate.
- Repair comparison (`compare_repair`) requires a fresh attacker on the public
  channel after a purported fix.

## Related

- [Methodology](methodology.md)
- [Labels and statistics](labels-and-stats.md)
- [Concepts](concepts.md)
