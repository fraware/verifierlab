# Tutorial hooks: method surfaces

Short entry points for H/F/S, metamorphic, planted calibration, response
surface, and EnvAssure on this tree. Full campaigns need sealed splits and
budgets; these hooks point at tests and CLIs that already exist.

## Hacker / Fixer / Solver (H/F/S)

```bash
uv run pytest tests/test_hfs_qualification_wp10.py tests/test_hacker_fixer_solver_protocol.py -q
```

Order is immutable: hacker → freeze exploits → fixer → solver → fresh attacker.
Failed patches are preserved; unequal budgets cannot support equal-budget claims.

## Metamorphic

```bash
uv run pytest tests/test_metamorphic_attack_wp08.py tests/test_metamorphic_registry.py -q
```

GT-invariance is evaluated first. Invalid transforms are not counted as
verifier failures. High invalid-transform suites cannot support verifier
conclusions.

## Planted calibration

```bash
uv run pytest tests/test_planted_calibration.py -q
```

Hard-coded: `supports_unknown_robustness_claim=false`. Do not cite planted
hits as unknown-adversary robustness.

## Response surface

```bash
uv run pytest tests/test_response_surface_orchestrator_wp07.py -q
# CLI expands registered sparse grids from released bundle refs only:
uv run valab surface --help
```

Exact cells only — never interpolate into a scalar robustness score.

## EnvAssure

```bash
uv run pytest tests/test_envassure_wp14.py -q
```

Adapter matrix status remains **fixture-only** until the EnvAssure package is
installable. Upstream indeterminate propagates through
`EnvironmentAssuranceRef` / `AssuranceChainManifest`.

## Related

- [architecture.md](../architecture.md)
- [methodology.md](../methodology.md)
- [claim-language.md](../claim-language.md)
- [limitations.md](../limitations.md)
- [security-grade.md](security-grade.md)

**Prerequisite:** editable install with `uv sync --extra dev` (or equivalent).
These tutorials point at existing pytest modules — they are not standalone
campaign walkthroughs and do not raise scientific maturity by themselves.
