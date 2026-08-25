# Tutorial: Security-grade execution (refuse unsuitable hosts)

This tutorial shows how VerifierLab **refuses** to mint `security_grade`
evidence on an unsuitable host. It does not walk through rootless Docker setup
on every laptop — that remains an operational prerequisite.

## Goal

Demonstrate fail-closed capability negotiation: local/process/rootful paths
must not be labeled security-grade.

## Steps

```bash
uv sync --extra dev
uv run pytest tests/test_secure_launcher.py tests/test_container_execution_boundary.py -q
```

Inspect a study attempt that recorded a refused security-grade evaluation:

```bash
# Flagship study records an honest refusal when the host cannot attest rootless probes.
type studies\flagship-2026\security_grade_attempt.json   # Windows
# cat studies/flagship-2026/security_grade_attempt.json  # Unix
```

Expected: the attempt documents blockers / refusal rather than
`security_grade=true`.

## Non-claims

- Passing process-local tests ≠ security-grade.
- Rootful Docker with container-local controls still yields `security_grade=false`.
- Do not patch fixtures to fake a green security-grade label.

See [threat-model.md](../threat-model.md) and [claim-language.md](../claim-language.md).
