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

Expected: the attempt documents blockers / refusal rather than a true
security-grade execution flag.

## Prerequisites for a real security-grade path

- Digest-pinned immutable worker image
- Rootless (or stronger) Docker / separate adjudication domain
- Live malicious probe catalogue evidence on a suitable host

Without those, keep maturity capped. Process-local and rootful paths are
development / internal-verification only.

See [threat-model.md](../threat-model.md), [claim-language.md](../claim-language.md),
and [support-matrix.md](../support-matrix.md).
