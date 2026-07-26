# Contributing verifiers

How to add or package a verifier for VerifierLab.

## Goals

- Expose a typed decision surface (`Decision` / `VerifierDecision`).
- Declare a verifier profile (digest, applicability, access surface).
- Run through the metered broker; never touch hidden labels from the attack plane.

## Minimal path (trusted local)

```python
from verifierlab.api.verifier import verifier
from verifierlab.api.decision import Decision

@verifier
def grade(observation: dict) -> Decision:
    # Return typed Decision — never bool("reject")
    ...
```

Inspect with `valab inspect MODULE:ATTR` or `valab verifier inspect MODULE:ATTR`
(same implementation).

## Packaged / subprocess path

Prefer `PythonVerifierRunner` for packaged native verifiers (`kind: packaged` or
`config.isolation: subprocess`):

- timeout, best-effort CPU/memory limits (Unix RLIMIT; Windows timeout-focused)
- structured stdin/stdout JSON
- exception → typed `error`
- deterministic child env + source/config digests
- **no label / vault imports** in the child

Trusted local `@verifier` callables remain in-process when isolation is omitted.

## Required checks

- [ ] Decisions use fail-closed normalization (no truthiness conversion).
- [ ] Profile digest is stable under canonical JSON.
- [ ] Compatibility / conformance tests at the status you claim in the plugin
      registry (`schema_validated`, `conformance_tested`, …).
- [ ] Worker-facing fixtures contain **no** hidden labels or vault material.
- [ ] Registry entry (if public) sets `hidden_label_access: false` unless this
      component is an adjudicator — and adjudicator plugins are never loaded in
      workers.

## Do not

- Import `verifierlab.labels` or vault clients from verifier attack-plane code.
- Claim live SDK behavior from fixture-only tests.
- Treat registry inclusion as permission to auto-execute remote code.

## Related

- [docs/concepts.md](../concepts.md)
- [docs/architecture.md](../architecture.md)
- [Attacks guide](attacks.md)
- [Defects](defects.md)
