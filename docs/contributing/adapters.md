# Contributing adapters

How to integrate an external SDK or protocol as a VerifierLab target.

## Goals

- Gate the SDK behind an optional extra.
- Fail with an install hint when the extra is missing — never a silent stub pass.
- Publish supported versions, live vs fixture, boundary, mapping, unsupported
  semantics, conformance command, CI status, example, and troubleshooting.

## Matrix honesty

| Claim | Allowed when |
| ----- | ------------ |
| `fixture` | Protocol/shape tests using checked-in logs or mocks |
| `live` | Real supported package installed and exercised in CI/release |

**No live claim from fixture-only tests.**

## Required checks

- [ ] Extra pin documented in `pyproject.toml` and adapter docs.
- [ ] Conformance via `verifierlab.targets.conformance` (or successor) where applicable.
- [ ] Hidden-label isolation tests for worker-facing paths.
- [ ] Decision normalization without truthiness conversion.
- [ ] Plugin registry entry (kind `adapter`) if listing publicly.

## Do not

- Invent a parallel adapter API — extend existing targets/broker/lifecycle.
- Collapse distinct Inspect modes into one ambiguous “live” path.
- Ship worker images that include adjudicator credentials.

## Related

- [docs/adapters.md](../adapters.md)
- [docs/limitations.md](../limitations.md)
- [Environments guide](environments.md)
- [Release process](release-process.md)
