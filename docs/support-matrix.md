# Support matrix (WP-19)

Honest platform support for VerifierLab `0.2.0rc2` on the
`integration/final-assurance` line.

## Operating systems

| OS | Role | CI posture | Release-qualified? |
| -- | ---- | ---------- | ------------------ |
| Ubuntu (GitHub `ubuntu-latest`) | Primary | Hard-fail | **Yes** |
| macOS (GitHub `macos-latest`) | Secondary | Hard-fail process smoke | **Yes** (process path) |
| Windows (GitHub `windows-latest`) | Best-effort smoke only | `continue-on-error: true` | **No** |

### Windows decision (G7)

Windows remains in CI for visibility but is **removed from the stable support
matrix** as a release-qualified platform. Soft-fail is retained intentionally
so Windows regressions are visible without blocking Ubuntu/macOS merges or
releases. Claiming “Windows supported” from this tree is a documentation bug.

Rationale: process-worker and path semantics have historically been flaky on
Windows runners; making Windows hard-fail would either (a) block the programme
on non-deterministic infra or (b) require substantial Windows-specific
engineering not yet evidenced on this branch.

## Python

| Version | Status |
| ------- | ------ |
| 3.11 | Required (CI matrix) |
| 3.12 | Required (CI matrix) |
| 3.13 | Required (CI matrix) |
| ≤3.10 | Unsupported |
| ≥3.14 | Unsupported |

## Execution backends

| Backend | Maturity cap if used alone |
| ------- | -------------------------- |
| Local threads | Development only |
| Local processes | Development / internally verified cap |
| Digest-pinned rootless container worker | Required for `security_grade` evidence |
| Rootful Docker | `security_grade=false` even if container-local controls pass |

## Related

- [repository-protection-policy.md](repository-protection-policy.md)
- [limitations.md](limitations.md)
- [threat-model.md](threat-model.md)
