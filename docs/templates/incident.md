# Integrity incident template (VerifierLab itself)

Use when operators suspect a **VerifierLab** integrity failure (label leak,
freeze bypass, CAS mutation, capability violation)—not a third-party verifier
exploit. For product vulns, also follow [SECURITY.md](https://github.com/fraware/verifierlab/blob/main/SECURITY.md).

## Incident metadata

- **ID / date (UTC):**
- **Reporter:**
- **Severity:** low / medium / high / critical
- **Affected version / commit:**
- **Environment:** OS / Python / extras installed

## Suspected class

- [ ] Pre-release `gt_valid` / label visible to workers or strategies
- [ ] Post-freeze vault injection succeeded
- [ ] Commitment brute-force / unsalted guess succeeded
- [ ] Capability bypass (black-box read of forbidden fields)
- [ ] Audit log / lifecycle chain tamper
- [ ] Secret or credential written into public report
- [ ] Other:

## Evidence

1. Minimal reproduction (campaign or unit test):
2. Run digests / vault audit excerpts (redact secrets):
3. Whether labels were released before discovery:

## Immediate containment

- [ ] Stop publishing reports from the affected workspace
- [ ] Preserve `.valab/runs/<run-id>/` and vault audit log
- [ ] Rotate vault keyring material if exposure is plausible
- [ ] File private security report (GitHub advisory / maintainer email)

## Resolution

- Root cause:
- Fix / workaround:
- Tests added:
- Disclosure status (internal / advisory):

See [threat-model.md](../threat-model.md) and [limitations.md](../limitations.md).
