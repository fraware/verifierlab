# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `0.2.0rc2` (release candidate) | Yes — best-effort for research RC |
| `0.2.0rc1` (prior RC) | Superseded — upgrade to `0.2.0rc2` |
| `0.1.x` (alpha) | Best-effort; prefer upgrading to `0.2.0rc2` |

There is no long-term support channel yet. Prefer reporting against the latest
`main` or `integration/final-assurance` commit until protected `main` is
fast-forwarded. Package version is **`0.2.0rc2`** with executable RC gates
(`tests/test_acceptance_gates.py`) and final-acceptance gates A–J
(`tests/test_final_acceptance_gates.py`). That is software readiness — not a
soundness or security-grade assurance claim. See
[docs/claim-language.md](docs/claim-language.md).

## What this project is (and is not)

VerifierLab evaluates verifier robustness. Campaign results showing “no exploit
found” are **not** soundness proofs. Do not treat the toolkit as a substitute
for formal verification, production sandboxing, or coordinated vulnerability
disclosure for third-party systems. Process-local runs are development-grade;
`security_grade` evidence requires rootless/separate-domain runners.

## Integrity posture (RC + final-assurance)

| Area | Honest status |
| ---- | ------------- |
| Process-pool workers | Module-level worker entry; CI covers `--processes` (+ multi-OS matrix). |
| Verifier decisions | Fail-closed typed normalization (`accept`/`reject`/`abstain`/`error`). |
| Hidden ground truth | Attack workers do not import GT; adjudication is coordinator-only after freeze. |
| Label vault / freeze | Vault v2 salted + encrypted; append-only freeze → adjudicate → release. |
| Access models | Capability-gated at `VerifierBroker`. |
| “Optimized” cohorts | Persistent attacker runtime with candidate-level metering. |
| Sandbox profiles | Process isolation default. Optional `[sandbox]` Docker runner (no network, RO mounts, limits) when Docker is available; otherwise honest `unavailable` — default local path trusts host Python. |
| Security-grade path | Digest-pinned rootless worker + probes; rootful/process hosts fail closed. |
| Maturity labels | Artifact-derived only; caller booleans cannot promote. |
| Transcript audit | Structural + plugin findings are **not** ground truth. |

Report concrete vault/CAS/bypass bugs via the channels below. See
[docs/limitations.md](docs/limitations.md) and
[docs/threat-model.md](docs/threat-model.md) for trust-boundary notes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

1. Prefer [GitHub Security Advisories](https://github.com/fraware/verifierlab/security/advisories/new)
   (private vulnerability reporting) when available on the repository.
2. Otherwise email the maintainers listed in the repository profile / organization
   with subject `[SECURITY] verifierlab`.

Include:

- Affected version or commit SHA
- Reproduction steps (minimal campaign or unit test preferred)
- Impact assessment (integrity of CAS/vault, label leakage, secret exposure in
  reports, remote code paths if any)
- Whether a fix or workaround is already known

We aim to acknowledge within **7 days** and provide a remediation plan for
confirmed issues within a reasonable window for an alpha research project.

For operator-facing integrity incidents (label leak, freeze bypass), use
[docs/templates/incident.md](docs/templates/incident.md).

## Scope

**In scope (examples):**

- Label vault / freeze bypasses that expose ground truth to workers or strategies
- Content-addressed store integrity failures (digest collisions by construction bugs,
  silent mutation after freeze)
- Secrets or credentials written into public reports or committed artifacts by
  default tooling
- Privilege issues in optional live Slurm / Kubernetes / S3 paths when used as
  documented

**Out of scope (examples):**

- Findings that require treating “no exploit found” as a soundness claim
- Issues solely in optional third-party SDKs (inspect-ai, Harbor, Gymnasium, …)
  unless VerifierLab’s adapter mishandles them in a security-relevant way
- Social engineering or physical access to the operator host
- Denial of service against unbounded local campaign configs chosen by the operator

## Disclosure of exploits found *with* VerifierLab

Campaign disclosures for third-party verifiers should follow your organization’s
responsible disclosure policy. VerifierLab provides a filesystem
`DisclosureRegistry` (see [docs/disclosure.md](docs/disclosure.md) and
[docs/templates/disclosure.md](docs/templates/disclosure.md)); it does
**not** automatically publish findings.

## Safe harbor

We will not pursue legal action against researchers who:

- Act in good faith
- Avoid privacy violations, data destruction, and service disruption beyond what
  is needed to demonstrate the issue
- Give us a reasonable opportunity to remediate before public disclosure
