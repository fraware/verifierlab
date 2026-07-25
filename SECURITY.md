# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` (alpha, including `0.1.0a0`) | Yes — best-effort for research alpha |

There is no long-term support channel yet. Prefer reporting against the latest
`main` commit.

## What this project is (and is not)

VerifierLab evaluates verifier robustness. Campaign results showing “no exploit
found” are **not** soundness proofs. Do not treat the toolkit as a substitute
for formal verification, production sandboxing, or coordinated vulnerability
disclosure for third-party systems.

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
`DisclosureRegistry` (see [docs/disclosure.md](docs/disclosure.md)); it does
**not** automatically publish findings.

## Safe harbor

We will not pursue legal action against researchers who:

- Act in good faith
- Avoid privacy violations, data destruction, and service disruption beyond what
  is needed to demonstrate the issue
- Give us a reasonable opportunity to remediate before public disclosure
