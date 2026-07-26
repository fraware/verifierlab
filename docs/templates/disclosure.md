# Disclosure template (third-party verifier finding)

Use this when coordinating disclosure of an exploit found **with** VerifierLab
against a third-party verifier. Prefer the Python `DisclosureRegistry` for
state transitions; this markdown is for humans / tickets.

## Summary

- **Title:**
- **Severity (operator judgment):** low / medium / high / critical
- **Embargo until (UTC):**
- **Campaign run digest:**
- **Access model / cohort / seed:**
- **Exploit taxonomy class:**
- **Public verifier accept?** yes / no
- **Hidden GT valid?** yes / no / unknown (pre-release)

## Reproduction

1. Package version / commit:
2. Campaign YAML path + pinned versions:
3. Commands:

```bash
uv run valab campaign run <campaign.yaml>
uv run valab campaign freeze <run_dir>
uv run valab campaign adjudicate <run_dir> --campaign <campaign.yaml>
uv run valab campaign release-labels <run_dir>
uv run valab report builds <run_dir>
```

4. Expected exploit id / taxonomy:
5. Artifacts to share privately (digests only when possible):

## Impact

- What the verifier incorrectly accepts or rejects:
- Who can trigger it (access model assumptions):
- Whether a repair is known:

## Coordinated disclosure plan

- [ ] Draft registry record (`draft`)
- [ ] Triage (`triaged`)
- [ ] Embargo set (`embargoed`)
- [ ] Private share with vendor (`shared_private`)
- [ ] Public summary / full (`public_summary` / `public_full`)

Do **not** auto-publish. See [disclosure.md](../disclosure.md) and
[SECURITY.md](https://github.com/fraware/verifierlab/blob/main/SECURITY.md).
