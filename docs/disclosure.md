# Disclosure

VerifierLab does **not** automatically publish findings. It provides a
filesystem `DisclosureRegistry` for tracking coordinated disclosure state
transitions and public views.

Module: `verifierlab.disclosure` (`DisclosureRegistry`, `DisclosureRecord`,
`DisclosureState`).

CLI wrappers (`valab disclose *`) are intentionally deferred; use the Python API.

## States

| State | Meaning |
| ----- | ------- |
| `draft` | Initial record |
| `triaged` | Accepted for handling |
| `embargoed` | Under embargo (`embargo_until`) |
| `shared_private` | Shared with a limited private audience |
| `public_summary` | Public summary only |
| `public_full` | Full public record (includes exploit id in public view) |
| `declined` | Not proceeding |
| `expired` | Embargo expired; may move to public summary or declined |

Illegal transitions raise `ValueError`.

## Public view rules

- Before `public_summary` / `public_full`: public view omits private detail and
  summary content (`public_summary` is `None` in the view).
- `public_summary`: id, state, severity, summary text.
- `public_full`: also includes `exploit_id`.
- Private detail refs stay out of public views until full release policy allows.

## Campaign disclosure class

Campaign YAML includes `disclosure_class` (for example `internal`). That field
classifies the campaign’s intended handling; it is separate from per-exploit
registry state.

## Reporting vulnerabilities *in* VerifierLab

See [SECURITY.md](../SECURITY.md). Do not confuse product vulnerability reports
with campaign disclosures of third-party verifier failures.

## Related

- Lifecycle states: [concepts.md](concepts.md)
- Threat model non-goals: [threat-model.md](threat-model.md)
- Reproduction disclosure checks: [reproduction-checklist.md](reproduction-checklist.md)
