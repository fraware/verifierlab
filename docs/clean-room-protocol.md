# Clean-room reconstruction protocol (WP-21)

This protocol validates that a VerifierLab reproduction bundle can be
reconstructed mechanically. An **internal** clean-room dry-run is **not**
independent verification.

## Scope

- Confirms artifact digests, claim binding, and reconstruction mechanics.
- Does **not** establish `independently_verified` maturity.
- Does **not** replace a signed `ExternalAssuranceAttestation` from an
  external trust root.

## Steps

1. Obtain the self-contained reproduction bundle directory (`bundle.json`,
   `claim.json`, `instructions.json`, `artifacts/`).
2. Run `valab reproduce BUNDLE --clean-room` on a machine without write access
   to the original sealed-label vault.
3. Confirm `ReconstructionReport.mechanics_ok` and
   `reconstructed=true` with `independent=false` and
   `clean_room_dry_run=true`.
4. For independent claims only: supply `--attestation` and `--trust-root`
   from an external reviewer; reject self-issued or subject-mismatched
   attestations.

## Non-claims

- Passing a clean-room dry-run does not mean the study is scientifically
  qualified or security-grade.
- Self-issued attestations are always rejected.
- Internal dry-runs on developer laptops remain development-grade evidence.

See [claim-language.md](claim-language.md) and
[reproduction-checklist.md](reproduction-checklist.md).
