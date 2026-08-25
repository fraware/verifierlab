"""Assurance package: artifact-derived qualification is the public path (WP-05).

``SEED_NOT_QUALIFICATION_PATH`` remains true: ``verifierlab.assurance.maturity``
is a frozen policy seed only. Callers must use ``qualify_run`` /
``EvidenceResolver``.
"""

from __future__ import annotations

from verifierlab.assurance.maturity import AssuranceClaim, AssuranceLevel
from verifierlab.assurance.resolver import (
    RESOLVER_VERSION,
    AssuranceQualification,
    EvidenceFact,
    EvidenceResolver,
    ExternalAssuranceAttestation,
    qualify_run,
    sign_external_attestation,
    verify_external_attestation,
)

SEED_NOT_QUALIFICATION_PATH = True

__all__ = [
    "RESOLVER_VERSION",
    "SEED_NOT_QUALIFICATION_PATH",
    "AssuranceClaim",
    "AssuranceLevel",
    "AssuranceQualification",
    "EvidenceFact",
    "EvidenceResolver",
    "ExternalAssuranceAttestation",
    "qualify_run",
    "sign_external_attestation",
    "verify_external_attestation",
]
