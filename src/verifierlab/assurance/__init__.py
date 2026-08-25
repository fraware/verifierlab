"""Assurance policy seed. Not the public qualification path.

WP-00 lands PR #10 as a *policy seed* only. WP-05 replaces this package with
``EvidenceResolver`` producing typed ``EvidenceFact`` records. Caller-supplied
booleans are not a qualification API and are not re-exported here.
"""

from __future__ import annotations

from verifierlab.assurance.maturity import (
    AssuranceClaim,
    AssuranceLevel,
    AssuranceQualification,
)

SEED_NOT_QUALIFICATION_PATH = True

__all__ = [
    "SEED_NOT_QUALIFICATION_PATH",
    "AssuranceClaim",
    "AssuranceLevel",
    "AssuranceQualification",
]
