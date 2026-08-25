"""Label vault, freeze, adjudication, and adjudicator-only reference oracles."""

from __future__ import annotations

from verifierlab.labels.adjudication import Adjudication, adjudicate
from verifierlab.labels.adjudication_service import adjudicate_run, resolve_is_valid
from verifierlab.labels.freeze import FreezeRecord, assert_freeze_immutable
from verifierlab.labels.planted_fake import PlantedOracleGroundTruth
from verifierlab.labels.release import (
    LabelReleaseReceipt,
    assert_receipt_binds_seal,
    label_set_digest,
)
from verifierlab.labels.vault import LabelVault

__all__ = [
    "Adjudication",
    "FreezeRecord",
    "LabelReleaseReceipt",
    "LabelVault",
    "PlantedOracleGroundTruth",
    "adjudicate",
    "adjudicate_run",
    "assert_freeze_immutable",
    "assert_receipt_binds_seal",
    "label_set_digest",
    "resolve_is_valid",
]
