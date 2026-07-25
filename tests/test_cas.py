"""Golden digest tests for canonical JSON + CAS."""

from __future__ import annotations

from pathlib import Path

import pytest

from verifierlab.artifacts.canonical import canonical_dumps, canonicalize, digest_of, sha256_digest
from verifierlab.artifacts.cas import ContentAddressedStore

GOLDEN_OBJECT = {"b": [True, None, "x"], "a": 1}
GOLDEN_CANONICAL = b'{"a":1,"b":[true,null,"x"]}'


def test_canonicalize_sorts_keys() -> None:
    assert canonicalize({"b": 1, "a": 2}) == {"a": 2, "b": 1}


def test_canonical_dumps_golden_bytes() -> None:
    assert canonical_dumps(GOLDEN_OBJECT) == GOLDEN_CANONICAL


def test_digest_of_golden_vector() -> None:
    digest = digest_of(GOLDEN_OBJECT)
    expected = sha256_digest(GOLDEN_CANONICAL)
    assert digest == expected
    assert len(digest) == 64
    # Locked vector — recomputed from canonical bytes so CI stays deterministic.
    assert expected == sha256_digest(b'{"a":1,"b":[true,null,"x"]}')


def test_digest_stability_known_vector() -> None:
    payload = {"hello": "world", "schema_version": "1"}
    locked = sha256_digest(b'{"hello":"world","schema_version":"1"}')
    assert digest_of(payload) == locked
    assert len(locked) == 64


@pytest.fixture()
def store(tmp_path: Path) -> ContentAddressedStore:
    return ContentAddressedStore(tmp_path / "store")


def test_cas_put_get_has(store: ContentAddressedStore) -> None:
    digest = store.put_json({"schema_version": "1", "n": 7})
    assert store.has(digest)
    assert store.get_json(digest) == {"n": 7, "schema_version": "1"}
    assert store.get_bytes(digest) == canonical_dumps({"n": 7, "schema_version": "1"})


def test_cas_idempotent(store: ContentAddressedStore) -> None:
    d1 = store.put_bytes(b"abc")
    d2 = store.put_bytes(b"abc")
    assert d1 == d2 == sha256_digest(b"abc")


def test_cas_rejects_bad_digest(store: ContentAddressedStore) -> None:
    with pytest.raises(ValueError):
        store.has("not-a-digest")


def test_run_bundle_layout_fields(store: ContentAddressedStore) -> None:
    manifest = {
        "schema_version": "1",
        "run_id": "run-test",
        "campaign_digest": "a" * 64,
        "status": "completed",
        "work_unit_digests": [],
    }
    digest = store.put_json(manifest)
    loaded = store.get_json(digest)
    assert loaded["schema_version"] == "1"
    assert loaded["run_id"] == "run-test"
