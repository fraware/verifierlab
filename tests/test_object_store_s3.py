"""Object-store CAS contract tests + optional live S3 (moto/boto3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from verifierlab.artifacts.cas import ContentAddressedStore
from verifierlab.artifacts.object_store import (
    LocalObjectStoreClient,
    ObjectStoreCAS,
    ObjectStoreClient,
    boto3_available,
)


def _cas_contract(client: ObjectStoreClient) -> None:
    cas = ObjectStoreCAS(client)
    digest = cas.put_json({"a": 1, "b": [2, 3]})
    assert len(digest) == 64
    assert cas.has(digest)
    assert cas.get_json(digest) == {"a": 1, "b": [2, 3]}
    # Idempotent put
    assert cas.put_json({"a": 1, "b": [2, 3]}) == digest
    raw = cas.put(b"hello-cas")
    assert cas.get(raw) == b"hello-cas"


def test_local_object_store_cas_contract(tmp_path: Path) -> None:
    _cas_contract(LocalObjectStoreClient(tmp_path / "s3"))


def test_local_mirror_from_fs(tmp_path: Path) -> None:
    client = LocalObjectStoreClient(tmp_path / "s3")
    cas = ObjectStoreCAS(client)
    fs = ContentAddressedStore(tmp_path / "fs")
    fs.put_json({"b": 2})
    mirrored = cas.mirror_from_fs(fs)
    assert mirrored
    assert all(cas.has(d) for d in mirrored)


@pytest.mark.objectstore
@pytest.mark.skipif(not boto3_available(), reason="boto3 not installed")
def test_s3_object_store_cas_with_moto() -> None:
    pytest.importorskip("moto")
    from moto import mock_aws

    from verifierlab.artifacts.object_store import S3ObjectStoreClient

    with mock_aws():
        client = S3ObjectStoreClient(
            "valab-test",
            region_name="us-east-1",
            create_bucket=True,
        )
        _cas_contract(client)


@pytest.mark.objectstore
@pytest.mark.skipif(not boto3_available(), reason="boto3 not installed")
def test_s3_client_requires_explicit_construct() -> None:
    from verifierlab.artifacts.object_store import S3ObjectStoreClient

    # Inject a fake client to avoid network; contract still holds.
    class FakeS3:
        def __init__(self) -> None:
            self.store: dict[str, bytes] = {}

        def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict[str, Any]:
            self.store[f"{Bucket}/{Key}"] = Body
            return {}

        def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
            class Body:
                def __init__(self, data: bytes) -> None:
                    self._data = data

                def read(self) -> bytes:
                    return self._data

            return {"Body": Body(self.store[f"{Bucket}/{Key}"])}

        def head_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
            if f"{Bucket}/{Key}" not in self.store:
                raise RuntimeError("404")
            return {}

        def head_bucket(self, *, Bucket: str) -> dict[str, Any]:
            return {}

        def create_bucket(self, **kwargs: Any) -> dict[str, Any]:
            return {}

    fake = FakeS3()
    client = S3ObjectStoreClient("bucket", client=fake, create_bucket=False)
    _cas_contract(client)
