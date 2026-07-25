"""S3-compatible object-store CAS backend.

**Default:** :class:`LocalObjectStoreClient` (filesystem stand-in) — no extra deps.

**Live S3:** :class:`S3ObjectStoreClient` behind the ``[objectstore]`` extra
(``boto3``). Works with AWS S3 and S3-compatible endpoints (MinIO, etc.).

Install::

    pip install "verifierlab[objectstore]"
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from verifierlab.artifacts.canonical import canonical_dumps, digest_of, sha256_digest
from verifierlab.artifacts.cas import ContentAddressedStore


@runtime_checkable
class ObjectStoreClient(Protocol):
    def put_bytes(self, key: str, data: bytes) -> None: ...

    def get_bytes(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...


class LocalObjectStoreClient:
    """Filesystem stand-in for S3-compatible APIs (offline / tests / default)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, key: str, data: bytes) -> None:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get_bytes(self, key: str) -> bytes:
        return (self.root / key).read_bytes()

    def exists(self, key: str) -> bool:
        return (self.root / key).is_file()


def boto3_available() -> bool:
    try:
        import boto3  # noqa: F401
    except ImportError:
        return False
    return True


class S3ObjectStoreClient:
    """Live S3 / S3-compatible object store client (requires ``boto3``).

    Parameters mirror common boto3 client knobs so MinIO and other
    S3-compatible services work via ``endpoint_url``.
    """

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "",
        endpoint_url: str | None = None,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        client: Any | None = None,
        create_bucket: bool = False,
    ) -> None:
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise ImportError(
                    "S3ObjectStoreClient requires boto3; "
                    "install with: pip install 'verifierlab[objectstore]'"
                ) from exc
            kwargs: dict[str, Any] = {}
            if endpoint_url is not None:
                kwargs["endpoint_url"] = endpoint_url
            if region_name is not None:
                kwargs["region_name"] = region_name
            if aws_access_key_id is not None:
                kwargs["aws_access_key_id"] = aws_access_key_id
            if aws_secret_access_key is not None:
                kwargs["aws_secret_access_key"] = aws_secret_access_key
            client = boto3.client("s3", **kwargs)
        self._client = client
        self.bucket = bucket
        self.prefix = prefix.lstrip("/")
        if create_bucket:
            self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            self._client.head_bucket(Bucket=self.bucket)
        except Exception:
            params: dict[str, Any] = {"Bucket": self.bucket}
            # us-east-1 cannot set LocationConstraint
            region = getattr(self._client.meta, "region_name", None)
            if region and region != "us-east-1":
                params["CreateBucketConfiguration"] = {"LocationConstraint": region}
            self._client.create_bucket(**params)

    def _full_key(self, key: str) -> str:
        key = key.lstrip("/")
        if self.prefix:
            return f"{self.prefix.rstrip('/')}/{key}"
        return key

    def put_bytes(self, key: str, data: bytes) -> None:
        self._client.put_object(Bucket=self.bucket, Key=self._full_key(key), Body=data)

    def get_bytes(self, key: str) -> bytes:
        response = self._client.get_object(Bucket=self.bucket, Key=self._full_key(key))
        body = response["Body"].read()
        if isinstance(body, bytes):
            return body
        return bytes(body)

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=self._full_key(key))
            return True
        except Exception:
            return False


class ObjectStoreCAS:
    """Content-addressed store over an S3-compatible client."""

    def __init__(self, client: ObjectStoreClient, *, prefix: str = "valab/") -> None:
        self.client = client
        self.prefix = prefix

    def _key(self, digest: str) -> str:
        return f"{self.prefix}{digest[:2]}/{digest}"

    def put(self, data: bytes) -> str:
        digest = sha256_digest(data)
        key = self._key(digest)
        if not self.client.exists(key):
            self.client.put_bytes(key, data)
        return digest

    def put_json(self, value: Any) -> str:
        return self.put(canonical_dumps(value))

    def get(self, digest: str) -> bytes:
        return self.client.get_bytes(self._key(digest))

    def get_json(self, digest: str) -> Any:
        return json.loads(self.get(digest).decode("utf-8"))

    def has(self, digest: str) -> bool:
        return self.client.exists(self._key(digest))

    def mirror_from_fs(self, fs_store: ContentAddressedStore) -> list[str]:
        """Copy all objects from a filesystem CAS into object store."""
        mirrored: list[str] = []
        root = Path(fs_store.root)
        for path in root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                mirrored.append(self.put(data))
        return mirrored


def digest_matches(value: Any, digest: str) -> bool:
    return digest_of(value) == digest
