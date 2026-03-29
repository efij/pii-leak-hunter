from __future__ import annotations

import importlib
from typing import Any
from urllib.parse import urlparse

from pii_leak_hunter.loader.file_loader import load_bytes
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.utils.config import ConfigurationError


class S3Source(BaseSource):
    def __init__(self, uri: str, client: Any | None = None) -> None:
        self.uri = uri
        parsed = urlparse(uri)
        self.bucket = parsed.netloc
        self.key = parsed.path.lstrip("/")
        self.client = client

    def load(self) -> LoadedSource:
        client = self.client or _build_s3_client()
        if not self.bucket:
            raise ValueError("S3 targets must include a bucket name.")

        records = []
        if not self.key or self.key.endswith("/"):
            paginator = client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=self.key):
                for item in page.get("Contents", []):
                    key = item.get("Key")
                    if not key or key.endswith("/"):
                        continue
                    records.extend(self._load_key(client, key))
        else:
            records.extend(self._load_key(client, self.key))

        return LoadedSource(
            records=records,
            source=f"s3://{self.bucket}/{self.key}",
            metadata={"mode": "object_store", "provider": "s3", "bucket": self.bucket, "prefix": self.key},
        )

    def _load_key(self, client: Any, key: str):
        body = client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        return load_bytes(body, source_name=key)


def _build_s3_client() -> Any:
    try:
        module = importlib.import_module("boto3")
    except ModuleNotFoundError as exc:
        raise ConfigurationError("boto3 is required for S3 scans. Install project dependencies first.") from exc
    return module.client("s3")
