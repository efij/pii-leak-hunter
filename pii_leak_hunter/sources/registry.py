from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from pii_leak_hunter.sources.base import BaseSource
from pii_leak_hunter.sources.filesystem import FilesystemSource
from pii_leak_hunter.sources.notion import NotionSource
from pii_leak_hunter.sources.postgres import PostgresSource
from pii_leak_hunter.sources.s3 import S3Source
from pii_leak_hunter.sources.servicenow import ServiceNowSource


def build_source(target: str) -> BaseSource:
    parsed = urlparse(target)
    if parsed.scheme == "file":
        return FilesystemSource(_file_uri_to_path(target))
    if parsed.scheme in {"postgres", "postgresql"}:
        return PostgresSource(target)
    if parsed.scheme == "s3":
        return S3Source(target)
    if parsed.scheme == "servicenow":
        return ServiceNowSource(target)
    if parsed.scheme == "notion":
        return NotionSource(target)
    if parsed.scheme == "" and Path(target).exists():
        return FilesystemSource(target)
    raise ValueError(f"Unsupported scan target: {target}")


def is_target_source(target: str | None) -> bool:
    if not target:
        return False
    parsed = urlparse(target)
    if parsed.scheme in {"file", "postgres", "postgresql", "s3", "servicenow", "notion"}:
        return True
    return parsed.scheme == "" and Path(target).exists()


def _file_uri_to_path(uri: str) -> str:
    parsed = urlparse(uri)
    host = parsed.netloc
    path = parsed.path
    if host:
        return f"//{host}{path}"
    return path
