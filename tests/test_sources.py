import bz2
import gzip
import io
import zipfile
from pathlib import Path
from types import SimpleNamespace

from pii_leak_hunter.sources.postgres import PostgresSource
from pii_leak_hunter.sources.s3 import S3Source
from pii_leak_hunter.sources.registry import build_source


def test_build_source_loads_directory_and_compressed_files(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "plain.ndjson").write_text(
        '{"timestamp":"2026-03-18T00:00:00Z","message":"owner@example.test"}\n',
        encoding="utf-8",
    )
    (logs_dir / "nested").mkdir()
    (logs_dir / "nested" / "service.log").write_text(
        "2026-03-18T00:01:00Z beneficiary_iban=DE89370400440532013000\n",
        encoding="utf-8",
    )
    (logs_dir / "events.ndjson.gz").write_bytes(
        gzip.compress(b'{"timestamp":"2026-03-18T00:02:00Z","message":"api_key=sk_live_FAKESECRET123"}\n')
    )
    (logs_dir / "audit.log.bz2").write_bytes(
        bz2.compress(b"2026-03-18T00:03:00Z customer_ssn=123-45-6789\n")
    )
    archive_path = logs_dir / "bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "inside.ndjson",
            '{"timestamp":"2026-03-18T00:04:00Z","message":"alice@example.test"}\n',
        )

    source = build_source(str(logs_dir))
    loaded = source.load()

    assert len(loaded.records) == 5
    assert loaded.metadata["mode"] == "file"


def test_postgres_source_scans_tables_without_touching_current_cli() -> None:
    class FakeCursor:
        def __init__(self, rows, description=None):
            self._rows = rows
            self.description = description or []

        def execute(self, query, params):
            self.query = query
            self.params = params

        def fetchall(self):
            return self._rows

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeConnection:
        def __init__(self):
            self.calls = 0

        def cursor(self):
            self.calls += 1
            if self.calls == 1:
                return FakeCursor([("public", "customers")])
            return FakeCursor(
                [("Alice Example", "alice@example.test")],
                description=[SimpleNamespace(name="name"), SimpleNamespace(name="email")],
            )

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    source = PostgresSource(
        "postgres://user:pass@localhost:5432/app?schema=public&row_limit=50",
        connector=lambda uri: FakeConnection(),
    )
    loaded = source.load()

    assert loaded.source == "postgres"
    assert loaded.metadata["database"] == "postgres"
    assert len(loaded.records) == 1
    assert loaded.records[0].attributes["table"] == "customers"


def test_s3_source_scans_prefix() -> None:
    class FakePaginator:
        def paginate(self, Bucket, Prefix):
            assert Bucket == "bucket"
            assert Prefix == "logs/"
            return [
                {"Contents": [{"Key": "logs/one.ndjson"}, {"Key": "logs/two.log.gz"}]}
            ]

    class FakeS3Client:
        def get_paginator(self, name):
            assert name == "list_objects_v2"
            return FakePaginator()

        def get_object(self, Bucket, Key):
            data = {
                "logs/one.ndjson": b'{"timestamp":"2026-03-18T00:00:00Z","message":"owner@example.test"}\n',
                "logs/two.log.gz": gzip.compress(b"2026-03-18T00:00:01Z api_key=sk_live_FAKESECRET123\n"),
            }[Key]
            return {"Body": io.BytesIO(data)}

    source = S3Source("s3://bucket/logs/", client=FakeS3Client())
    loaded = source.load()

    assert loaded.metadata["provider"] == "s3"
    assert len(loaded.records) == 2
