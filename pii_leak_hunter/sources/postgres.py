from __future__ import annotations

import importlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.utils.config import ConfigurationError


@dataclass(slots=True)
class PostgresOptions:
    schema: str = "public"
    row_limit: int = 1000
    tables: list[str] | None = None


class PostgresSource(BaseSource):
    def __init__(self, uri: str, connector: Any | None = None) -> None:
        self.uri = uri
        self.connector = connector
        self.options = _parse_postgres_options(uri)

    def load(self) -> LoadedSource:
        connect = self.connector or _load_psycopg_connect()
        with connect(self.uri) as connection:
            records = []
            for schema_name, table_name in self._list_tables(connection):
                records.extend(self._scan_table(connection, schema_name, table_name))
        return LoadedSource(
            records=records,
            source="postgres",
            metadata={
                "mode": "database",
                "database": "postgres",
                "schema": self.options.schema,
                "row_limit": str(self.options.row_limit),
            },
        )

    def _list_tables(self, connection: Any) -> Iterable[tuple[str, str]]:
        if self.options.tables:
            return [(self.options.schema, table) for table in self.options.tables]
        query = (
            "SELECT table_schema, table_name "
            "FROM information_schema.tables "
            "WHERE table_type = 'BASE TABLE' AND table_schema = %s "
            "ORDER BY table_name"
        )
        with connection.cursor() as cursor:
            cursor.execute(query, (self.options.schema,))
            return [(row[0], row[1]) for row in cursor.fetchall()]

    def _scan_table(self, connection: Any, schema_name: str, table_name: str) -> list[LogRecord]:
        query = (
            f'SELECT * FROM "{schema_name.replace(chr(34), chr(34) * 2)}"."{table_name.replace(chr(34), chr(34) * 2)}" '
            "LIMIT %s"
        )
        with connection.cursor() as cursor:
            cursor.execute(query, (self.options.row_limit,))
            columns = [column.name for column in cursor.description]
            rows = cursor.fetchall()

        records: list[LogRecord] = []
        for index, row in enumerate(rows, start=1):
            payload = {column: _coerce_value(value) for column, value in zip(columns, row)}
            message = json.dumps(payload, sort_keys=True, default=str)
            timestamp = _extract_timestamp(payload)
            records.append(
                LogRecord(
                    timestamp=timestamp,
                    message=message,
                    attributes={"table": table_name, "schema": schema_name, **payload},
                    source=f"postgres:{schema_name}.{table_name}:{index}",
                )
            )
        return records


def _parse_postgres_options(uri: str) -> PostgresOptions:
    parsed = urlparse(uri)
    options = parse_qs(parsed.query)
    schema = options.get("schema", ["public"])[0]
    row_limit = int(options.get("row_limit", ["1000"])[0])
    tables = options.get("tables", [None])[0]
    return PostgresOptions(
        schema=schema,
        row_limit=row_limit,
        tables=tables.split(",") if tables else None,
    )


def _extract_timestamp(payload: dict[str, Any]) -> str:
    for key in ("timestamp", "created_at", "updated_at", "time"):
        if key in payload and payload[key] is not None:
            return str(payload[key])
    return ""


def _coerce_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _load_psycopg_connect() -> Any:
    try:
        module = importlib.import_module("psycopg")
    except ModuleNotFoundError as exc:
        raise ConfigurationError("psycopg is required for Postgres scans. Install project dependencies first.") from exc
    return module.connect
