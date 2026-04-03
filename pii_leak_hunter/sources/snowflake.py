from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.sources.http_utils import request_json_with_retries
from pii_leak_hunter.utils.config import SnowflakeConfig


class SnowflakeSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: SnowflakeConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=20.0)
        parsed = _parse_snowflake_uri(uri)
        self.config = config or SnowflakeConfig.from_env()
        self.statement = parsed["statement"]
        self.limit = parsed["limit"]
        self.account_url = str(parsed["account_url"] or self.config.account_url)

    def load(self) -> LoadedSource:
        payload = request_json_with_retries(
            self.client,
            method="POST",
            url=f"{self.account_url}/api/v2/statements",
            label="Snowflake",
            headers=self._headers(),
            json_body=self._statement_payload(),
        )
        row_types = payload.get("resultSetMetaData", {}).get("rowType", [])
        column_names = [str(item.get("name")) for item in row_types if isinstance(item, dict) and item.get("name")]
        data = payload.get("data", [])
        records = []
        for index, row in enumerate(data[: self.limit], start=1):
            if isinstance(row, dict):
                payload_row = row
            elif isinstance(row, list):
                payload_row = {column: value for column, value in zip(column_names, row)}
            else:
                continue
            records.append(self._to_record(payload_row, index))
        return LoadedSource(
            records=records,
            source="snowflake",
            metadata={
                "mode": "database",
                "database": "snowflake",
                "statement": self.statement,
                "least_privilege_preset": "snowflake-query-read-only",
            },
        )

    def _statement_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "statement": self.statement,
            "timeout": 60,
            "resultSetMetaData": {"format": "json"},
        }
        if self.config.warehouse:
            payload["warehouse"] = self.config.warehouse
        if self.config.database:
            payload["database"] = self.config.database
        if self.config.schema:
            payload["schema"] = self.config.schema
        if self.config.role:
            payload["role"] = self.config.role
        return payload

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.token}",
            "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
        }

    def _to_record(self, row: dict[str, Any], index: int) -> LogRecord:
        message = json.dumps(row, sort_keys=True, default=str)
        timestamp = str(row.get("timestamp") or row.get("created_at") or row.get("updated_at") or "")
        return LogRecord(
            timestamp=timestamp,
            message=message,
            attributes=row,
            source=f"snowflake:result:{index}",
        )


def _parse_snowflake_uri(uri: str) -> dict[str, object]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    fallback_url = None if parsed.netloc in {"", "workspace"} else f"https://{parsed.netloc}"
    account_url = params.get("account_url", [fallback_url or ""])[0].rstrip("/") or None
    table = params.get("table", [""])[0]
    limit = int(params.get("limit", ["250"])[0])
    default_statement = f"SELECT * FROM {table} LIMIT {limit}" if table else "SELECT CURRENT_TIMESTAMP()"
    statement = params.get("statement", [default_statement])[0]
    return {"account_url": account_url, "statement": statement, "limit": limit}
