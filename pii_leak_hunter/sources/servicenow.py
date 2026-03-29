from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.sources.base import BaseSource, LoadedSource
from pii_leak_hunter.utils.config import ServiceNowConfig


class ServiceNowSource(BaseSource):
    def __init__(
        self,
        uri: str,
        client: httpx.Client | None = None,
        config: ServiceNowConfig | None = None,
    ) -> None:
        self.uri = uri
        self.client = client or httpx.Client(timeout=10.0)
        self.config = config or ServiceNowConfig.from_env()
        self.instance_url, self.table, self.query, self.page_size = _parse_servicenow_uri(uri)

    def load(self) -> LoadedSource:
        records: list[LogRecord] = []
        offset = 0
        while True:
            params = {
                "sysparm_query": self.query,
                "sysparm_limit": str(self.page_size),
                "sysparm_offset": str(offset),
            }
            body = self._request_with_retries(params)
            items = body.get("result", [])
            if not isinstance(items, list) or not items:
                break
            for index, item in enumerate(items, start=1):
                if isinstance(item, dict):
                    records.append(self._to_record(item, offset + index))
            if len(items) < self.page_size:
                break
            offset += self.page_size
        return LoadedSource(
            records=records,
            source="servicenow",
            metadata={
                "mode": "saas",
                "provider": "servicenow",
                "table": self.table,
                "query": self.query,
                "least_privilege_preset": "servicenow-read-only",
            },
        )

    def _request_with_retries(self, params: dict[str, str]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = self.client.get(
                    f"{self.instance_url}/api/now/table/{self.table}",
                    headers=self._headers(),
                    params=params,
                    auth=self._auth(),
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise httpx.HTTPStatusError(
                        f"Retryable ServiceNow response: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("ServiceNow response must be a JSON object.")
                return payload
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"ServiceNow fetch failed after 3 attempts: {last_error}") from last_error

    def _to_record(self, item: dict[str, Any], index: int) -> LogRecord:
        message_parts = [
            str(item.get("short_description") or ""),
            str(item.get("description") or ""),
            str(item.get("comments") or ""),
            str(item.get("work_notes") or ""),
        ]
        message = " | ".join(part for part in message_parts if part)
        timestamp = str(item.get("sys_updated_on") or item.get("opened_at") or item.get("sys_created_on") or "")
        return LogRecord(
            timestamp=timestamp,
            message=message,
            attributes=item,
            source=f"servicenow:{self.table}:{item.get('sys_id', index)}",
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        return headers

    def _auth(self) -> tuple[str, str] | None:
        if self.config.username and self.config.password:
            return (self.config.username, self.config.password)
        return None


def _parse_servicenow_uri(uri: str) -> tuple[str, str, str, int]:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    instance_url = f"https://{parsed.netloc}" if parsed.netloc else "https://"
    table = params.get("table", ["incident"])[0]
    query = params.get("query", ["active=true"])[0]
    page_size = int(params.get("page_size", ["100"])[0])
    return instance_url.rstrip("/"), table, query, page_size
