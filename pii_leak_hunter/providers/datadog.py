from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.utils.config import DatadogConfig


class DatadogProvider(BaseProvider):
    def __init__(
        self,
        config: DatadogConfig,
        client: httpx.Client | None = None,
        page_size: int = 500,
    ) -> None:
        self.config = config
        self.client = client or httpx.Client(timeout=10.0)
        self.page_size = min(page_size, 1000)

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        records: list[LogRecord] = []
        for page in self._paginate(query=query, start=start, end=end):
            records.extend(self._to_record(item) for item in page)
        return records

    def _paginate(self, *, query: str, start: str, end: str) -> Iterator[list[dict[str, Any]]]:
        cursor: str | None = None
        while True:
            payload = {
                "index": "*",
                "limit": self.page_size,
                "query": query,
                "sort": "desc",
                "time": {
                    "from": start,
                    "to": end,
                },
            }
            if cursor:
                payload["startAt"] = cursor

            body = self._request_with_retries(payload)
            items = body.get("logs", [])
            if not isinstance(items, list) or not items:
                break
            yield [item for item in items if isinstance(item, dict)]
            cursor = body.get("nextLogId")
            if not cursor:
                break

    def _request_with_retries(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = self.client.post(
                    f"{self.config.base_url}/api/v1/logs-queries/list",
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "DD-API-KEY": self.config.api_key,
                        "DD-APPLICATION-KEY": self.config.app_key,
                    },
                    json=payload,
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise httpx.HTTPStatusError(
                        f"Retryable Datadog response: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Datadog response must be a JSON object.")
                return data
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"Datadog fetch failed after 3 attempts: {last_error}") from last_error

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        payload = dict(item)
        attributes = item.get("attributes", {})
        if isinstance(attributes, dict):
            payload.update(attributes)
        message = str(payload.get("message") or item.get("message") or "")
        timestamp = str(payload.get("timestamp") or item.get("timestamp") or "")
        return LogRecord(timestamp=timestamp, message=message, attributes=payload, source="datadog")
