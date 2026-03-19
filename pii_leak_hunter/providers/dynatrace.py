from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.utils.config import DynatraceConfig


class DynatraceProvider(BaseProvider):
    def __init__(
        self,
        config: DynatraceConfig,
        client: httpx.Client | None = None,
        page_size: int = 500,
    ) -> None:
        self.config = config
        self.client = client or httpx.Client(timeout=10.0)
        self.page_size = page_size

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        records: list[LogRecord] = []
        for page in self._paginate(query=query, start=start, end=end):
            records.extend(self._to_record(item) for item in page)
        return records

    def _paginate(self, *, query: str, start: str, end: str) -> Iterator[list[dict[str, Any]]]:
        next_page_key: str | None = None
        while True:
            params = (
                {"nextPageKey": next_page_key}
                if next_page_key
                else {"query": query, "from": start, "to": end, "pageSize": self.page_size, "sort": "-timestamp"}
            )
            body = self._request_with_retries(params)
            items = body.get("results", [])
            if not isinstance(items, list) or not items:
                break
            yield [item for item in items if isinstance(item, dict)]
            next_page_key = body.get("nextPageKey")
            if not next_page_key:
                break

    def _request_with_retries(self, params: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = self.client.get(
                    f"{self.config.environment_url}/api/v2/logs/export",
                    headers={"Authorization": f"Api-Token {self.config.api_token}"},
                    params=params,
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise httpx.HTTPStatusError(
                        f"Retryable Dynatrace response: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Dynatrace response must be a JSON object.")
                return data
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"Dynatrace fetch failed after 3 attempts: {last_error}") from last_error

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        additional = item.get("additionalColumns", {})
        attributes = dict(additional) if isinstance(additional, dict) else {}
        message = str(item.get("content") or "")
        timestamp = str(item.get("timestamp") or "")
        attributes.update(item)
        return LogRecord(timestamp=timestamp, message=message, attributes=attributes, source="dynatrace")
