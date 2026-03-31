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
            payload: dict[str, Any] = {
                "filter": {
                    "from": start,
                    "to": end,
                },
                "page": {
                    "limit": self.page_size,
                },
                "sort": "-timestamp",
            }
            if cursor:
                payload["page"]["cursor"] = cursor
            if query.strip() and query.strip() != "*":
                payload["filter"]["query"] = query.strip()

            body = self._request_with_retries(payload)
            items = body.get("data", [])
            if not isinstance(items, list) or not items:
                break
            yield [item for item in items if isinstance(item, dict)]
            cursor = (
                body.get("meta", {}).get("page", {}).get("after")
                if isinstance(body.get("meta"), dict)
                else None
            )
            if not cursor:
                break

    def _request_with_retries(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = self.client.post(
                    f"{self.config.base_url}/api/v2/logs/events/search",
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
        detail = _error_detail(last_error)
        raise RuntimeError(f"Datadog fetch failed after 3 attempts: {detail}") from last_error

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        payload = dict(item)
        attributes = item.get("attributes", {})
        if isinstance(attributes, dict):
            payload.update(attributes)
            nested_attributes = attributes.get("attributes", {})
            if isinstance(nested_attributes, dict):
                payload.update(nested_attributes)
        message = str(payload.get("message") or item.get("message") or "")
        timestamp = str(payload.get("timestamp") or item.get("timestamp") or "")
        return LogRecord(timestamp=timestamp, message=message, attributes=payload, source="datadog")


def _error_detail(error: Exception | None) -> str:
    if isinstance(error, httpx.HTTPStatusError) and error.response is not None:
        try:
            payload = error.response.json()
        except Exception:
            payload = None
        if isinstance(payload, dict):
            errors = payload.get("errors")
            if isinstance(errors, list) and errors:
                return f"{error}; API errors: {', '.join(str(item) for item in errors)}"
        text = error.response.text.strip()
        if text:
            return f"{error}; response body: {text}"
    return str(error)
