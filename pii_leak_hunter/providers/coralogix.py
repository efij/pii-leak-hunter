from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.utils.config import CoralogixConfig


class CoralogixProvider(BaseProvider):
    def __init__(
        self,
        config: CoralogixConfig,
        client: httpx.Client | None = None,
        page_size: int = 500,
    ) -> None:
        self.config = config
        self.client = client or httpx.Client(timeout=10.0)
        self.page_size = page_size

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        records: list[LogRecord] = []
        for page in self._paginate(query=query, start=start, end=end):
            for item in page:
                records.append(self._to_record(item))
        return records

    def _paginate(self, *, query: str, start: str, end: str) -> Iterator[list[dict[str, Any]]]:
        next_token: str | None = None
        for attempt in range(1, 1000):
            payload = {
                "query": query,
                "startTime": start,
                "endTime": end,
                "pageSize": self.page_size,
            }
            if next_token:
                payload["nextPageToken"] = next_token

            body = self._request_with_retries(payload)
            items, next_token = self._extract_items(body)
            if not items:
                break
            yield items
            if not next_token:
                break
            if attempt >= 999:
                break

    def _request_with_retries(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = self.client.post(
                    self._build_url(),
                    headers=self._headers(),
                    json=payload,
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise httpx.HTTPStatusError(
                        f"Retryable Coralogix response: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Coralogix response must be a JSON object.")
                return data
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"Coralogix fetch failed after 3 attempts: {last_error}") from last_error

    def _extract_items(self, body: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
        for key in ("records", "results", "data", "logs"):
            value = body.get(key)
            if isinstance(value, list):
                next_token = body.get("nextPageToken") or body.get("next_page_token")
                return [item for item in value if isinstance(item, dict)], next_token

        if isinstance(body.get("data"), dict):
            data = body["data"]
            for key in ("records", "results", "logs"):
                value = data.get(key)
                if isinstance(value, list):
                    next_token = data.get("nextPageToken") or data.get("next_page_token")
                    return [item for item in value if isinstance(item, dict)], next_token
        return [], None

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        timestamp = str(item.get("timestamp") or item.get("@timestamp") or item.get("time") or "")
        message = str(item.get("message") or item.get("text") or item.get("log") or "")
        return LogRecord(timestamp=timestamp, message=message, attributes=item, source="coralogix")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

    def _build_url(self) -> str:
        return f"{self.config.base_url}/api/v1/logs/search"
