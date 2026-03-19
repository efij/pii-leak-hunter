from __future__ import annotations

import json
import time
from typing import Any

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.utils.config import SplunkConfig


class SplunkProvider(BaseProvider):
    def __init__(
        self,
        config: SplunkConfig,
        client: httpx.Client | None = None,
    ) -> None:
        self.config = config
        self.client = client or httpx.Client(timeout=10.0)

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        body = self._request_with_retries(
            {
                "search": self._normalize_search(query),
                "earliest_time": start,
                "latest_time": end,
                "output_mode": "json",
            }
        )
        records: list[LogRecord] = []
        for item in body:
            records.append(self._to_record(item))
        return records

    def _request_with_retries(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = self.client.post(
                    f"{self.config.base_url}/services/search/v2/jobs/export",
                    headers=self._headers(),
                    data=payload,
                    auth=self._auth(),
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise httpx.HTTPStatusError(
                        f"Retryable Splunk response: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                return self._parse_stream(response.text)
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"Splunk fetch failed after 3 attempts: {last_error}") from last_error

    def _parse_stream(self, text: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in text.splitlines():
            raw = line.strip()
            if not raw:
                continue
            payload = json.loads(raw)
            if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
                items.append(payload["result"])
            elif isinstance(payload, dict):
                items.append(payload)
        return items

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        message = str(item.get("_raw") or item.get("message") or "")
        timestamp = str(item.get("_time") or item.get("timestamp") or "")
        return LogRecord(timestamp=timestamp, message=message, attributes=item, source="splunk")

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    def _auth(self) -> tuple[str, str] | None:
        if self.config.token:
            return None
        if self.config.username and self.config.password:
            return (self.config.username, self.config.password)
        return None

    def _normalize_search(self, query: str) -> str:
        stripped = query.strip()
        if stripped.startswith("search ") or stripped.startswith("|"):
            return stripped
        return f"search {stripped}"
