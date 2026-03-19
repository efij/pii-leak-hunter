from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.utils.config import NewRelicConfig


_RELATIVE_TIME_RE = re.compile(r"^-(\d+)([mhdw])$")


class NewRelicProvider(BaseProvider):
    def __init__(
        self,
        config: NewRelicConfig,
        client: httpx.Client | None = None,
        limit: int = 200,
    ) -> None:
        self.config = config
        self.client = client or httpx.Client(timeout=10.0)
        self.limit = limit

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        nrql = self._build_nrql(query=query, start=start, end=end)
        body = self._request_with_retries(nrql)
        results = (
            body.get("data", {})
            .get("actor", {})
            .get("account", {})
            .get("nrql", {})
            .get("results", [])
        )
        if not isinstance(results, list):
            return []
        return [self._to_record(item) for item in results if isinstance(item, dict)]

    def _request_with_retries(self, nrql: str) -> dict[str, Any]:
        last_error: Exception | None = None
        graphql = {
            "query": (
                "{ actor { account(id: %d) { nrql(query: %s, timeout: 70) { results } } } }"
                % (self.config.account_id, json.dumps(nrql))
            )
        }
        for attempt in range(1, 4):
            try:
                response = self.client.post(
                    self.config.base_url,
                    headers={
                        "Content-Type": "application/json",
                        "API-Key": self.config.api_key,
                    },
                    json=graphql,
                )
                if response.status_code in {429, 500, 502, 503, 504}:
                    raise httpx.HTTPStatusError(
                        f"Retryable New Relic response: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("New Relic response must be a JSON object.")
                if data.get("errors"):
                    raise ValueError(f"New Relic query failed: {data['errors']}")
                return data
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"New Relic fetch failed after 3 attempts: {last_error}") from last_error

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        message = str(item.get("message") or item.get("log") or json.dumps(item, sort_keys=True))
        timestamp = str(item.get("timestamp") or item.get("time") or "")
        return LogRecord(timestamp=timestamp, message=message, attributes=item, source="newrelic")

    def _build_nrql(self, *, query: str, start: str, end: str) -> str:
        stripped = query.strip()
        if stripped.lower().startswith("select "):
            return stripped
        since = _to_nrql_time(start)
        until = _to_nrql_time(end)
        return (
            f"SELECT * FROM Log WHERE {stripped} "
            f"SINCE {since} UNTIL {until} LIMIT {self.limit}"
        )


def _to_nrql_time(value: str) -> str:
    normalized = value.strip()
    if normalized.lower() == "now":
        return "NOW"
    match = _RELATIVE_TIME_RE.match(normalized)
    if not match:
        return json.dumps(normalized)
    amount, unit = match.groups()
    words = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}[unit]
    return f"{amount} {words} ago"
