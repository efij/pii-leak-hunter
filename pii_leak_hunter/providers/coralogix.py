from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from pii_leak_hunter.core.models import LogRecord
from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.utils.config import CoralogixConfig


_RELATIVE_TIME_RE = re.compile(r"^-(\d+)([mhdw])$")


class CoralogixProvider(BaseProvider):
    def __init__(
        self,
        config: CoralogixConfig,
        client: httpx.Client | None = None,
        page_size: int = 500,
    ) -> None:
        super().__init__()
        self.config = config
        self.client = client or httpx.Client(timeout=10.0)
        self.page_size = page_size

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        payload = self._build_payload(query=query, start=start, end=end)
        items = self._request_with_retries(payload)
        records = [self._to_record(item) for item in items]
        self.last_fetch_details = {
            "endpoint": self._build_url(),
            "requested_query": query,
            "effective_query": payload["query"],
            "query_syntax": payload["metadata"]["syntax"],
            "from": payload["metadata"]["startDate"],
            "to": payload["metadata"]["endDate"],
            "raw_rows_received": len(items),
            "records_parsed": len(records),
        }
        return records

    def _request_with_retries(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
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
                return self._parse_response(response)
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                last_error = exc
                if attempt >= 3:
                    break
                time.sleep(0.2 * attempt)
        raise RuntimeError(f"Coralogix fetch failed after 3 attempts: {self._format_error(last_error)}") from last_error

    def _parse_response(self, response: httpx.Response) -> list[dict[str, Any]]:
        text = response.text.strip()
        if not text:
            return []

        parsed_lines: list[dict[str, Any]] = []
        try:
            body = response.json()
        except json.JSONDecodeError:
            body = None
        if body is not None:
            parsed_lines.extend(self._collect_records(body))
        else:
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                parsed_lines.extend(self._collect_records(entry))
        return parsed_lines

    def _collect_records(self, payload: Any) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        self._walk_payload(payload, records)
        return records

    def _walk_payload(self, payload: Any, records: list[dict[str, Any]]) -> None:
        if isinstance(payload, list):
            for item in payload:
                self._walk_payload(item, records)
            return
        if not isinstance(payload, dict):
            return

        normalized_row = self._normalize_data_row(payload)
        if normalized_row is not None:
            records.append(normalized_row)
            return

        if any(key in payload for key in ("message", "text", "log", "_raw", "body", "content")):
            records.append(payload)
            return
        if any(key in payload for key in ("timestamp", "@timestamp", "time", "_time")) and payload:
            records.append(payload)
            return

        for key in ("result", "results", "records", "logs", "data", "userData", "record", "items", "hits"):
            if key in payload:
                self._walk_payload(payload[key], records)

    def _normalize_data_row(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        user_data = payload.get("userData")
        if user_data is None:
            return None

        parsed_user_data = self._parse_user_data(user_data)
        if isinstance(parsed_user_data, dict):
            record = dict(parsed_user_data)
        else:
            record = {"message": str(parsed_user_data)}

        for field in ("message", "text", "log", "_raw", "body", "content"):
            if field in payload and field not in record:
                record[field] = payload[field]

        metadata = payload.get("metadata")
        if isinstance(metadata, list):
            record["coralogix_metadata"] = metadata
            extracted_timestamp = _extract_field_from_pairs(metadata, {"timestamp", "@timestamp", "time", "_time"})
            if extracted_timestamp and "timestamp" not in record and "@timestamp" not in record and "time" not in record:
                record["timestamp"] = extracted_timestamp
        elif isinstance(metadata, dict):
            record["coralogix_metadata"] = metadata
            extracted_timestamp = (
                metadata.get("timestamp") or metadata.get("@timestamp") or metadata.get("time") or metadata.get("_time")
            )
            if extracted_timestamp and "timestamp" not in record and "@timestamp" not in record and "time" not in record:
                record["timestamp"] = extracted_timestamp

        labels = payload.get("labels")
        if isinstance(labels, list):
            record["coralogix_labels"] = labels
        elif isinstance(labels, dict):
            record["coralogix_labels"] = labels

        for key, value in payload.items():
            if key not in {"userData", "metadata", "labels"} and key not in record:
                record[key] = value
        return record

    def _parse_user_data(self, user_data: Any) -> Any:
        if isinstance(user_data, dict):
            return user_data
        if isinstance(user_data, str):
            stripped = user_data.strip()
            if not stripped:
                return ""
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return stripped
        return user_data

    def _to_record(self, item: dict[str, Any]) -> LogRecord:
        timestamp = str(item.get("timestamp") or item.get("@timestamp") or item.get("time") or item.get("_time") or "")
        message = str(
            item.get("message")
            or item.get("text")
            or item.get("log")
            or item.get("_raw")
            or item.get("body")
            or item.get("content")
            or json.dumps(item, sort_keys=True)
        )
        return LogRecord(timestamp=timestamp, message=message, attributes=item, source="coralogix")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/x-ndjson, application/json",
        }

    def _build_url(self) -> str:
        return f"{self.config.base_url}/api/v1/dataprime/query"

    def _build_payload(self, *, query: str, start: str, end: str) -> dict[str, Any]:
        normalized_query = query.strip()
        metadata = {
            "tier": "TIER_FREQUENT_SEARCH",
            "startDate": _to_coralogix_time(start),
            "endDate": _to_coralogix_time(end),
            "defaultSource": "logs",
        }
        if self._looks_like_dataprime_query(normalized_query):
            metadata["syntax"] = "QUERY_SYNTAX_DATAPRIME"
            final_query = self._ensure_limit(normalized_query)
        else:
            metadata["syntax"] = "QUERY_SYNTAX_LUCENE"
            final_query = normalized_query or "*"
        return {"query": final_query, "metadata": metadata}

    def _ensure_limit(self, query: str) -> str:
        lowered = query.lower()
        if "| limit " in lowered:
            return query
        return f"{query} | limit {self.page_size}"

    def _looks_like_dataprime_query(self, query: str) -> bool:
        normalized = query.strip().lower()
        if normalized in {"", "*"}:
            return False
        return "|" in normalized or normalized.startswith("source ")

    def _format_error(self, error: Exception | None) -> str:
        if isinstance(error, httpx.HTTPStatusError) and error.response is not None:
            details = error.response.text.strip()
            if details:
                return f"{error} | response={details}"
        return str(error)


def _to_coralogix_time(value: str) -> str:
    normalized = value.strip()
    now = datetime.now(timezone.utc)
    if not normalized or normalized.lower() == "now":
        return _format_datetime(now)

    match = _RELATIVE_TIME_RE.match(normalized)
    if match:
        amount, unit = match.groups()
        delta = {
            "m": timedelta(minutes=int(amount)),
            "h": timedelta(hours=int(amount)),
            "d": timedelta(days=int(amount)),
            "w": timedelta(weeks=int(amount)),
        }[unit]
        return _format_datetime(now - delta)

    iso_value = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        return normalized
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return _format_datetime(parsed)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _extract_field_from_pairs(pairs: list[Any], candidate_keys: set[str]) -> str | None:
    for item in pairs:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or item.get("name") or "").strip().lower()
        if key in candidate_keys:
            value = item.get("value")
            if value is not None:
                return str(value)
    return None
