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
        page_size: int = 5000,
        min_window: timedelta = timedelta(minutes=15),
    ) -> None:
        super().__init__()
        self.config = config
        self.client = client or httpx.Client(timeout=10.0)
        self.page_size = page_size
        self.min_window = min_window

    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        self._progress_started_at = time.monotonic()
        self._progress_completed = 0
        self._progress_expected = 1
        now = datetime.now(timezone.utc)
        start_dt, end_dt = _resolve_time_window(start, end, now=now)
        normalized_query = query.strip()
        query_syntax = "QUERY_SYNTAX_DATAPRIME" if self._looks_like_dataprime_query(normalized_query) else "QUERY_SYNTAX_LUCENE"
        has_explicit_limit = query_syntax == "QUERY_SYNTAX_DATAPRIME" and "| limit " in normalized_query.lower()
        attempts: list[dict[str, Any]] = []
        self._emit_runtime_progress(
            stage="starting",
            tier="TIER_FREQUENT_SEARCH",
            start_dt=start_dt,
            end_dt=end_dt,
            query=normalized_query,
            note="Preparing Coralogix scan windows",
        )

        primary_records = self._fetch_window_records(
            query=normalized_query,
            start_dt=start_dt,
            end_dt=end_dt,
            tier="TIER_FREQUENT_SEARCH",
            query_syntax=query_syntax,
            has_explicit_limit=has_explicit_limit,
            attempts=attempts,
        )

        records = list(primary_records)
        if not records and _should_try_archive(start_dt, end_dt):
            self._progress_expected += 1
            self._emit_runtime_progress(
                stage="switching_tier",
                tier="TIER_ARCHIVE",
                start_dt=start_dt,
                end_dt=end_dt,
                query=normalized_query,
                note="No parsed records from frequent tier, retrying archive",
            )
            archive_records = self._fetch_window_records(
                query=normalized_query,
                start_dt=start_dt,
                end_dt=end_dt,
                tier="TIER_ARCHIVE",
                query_syntax=query_syntax,
                has_explicit_limit=has_explicit_limit,
                attempts=attempts,
            )
            records = archive_records

        final_attempt = attempts[-1]
        total_elapsed = time.monotonic() - self._progress_started_at
        self.last_fetch_details = {
            "endpoint": self._build_url(),
            "requested_query": normalized_query,
            "effective_query": final_attempt["effective_query"],
            "query_syntax": final_attempt["query_syntax"],
            "tier": final_attempt["tier"],
            "from": final_attempt["from"],
            "to": final_attempt["to"],
            "raw_rows_received": final_attempt["raw_rows_received"],
            "records_parsed": final_attempt["records_parsed"],
            "window_count": len({(attempt["from"], attempt["to"], attempt["tier"]) for attempt in attempts}),
            "elapsed_seconds": round(total_elapsed, 2),
            "attempts": attempts,
        }
        return records

    def _fetch_window_records(
        self,
        *,
        query: str,
        start_dt: datetime,
        end_dt: datetime,
        tier: str,
        query_syntax: str,
        has_explicit_limit: bool,
        attempts: list[dict[str, Any]],
        depth: int = 0,
    ) -> list[LogRecord]:
        self._emit_runtime_progress(
            stage="requesting",
            tier=tier,
            start_dt=start_dt,
            end_dt=end_dt,
            query=query,
            note=f"Querying {tier.lower()} window at depth {depth}",
        )
        payload = self._build_payload(
            query=query,
            start_dt=start_dt,
            end_dt=end_dt,
            tier=tier,
            query_syntax=query_syntax,
            has_explicit_limit=has_explicit_limit,
        )
        items = self._request_with_retries(payload)
        records = [self._to_record(item) for item in items]
        attempts.append(self._build_attempt_details(payload, items, records, depth=depth))
        self._progress_completed += 1
        self._emit_runtime_progress(
            stage="received",
            tier=tier,
            start_dt=start_dt,
            end_dt=end_dt,
            query=payload["query"],
            note=f"Received {len(records)} parsed record(s) from {tier.lower()}",
            raw_rows=len(items),
            parsed_rows=len(records),
            depth=depth,
        )

        if (
            query_syntax == "QUERY_SYNTAX_DATAPRIME"
            and not has_explicit_limit
            and len(records) >= self.page_size
            and (end_dt - start_dt) > self.min_window
        ):
            self._progress_expected += 2
            self._emit_runtime_progress(
                stage="splitting",
                tier=tier,
                start_dt=start_dt,
                end_dt=end_dt,
                query=payload["query"],
                note=f"Chunk hit cap ({self.page_size}); splitting window in half",
                raw_rows=len(items),
                parsed_rows=len(records),
                depth=depth,
            )
            midpoint = start_dt + (end_dt - start_dt) / 2
            left_end = midpoint
            right_start = midpoint + timedelta(milliseconds=1)
            left_records = self._fetch_window_records(
                query=query,
                start_dt=start_dt,
                end_dt=left_end,
                tier=tier,
                query_syntax=query_syntax,
                has_explicit_limit=has_explicit_limit,
                attempts=attempts,
                depth=depth + 1,
            )
            right_records = self._fetch_window_records(
                query=query,
                start_dt=right_start,
                end_dt=end_dt,
                tier=tier,
                query_syntax=query_syntax,
                has_explicit_limit=has_explicit_limit,
                attempts=attempts,
                depth=depth + 1,
            )
            return _dedupe_records(left_records + right_records)
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

    def _build_payload(
        self,
        *,
        query: str,
        start_dt: datetime,
        end_dt: datetime,
        tier: str,
        query_syntax: str,
        has_explicit_limit: bool,
    ) -> dict[str, Any]:
        normalized_query = query.strip()
        metadata = {
            "tier": tier,
            "startDate": _format_datetime(start_dt),
            "endDate": _format_datetime(end_dt),
            "defaultSource": "logs",
        }
        metadata["syntax"] = query_syntax
        if query_syntax == "QUERY_SYNTAX_DATAPRIME":
            final_query = normalized_query if has_explicit_limit else self._ensure_limit(normalized_query)
        else:
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

    def _emit_runtime_progress(
        self,
        *,
        stage: str,
        tier: str,
        start_dt: datetime,
        end_dt: datetime,
        query: str,
        note: str,
        raw_rows: int | None = None,
        parsed_rows: int | None = None,
        depth: int | None = None,
    ) -> None:
        elapsed_seconds = max(0.0, time.monotonic() - getattr(self, "_progress_started_at", time.monotonic()))
        remaining = max(self._progress_expected - self._progress_completed, 0)
        eta_seconds = (elapsed_seconds / self._progress_completed * remaining) if self._progress_completed else None
        progress = self._progress_completed / max(self._progress_expected, 1)
        payload: dict[str, Any] = {
            "provider": "coralogix",
            "stage": stage,
            "tier": tier,
            "query": query,
            "window_start": _format_datetime(start_dt),
            "window_end": _format_datetime(end_dt),
            "completed": self._progress_completed,
            "expected": self._progress_expected,
            "progress": progress,
            "elapsed_seconds": elapsed_seconds,
            "eta_seconds": eta_seconds,
            "note": note,
        }
        if raw_rows is not None:
            payload["raw_rows"] = raw_rows
        if parsed_rows is not None:
            payload["parsed_rows"] = parsed_rows
        if depth is not None:
            payload["depth"] = depth
        self._emit_progress(payload)

    def _build_attempt_details(
        self,
        payload: dict[str, Any],
        items: list[dict[str, Any]],
        records: list[LogRecord],
        *,
        depth: int,
    ) -> dict[str, Any]:
        return {
            "effective_query": payload["query"],
            "query_syntax": payload["metadata"]["syntax"],
            "tier": payload["metadata"]["tier"],
            "from": payload["metadata"]["startDate"],
            "to": payload["metadata"]["endDate"],
            "raw_rows_received": len(items),
            "records_parsed": len(records),
            "depth": depth,
        }


def _to_coralogix_time(value: str, *, now: datetime | None = None) -> str:
    normalized = value.strip()
    reference_now = now or datetime.now(timezone.utc)
    if not normalized or normalized.lower() == "now":
        return _format_datetime(reference_now)

    match = _RELATIVE_TIME_RE.match(normalized)
    if match:
        amount, unit = match.groups()
        delta = {
            "m": timedelta(minutes=int(amount)),
            "h": timedelta(hours=int(amount)),
            "d": timedelta(days=int(amount)),
            "w": timedelta(weeks=int(amount)),
        }[unit]
        return _format_datetime(reference_now - delta)

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


def _should_try_archive(start_dt: datetime, end_dt: datetime) -> bool:
    return (end_dt - start_dt) >= timedelta(days=7)


def _resolve_time_window(start: str, end: str, *, now: datetime) -> tuple[datetime, datetime]:
    start_dt = _parse_time_value(start, now=now)
    end_dt = _parse_time_value(end, now=now)
    if end_dt <= start_dt:
        raise ValueError("Coralogix scan window end must be after the start time.")
    return start_dt, end_dt


def _parse_time_value(value: str, *, now: datetime) -> datetime:
    normalized = _to_coralogix_time(value, now=now)
    iso_value = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    parsed = datetime.fromisoformat(iso_value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _dedupe_records(records: list[LogRecord]) -> list[LogRecord]:
    seen: set[tuple[str, str]] = set()
    deduped: list[LogRecord] = []
    for record in records:
        key = (record.timestamp, record.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped
