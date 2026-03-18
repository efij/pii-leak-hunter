from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pii_leak_hunter.core.models import LogRecord


def load_file(path: str) -> list[LogRecord]:
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix == ".ndjson":
        return _load_ndjson(file_path)
    if suffix == ".json":
        return _load_json(file_path)
    if suffix == ".log":
        return _load_log(file_path)
    raise ValueError(f"Unsupported file type: {file_path.suffix}")


def _load_ndjson(path: Path) -> list[LogRecord]:
    records: list[LogRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            payload = json.loads(raw)
            records.append(_record_from_payload(payload, f"{path.name}:{line_number}"))
    return records


def _load_json(path: Path) -> list[LogRecord]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        return [_record_from_payload(item, path.name) for item in payload]
    if isinstance(payload, dict):
        return [_record_from_payload(payload, path.name)]
    raise ValueError("JSON log file must contain an object or an array of objects.")


def _load_log(path: Path) -> list[LogRecord]:
    records: list[LogRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            timestamp, message = _split_log_line(raw)
            records.append(
                LogRecord(
                    timestamp=timestamp,
                    message=message,
                    attributes={"line_number": line_number},
                    source=str(path),
                )
            )
    return records


def _record_from_payload(payload: dict[str, Any], source: str) -> LogRecord:
    if not isinstance(payload, dict):
        raise ValueError("Each log entry must be a JSON object.")
    timestamp = str(
        payload.get("timestamp")
        or payload.get("@timestamp")
        or payload.get("time")
        or ""
    )
    message = str(payload.get("message") or payload.get("msg") or payload.get("log") or "")
    attributes = dict(payload)
    return LogRecord(timestamp=timestamp, message=message, attributes=attributes, source=source)


def _split_log_line(line: str) -> tuple[str, str]:
    parts = line.split(" ", 1)
    if len(parts) == 2 and ("T" in parts[0] or parts[0].count("-") >= 2):
        return parts[0], parts[1]
    return "", line
