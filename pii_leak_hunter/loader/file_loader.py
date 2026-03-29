from __future__ import annotations

import bz2
import gzip
import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from pii_leak_hunter.core.models import LogRecord

SUPPORTED_SUFFIXES = {".ndjson", ".json", ".log"}
COMPRESSED_SUFFIXES = {".gz", ".bz2", ".zip"}


def load_file(path: str) -> list[LogRecord]:
    file_path = Path(path)
    if file_path.is_dir():
        raise ValueError("load_file expects a file path. Use load_path for directories.")
    return load_path(path)


def load_path(path: str) -> list[LogRecord]:
    file_path = Path(path)
    if file_path.is_dir():
        records: list[LogRecord] = []
        for candidate in sorted(file_path.rglob("*")):
            if candidate.is_file() and is_supported_path(candidate):
                records.extend(load_path(str(candidate)))
        return records

    suffix = file_path.suffix.lower()
    if suffix == ".zip":
        return _load_zip(file_path)
    if suffix in {".gz", ".bz2"}:
        inner_suffix = _resolve_inner_suffix(file_path)
        data = _decompress_file(file_path)
        return load_bytes(data, source_name=file_path.name, forced_suffix=inner_suffix)
    if suffix == ".ndjson":
        return _load_ndjson(file_path)
    if suffix == ".json":
        return _load_json(file_path)
    if suffix == ".log":
        return _load_log(file_path)
    raise ValueError(f"Unsupported file type: {file_path.suffix}")


def load_bytes(data: bytes, source_name: str, forced_suffix: str | None = None) -> list[LogRecord]:
    suffix = forced_suffix or Path(source_name).suffix.lower()
    if suffix == ".zip":
        return _load_zip_bytes(data, source_name)
    if suffix in {".gz", ".bz2"}:
        inner_suffix = _resolve_inner_suffix(Path(source_name))
        decompressed = _decompress_bytes(data, suffix)
        return load_bytes(decompressed, source_name=source_name, forced_suffix=inner_suffix)
    if suffix == ".ndjson":
        return _load_ndjson_text(data.decode("utf-8"), source_name)
    if suffix == ".json":
        return _load_json_text(data.decode("utf-8"), source_name)
    if suffix == ".log":
        return _load_log_text(data.decode("utf-8"), source_name)
    raise ValueError(f"Unsupported file type: {source_name}")


def is_supported_path(path: Path) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if not suffixes:
        return False
    if suffixes[-1] == ".zip":
        return True
    if suffixes[-1] in {".gz", ".bz2"} and len(suffixes) >= 2:
        return suffixes[-2] in SUPPORTED_SUFFIXES
    return suffixes[-1] in SUPPORTED_SUFFIXES


def _load_ndjson(path: Path) -> list[LogRecord]:
    return _load_ndjson_text(path.read_text(encoding="utf-8"), str(path))


def _load_ndjson_text(text: str, source_name: str) -> list[LogRecord]:
    records: list[LogRecord] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        raw = line.strip()
        if not raw:
            continue
        payload = json.loads(raw)
        records.append(_record_from_payload(payload, f"{source_name}:{line_number}"))
    return records


def _load_json(path: Path) -> list[LogRecord]:
    return _load_json_text(path.read_text(encoding="utf-8"), str(path))


def _load_json_text(text: str, source_name: str) -> list[LogRecord]:
    payload = json.loads(text)
    if isinstance(payload, list):
        return [_record_from_payload(item, source_name) for item in payload]
    if isinstance(payload, dict):
        return [_record_from_payload(payload, source_name)]
    raise ValueError("JSON log file must contain an object or an array of objects.")


def _load_log(path: Path) -> list[LogRecord]:
    return _load_log_text(path.read_text(encoding="utf-8"), str(path))


def _load_log_text(text: str, source_name: str) -> list[LogRecord]:
    records: list[LogRecord] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        raw = line.rstrip("\n")
        if not raw.strip():
            continue
        timestamp, message = _split_log_line(raw)
        records.append(
            LogRecord(
                timestamp=timestamp,
                message=message,
                attributes={"line_number": line_number},
                source=source_name,
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


def _resolve_inner_suffix(path: Path) -> str:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if not suffixes:
        raise ValueError(f"Unsupported file type: {path}")
    if suffixes[-1] not in COMPRESSED_SUFFIXES:
        return suffixes[-1]
    if len(suffixes) < 2:
        raise ValueError(f"Compressed file must have a supported inner extension: {path.name}")
    return suffixes[-2]


def _decompress_file(path: Path) -> bytes:
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return gzip.decompress(path.read_bytes())
    if suffix == ".bz2":
        return bz2.decompress(path.read_bytes())
    raise ValueError(f"Unsupported compressed file type: {path.suffix}")


def _decompress_bytes(data: bytes, suffix: str) -> bytes:
    if suffix == ".gz":
        return gzip.decompress(data)
    if suffix == ".bz2":
        return bz2.decompress(data)
    raise ValueError(f"Unsupported compressed file type: {suffix}")


def _load_zip(path: Path) -> list[LogRecord]:
    return _load_zip_bytes(path.read_bytes(), str(path))


def _load_zip_bytes(data: bytes, source_name: str) -> list[LogRecord]:
    records: list[LogRecord] = []
    with zipfile.ZipFile(BytesIO(data)) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            member_path = Path(member.filename)
            if not is_supported_path(member_path):
                continue
            records.extend(
                load_bytes(
                    archive.read(member),
                    source_name=f"{source_name}:{member.filename}",
                )
            )
    return records
