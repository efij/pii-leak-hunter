from __future__ import annotations

import hashlib
from typing import Any

from pii_leak_hunter.core.models import LogRecord


class Normalizer:
    def normalize(self, record: LogRecord) -> tuple[str, dict[str, str]]:
        flattened = flatten_dict(record.attributes)
        message = record.message or str(flattened.get("message", ""))
        flattened.setdefault("message", message)
        normalized_text = " | ".join(
            f"{key}={value}"
            for key, value in flattened.items()
            if value not in ("", None)
        )
        record.record_id = self.build_record_id(record, normalized_text)
        return normalized_text, {key: str(value) for key, value in flattened.items()}

    @staticmethod
    def build_record_id(record: LogRecord, normalized_text: str) -> str:
        basis = f"{record.source}|{record.timestamp}|{normalized_text}"
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
        return digest[:16]


def flatten_dict(payload: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    items: dict[str, Any] = {}
    for key, value in payload.items():
        new_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            items.update(flatten_dict(value, new_key))
        elif isinstance(value, list):
            items[new_key] = ", ".join(str(item) for item in value)
        else:
            items[new_key] = value
    return items
