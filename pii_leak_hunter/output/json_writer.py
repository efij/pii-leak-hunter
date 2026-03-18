from __future__ import annotations

import json
from pathlib import Path

from pii_leak_hunter.core.models import ScanResult


def write_json(result: ScanResult, path: str, include_values: bool = False) -> None:
    Path(path).write_text(
        json.dumps(result.to_safe_dict(include_values=include_values), indent=2),
        encoding="utf-8",
    )
