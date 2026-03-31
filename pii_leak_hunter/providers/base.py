from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from pii_leak_hunter.core.models import LogRecord


class BaseProvider(ABC):
    def __init__(self) -> None:
        self.last_fetch_details: dict[str, object] = {}
        self.progress_callback: Callable[[dict[str, Any]], None] | None = None

    def set_progress_callback(self, callback: Callable[[dict[str, Any]], None] | None) -> None:
        self.progress_callback = callback

    def _emit_progress(self, payload: dict[str, Any]) -> None:
        if self.progress_callback is not None:
            self.progress_callback(payload)

    @abstractmethod
    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        raise NotImplementedError
