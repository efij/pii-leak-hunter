from __future__ import annotations

from abc import ABC, abstractmethod

from pii_leak_hunter.core.models import LogRecord


class BaseProvider(ABC):
    def __init__(self) -> None:
        self.last_fetch_details: dict[str, object] = {}

    @abstractmethod
    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        raise NotImplementedError
