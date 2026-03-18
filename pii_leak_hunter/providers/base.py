from __future__ import annotations

from abc import ABC, abstractmethod

from pii_leak_hunter.core.models import LogRecord


class BaseProvider(ABC):
    @abstractmethod
    def fetch(self, query: str, start: str, end: str) -> list[LogRecord]:
        raise NotImplementedError
