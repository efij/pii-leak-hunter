from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from pii_leak_hunter.core.models import LogRecord


@dataclass(slots=True)
class LoadedSource:
    records: list[LogRecord]
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseSource(ABC):
    @abstractmethod
    def load(self) -> LoadedSource:
        raise NotImplementedError
