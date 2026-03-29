from __future__ import annotations

from pathlib import Path

from pii_leak_hunter.loader.file_loader import load_path
from pii_leak_hunter.sources.base import BaseSource, LoadedSource


class FilesystemSource(BaseSource):
    def __init__(self, path: str) -> None:
        self.path = path

    def load(self) -> LoadedSource:
        records = load_path(self.path)
        return LoadedSource(
            records=records,
            source=str(Path(self.path)),
            metadata={"mode": "file"},
        )
