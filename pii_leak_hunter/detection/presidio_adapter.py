from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from typing import Any

from pii_leak_hunter.detection.patterns import PII_ENTITY_TYPES

try:
    from presidio_analyzer import AnalyzerEngine
except Exception:  # pragma: no cover - import fallback is environment dependent
    AnalyzerEngine = None  # type: ignore[assignment]


PRESIDIO_ENTITY_MAP = {
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "US_SSN": "US_SSN",
    "CREDIT_CARD": "CREDIT_CARD",
    "PERSON": "PERSON",
    "DATE_TIME": "DATE_OF_BIRTH",
}


@dataclass(slots=True)
class PresidioMatch:
    entity_type: str
    start: int
    end: int
    score: float


class PresidioAdapter:
    def __init__(self) -> None:
        self._engine = self._build_engine()

    @property
    def available(self) -> bool:
        return self._engine is not None

    def analyze(self, text: str) -> list[PresidioMatch]:
        if not self._engine or not text.strip():
            return []
        try:
            results = self._engine.analyze(
                text=text,
                language="en",
                entities=list(PRESIDIO_ENTITY_MAP.keys()),
            )
        except Exception:
            return []

        matches: list[PresidioMatch] = []
        for result in results:
            mapped = PRESIDIO_ENTITY_MAP.get(result.entity_type)
            if not mapped or mapped not in PII_ENTITY_TYPES:
                continue
            matches.append(
                PresidioMatch(
                    entity_type=mapped,
                    start=result.start,
                    end=result.end,
                    score=float(result.score),
                )
            )
        return matches

    def _build_engine(self) -> Any | None:
        if AnalyzerEngine is None:
            return None
        if not any(
            importlib.util.find_spec(model_name)
            for model_name in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm")
        ):
            return None
        try:
            return AnalyzerEngine()
        except Exception:
            return None
