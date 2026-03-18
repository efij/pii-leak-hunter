from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from pii_leak_hunter.detection.patterns import PATTERNS


@dataclass(frozen=True, slots=True)
class PatternDefinition:
    entity_type: str
    score: float


def iter_pattern_definitions() -> Iterable[PatternDefinition]:
    scores = {
        "EMAIL_ADDRESS": 0.75,
        "PHONE_NUMBER": 0.55,
        "US_SSN": 0.9,
        "CREDIT_CARD": 0.85,
        "IBAN_CODE": 0.9,
        "ROUTING_NUMBER": 0.7,
        "ACCOUNT_NUMBER": 0.65,
        "TAX_ID": 0.8,
        "DATE_OF_BIRTH": 0.65,
        "API_KEY": 0.9,
    }
    for entity_type in PATTERNS:
        yield PatternDefinition(entity_type=entity_type, score=scores.get(entity_type, 0.5))
