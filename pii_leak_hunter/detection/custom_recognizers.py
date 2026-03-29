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
        "PRIVATE_KEY_BLOB": 0.98,
        "AWS_ACCESS_KEY_ID": 0.95,
        "AWS_SECRET_ACCESS_KEY": 0.98,
        "AWS_SESSION_TOKEN": 0.92,
        "AWS_SECRET_ARN": 0.65,
        "AWS_ROLE_ARN": 0.6,
        "AWS_ARN": 0.45,
        "GCP_API_KEY": 0.9,
        "AZURE_STORAGE_CONNECTION_STRING": 0.96,
        "AZURE_CLIENT_SECRET": 0.88,
        "KUBERNETES_BEARER_TOKEN": 0.96,
        "KUBERNETES_API_SERVER": 0.55,
        "TERRAFORM_CLOUD_TOKEN": 0.92,
        "DATADOG_API_KEY": 0.9,
        "NEW_RELIC_LICENSE_KEY": 0.88,
    }
    for entity_type in PATTERNS:
        yield PatternDefinition(entity_type=entity_type, score=scores.get(entity_type, 0.5))
