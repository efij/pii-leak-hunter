from __future__ import annotations

from pii_leak_hunter.core.models import Finding
from pii_leak_hunter.detection.patterns import FINANCIAL_ENTITY_TYPES


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def score(finding: Finding) -> str:
    if finding.type == "identity_bundle":
        return "critical"
    if finding.type == "secret_pii_overlap":
        return "critical"
    if finding.type == "masking_failure":
        entity_types = {entity.entity_type for entity in finding.entities}
        if entity_types & {"US_SSN", "ACCOUNT_NUMBER", "IBAN_CODE"}:
            return "critical"
        return "high"

    entity_types = {entity.entity_type for entity in finding.entities}
    if "US_SSN" in entity_types:
        return "critical"
    if entity_types & FINANCIAL_ENTITY_TYPES:
        if len(entity_types) > 1 or _contains_context_keywords(finding):
            return "high"
        return "medium"
    if entity_types & {"EMAIL_ADDRESS", "PHONE_NUMBER", "TAX_ID", "DATE_OF_BIRTH", "PERSON"}:
        return "medium"
    return "low"


def exceeds_threshold(severity: str, threshold: str | None) -> bool:
    if threshold is None:
        return False
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


def _contains_context_keywords(finding: Finding) -> bool:
    summary = finding.safe_summary.lower()
    context = " ".join(str(value).lower() for value in finding.context.values())
    haystack = f"{summary} {context}"
    return any(word in haystack for word in ("payment", "account", "bank", "beneficiary", "customer"))
