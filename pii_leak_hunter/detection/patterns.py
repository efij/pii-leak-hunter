from __future__ import annotations

import re


PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "PHONE_NUMBER": re.compile(r"(?:(?<=\s)|^)(?:\+?\d[\d\-\s().]{7,}\d)"),
    "US_SSN": re.compile(r"\b(?!000|666|9\d\d)\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
    "IBAN_CODE": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "ROUTING_NUMBER": re.compile(r"\b\d{9}\b"),
    "ACCOUNT_NUMBER": re.compile(r"\b\d{10,17}\b"),
    "TAX_ID": re.compile(r"\b\d{2}-\d{7}\b"),
    "DATE_OF_BIRTH": re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"),
    "API_KEY": re.compile(
        r"\b(?:sk_live|sk_test|api[_-]?key|token|secret)[A-Za-z0-9_\-=:]{8,}\b",
        re.IGNORECASE,
    ),
}

FINANCIAL_ENTITY_TYPES = {"IBAN_CODE", "ROUTING_NUMBER", "ACCOUNT_NUMBER", "CREDIT_CARD"}
HIGH_RISK_ENTITY_TYPES = {"US_SSN", "IBAN_CODE", "ACCOUNT_NUMBER", "TAX_ID", "DATE_OF_BIRTH"}
PII_ENTITY_TYPES = {
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "ROUTING_NUMBER",
    "ACCOUNT_NUMBER",
    "TAX_ID",
    "PERSON",
    "DATE_OF_BIRTH",
}
SECRET_ENTITY_TYPES = {"API_KEY"}


def looks_like_name(value: str) -> bool:
    parts = [part for part in re.split(r"\s+", value.strip()) if part]
    if len(parts) < 2 or len(parts) > 4:
        return False
    return all(re.fullmatch(r"[A-Z][a-z]+(?:['-][A-Z][a-z]+)?", part) for part in parts)
