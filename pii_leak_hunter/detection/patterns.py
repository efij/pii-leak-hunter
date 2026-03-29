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
    "PRIVATE_KEY_BLOB": re.compile(
        r"-----BEGIN(?: RSA| OPENSSH| EC| DSA| PGP)? PRIVATE KEY-----",
        re.IGNORECASE,
    ),
    "AWS_ACCESS_KEY_ID": re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA|AGPA|AIPA)[A-Z0-9]{16}\b"),
    "AWS_SECRET_ACCESS_KEY": re.compile(
        r"(?i)\b(?:aws(?:_| )?(?:secret(?:_| )?access(?:_| )?key|access(?:_| )?key(?:_| )?secret)|secret_access_key)\b['\"\s:=]{0,6}[A-Za-z0-9/+=]{40}\b"
    ),
    "AWS_SESSION_TOKEN": re.compile(
        r"(?i)\b(?:aws_session_token|session_token)\b['\"\s:=]{0,6}[A-Za-z0-9/+=]{16,4096}"
    ),
    "AWS_SECRET_ARN": re.compile(
        r"\barn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@\-]+\b"
    ),
    "AWS_ROLE_ARN": re.compile(
        r"\barn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_\-/]+\b"
    ),
    "AWS_ARN": re.compile(
        r"\barn:(?:aws|aws-us-gov|aws-cn):[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[A-Za-z0-9+=,.@_/\-:]+\b"
    ),
    "GCP_API_KEY": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "AZURE_STORAGE_CONNECTION_STRING": re.compile(
        r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9\-]+;AccountKey=[A-Za-z0-9+/=]{40,};EndpointSuffix=core\.windows\.net",
        re.IGNORECASE,
    ),
    "AZURE_CLIENT_SECRET": re.compile(
        r"(?i)\bclient_secret\b['\"\s:=]{0,6}[A-Za-z0-9~._\-]{20,}\b"
    ),
    "KUBERNETES_BEARER_TOKEN": re.compile(
        r"(?i)\b(?:bearer|serviceaccount|service-account|kube(?:rnetes)?(?:_token)?)\b[^\n]{0,24}[=:\"'\s]+eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
    ),
    "KUBERNETES_API_SERVER": re.compile(r"\bhttps://[A-Za-z0-9.\-]+(?::6443|:443)\b"),
    "TERRAFORM_CLOUD_TOKEN": re.compile(r"\b(?:atlasv1|tfc)\.[A-Za-z0-9_\-]{16,}\b"),
    "DATADOG_API_KEY": re.compile(
        r"(?i)\b(?:dd_api_key|datadog_api_key|datadog api key)\b['\"\s:=]{0,6}[a-f0-9]{32}\b"
    ),
    "NEW_RELIC_LICENSE_KEY": re.compile(
        r"(?i)\b(?:new[_ ]?relic|nr)[_ ]?(?:license|api)[_ ]?key\b['\"\s:=]{0,6}[A-Za-z0-9]{20,}\b"
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
SECRET_ENTITY_TYPES = {
    "API_KEY",
    "PRIVATE_KEY_BLOB",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GCP_API_KEY",
    "AZURE_STORAGE_CONNECTION_STRING",
    "AZURE_CLIENT_SECRET",
    "KUBERNETES_BEARER_TOKEN",
    "TERRAFORM_CLOUD_TOKEN",
    "DATADOG_API_KEY",
    "NEW_RELIC_LICENSE_KEY",
}
INFRA_IDENTIFIER_ENTITY_TYPES = {
    "AWS_ARN",
    "AWS_SECRET_ARN",
    "AWS_ROLE_ARN",
    "KUBERNETES_API_SERVER",
}
HIGH_IMPACT_SECRET_ENTITY_TYPES = {
    "PRIVATE_KEY_BLOB",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_STORAGE_CONNECTION_STRING",
    "KUBERNETES_BEARER_TOKEN",
}

ENTITY_TAGS: dict[str, list[str]] = {
    "API_KEY": ["secret", "generic"],
    "PRIVATE_KEY_BLOB": ["secret", "infra", "private-key"],
    "AWS_ACCESS_KEY_ID": ["secret", "cloud", "aws", "identity"],
    "AWS_SECRET_ACCESS_KEY": ["secret", "cloud", "aws", "credential"],
    "AWS_SESSION_TOKEN": ["secret", "cloud", "aws", "session"],
    "AWS_SECRET_ARN": ["cloud", "aws", "infra", "secret-reference"],
    "AWS_ROLE_ARN": ["cloud", "aws", "identity", "infra"],
    "AWS_ARN": ["cloud", "aws", "infra"],
    "GCP_API_KEY": ["secret", "cloud", "gcp"],
    "AZURE_STORAGE_CONNECTION_STRING": ["secret", "cloud", "azure", "storage"],
    "AZURE_CLIENT_SECRET": ["secret", "cloud", "azure", "identity"],
    "KUBERNETES_BEARER_TOKEN": ["secret", "infra", "kubernetes", "control-plane"],
    "KUBERNETES_API_SERVER": ["infra", "kubernetes", "control-plane"],
    "TERRAFORM_CLOUD_TOKEN": ["secret", "infra", "terraform", "iac"],
    "DATADOG_API_KEY": ["secret", "observability"],
    "NEW_RELIC_LICENSE_KEY": ["secret", "observability"],
}


def looks_like_name(value: str) -> bool:
    parts = [part for part in re.split(r"\s+", value.strip()) if part]
    if len(parts) < 2 or len(parts) > 4:
        return False
    return all(re.fullmatch(r"[A-Z][a-z]+(?:['-][A-Z][a-z]+)?", part) for part in parts)
