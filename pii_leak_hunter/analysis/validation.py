from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any

import httpx

from pii_leak_hunter.core.models import Finding, ValidationResult


class ValidationEngine:
    def __init__(self, http_client: httpx.Client | None = None) -> None:
        self.http_client = http_client or httpx.Client(timeout=5.0)

    def validate_entities(self, findings: list[Finding], validation_context: dict[str, str] | None = None) -> dict[str, object]:
        validation_context = validation_context or {}
        family_counts: dict[str, int] = defaultdict(int)
        provider_checks = 0
        likely_live = 0

        for finding in findings:
            results = self._validate_finding(finding, validation_context)
            finding.context["validation"] = [item.to_safe_dict() for item in results]
            for result in results:
                family_counts[result.provider_family] += 1
                if result.provider_check_run:
                    provider_checks += 1
                if result.classification == "likely_live":
                    likely_live += 1

        return {
            "families": dict(sorted(family_counts.items())),
            "provider_checks_run": provider_checks,
            "likely_live_findings": likely_live,
        }

    def _validate_finding(self, finding: Finding, validation_context: dict[str, str]) -> list[ValidationResult]:
        entity_types = {entity.entity_type for entity in finding.entities}
        entity_values = {
            entity.entity_type: (entity.raw_value or "")
            for entity in finding.entities
            if entity.raw_value
        }
        results: list[ValidationResult] = []
        for entity in finding.entities:
            family = _provider_family(entity.entity_type, entity.raw_value or "")
            results.append(
                self._validate_entity(
                    entity.entity_type,
                    entity.raw_value or "",
                    family,
                    entity_types,
                    entity_values,
                    validation_context,
                )
            )
        return _dedupe_validation_results(results)

    def _validate_entity(
        self,
        entity_type: str,
        raw_value: str,
        family: str,
        entity_types: set[str],
        entity_values: dict[str, str],
        validation_context: dict[str, str],
    ) -> ValidationResult:
        evidence: list[str] = []
        syntactically_valid = _looks_syntactically_valid(entity_type, raw_value, evidence)
        paired = _is_paired(entity_type, entity_types)
        if paired:
            evidence.append("Supporting secret pair found in the same finding.")

        if not syntactically_valid:
            return ValidationResult(
                classification="invalid_or_rejected",
                provider_family=family,
                entity_type=entity_type,
                evidence=evidence or ["The value failed basic syntax checks."],
                confidence="high",
                supporting_entity_types=sorted(entity_types - {entity_type}),
            )

        provider_result = self._provider_check(entity_type, raw_value, family, paired, entity_values, validation_context)
        if provider_result is not None:
            provider_result.supporting_entity_types = sorted(entity_types - {entity_type})
            return provider_result

        classification = "paired" if paired else "syntactically_valid"
        return ValidationResult(
            classification=classification,
            provider_family=family,
            entity_type=entity_type,
            evidence=evidence or ["The value passed offline format and structure checks."],
            confidence="medium",
            provider_check_run=False,
            supporting_entity_types=sorted(entity_types - {entity_type}),
        )

    def _provider_check(
        self,
        entity_type: str,
        raw_value: str,
        family: str,
        paired: bool,
        entity_values: dict[str, str],
        validation_context: dict[str, str],
    ) -> ValidationResult | None:
        if family == "aws" and entity_type == "AWS_SECRET_ACCESS_KEY" and paired:
            access_key = _extract_secret_value(entity_values.get("AWS_ACCESS_KEY_ID", "")) or validation_context.get("AWS_ACCESS_KEY_ID")
            if not access_key:
                return ValidationResult(
                    classification="insufficient_scope",
                    provider_family=family,
                    entity_type=entity_type,
                    evidence=["AWS secret key detected but the matching access key was not available for a read-only STS check."],
                    confidence="medium",
                    provider_check_run=False,
                )
            return _aws_sts_check(access_key, _extract_secret_value(raw_value))
        if family == "datadog" and entity_type == "DATADOG_API_KEY":
            api_key = _extract_secret_value(raw_value)
            response = self.http_client.get(
                "https://api.datadoghq.com/api/v1/validate",
                headers={"DD-API-KEY": api_key},
            )
            if response.status_code == 200:
                payload = response.json()
                valid = bool(payload.get("valid"))
                return ValidationResult(
                    classification="likely_live" if valid else "invalid_or_rejected",
                    provider_family=family,
                    entity_type=entity_type,
                    evidence=["Datadog validate endpoint accepted the API key." if valid else "Datadog validate endpoint rejected the API key."],
                    confidence="high",
                    provider_check_run=True,
                )
            return ValidationResult(
                classification="insufficient_scope",
                provider_family=family,
                entity_type=entity_type,
                evidence=[f"Datadog validation endpoint returned HTTP {response.status_code}."],
                confidence="low",
                provider_check_run=True,
            )
        return None


def _provider_family(entity_type: str, raw_value: str) -> str:
    if entity_type.startswith("AWS_"):
        return "aws"
    if entity_type.startswith("GCP_"):
        return "gcp"
    if entity_type.startswith("AZURE_"):
        return "azure"
    if entity_type.startswith("KUBERNETES_"):
        return "kubernetes"
    if entity_type.startswith("DATADOG_"):
        return "datadog"
    if entity_type.startswith("NEW_RELIC_"):
        return "newrelic"
    if entity_type.startswith("TERRAFORM_"):
        return "terraform"
    if entity_type == "API_KEY" and raw_value.startswith(("ghp_", "github_pat_")):
        return "github"
    if entity_type == "API_KEY" and raw_value.startswith("xox"):
        return "slack"
    return "generic"


def _looks_syntactically_valid(entity_type: str, raw_value: str, evidence: list[str]) -> bool:
    value = _extract_secret_value(raw_value)
    if entity_type == "AWS_ACCESS_KEY_ID":
        valid = bool(re.fullmatch(r"(?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA|AGPA|AIPA)[A-Z0-9]{16}", value))
    elif entity_type == "AWS_SECRET_ACCESS_KEY":
        valid = len(value) == 40 and bool(re.fullmatch(r"[A-Za-z0-9/+=]{40}", value))
    elif entity_type == "AWS_SESSION_TOKEN":
        valid = len(value) >= 16
    elif entity_type == "GCP_API_KEY":
        valid = value.startswith("AIza") and len(value) == 39
    elif entity_type == "DATADOG_API_KEY":
        valid = bool(re.fullmatch(r"[a-f0-9]{32}", value.lower()))
    elif entity_type == "NEW_RELIC_LICENSE_KEY":
        valid = len(value) >= 20
    elif entity_type == "AZURE_CLIENT_SECRET":
        valid = len(value) >= 20
    elif entity_type == "AZURE_STORAGE_CONNECTION_STRING":
        valid = "AccountKey=" in value and "AccountName=" in value
    elif entity_type == "KUBERNETES_BEARER_TOKEN":
        valid = value.count(".") == 2 and value.startswith("eyJ")
    elif entity_type == "TERRAFORM_CLOUD_TOKEN":
        valid = value.startswith(("atlasv1.", "tfc.")) and len(value) >= 20
    elif entity_type == "PRIVATE_KEY_BLOB":
        valid = "PRIVATE KEY" in value
    else:
        valid = len(value) >= 8 and _shannon_entropy(value) >= 2.8
    evidence.append("The value matched the expected provider-specific format." if valid else "The value did not match the expected provider-specific format.")
    return valid


def _is_paired(entity_type: str, entity_types: set[str]) -> bool:
    return (
        entity_type == "AWS_SECRET_ACCESS_KEY" and "AWS_ACCESS_KEY_ID" in entity_types
    ) or (
        entity_type == "AWS_ACCESS_KEY_ID" and "AWS_SECRET_ACCESS_KEY" in entity_types
    ) or (
        entity_type == "KUBERNETES_BEARER_TOKEN" and "KUBERNETES_API_SERVER" in entity_types
    )


def _dedupe_validation_results(results: list[ValidationResult]) -> list[ValidationResult]:
    unique: dict[tuple[str, str, str], ValidationResult] = {}
    for result in results:
        key = (result.entity_type, result.provider_family, result.classification)
        if key not in unique:
            unique[key] = result
    return list(unique.values())


def _extract_secret_value(raw_value: str) -> str:
    if "=" not in raw_value and ":" not in raw_value:
        return raw_value.strip().strip("'\"")
    parts = re.split(r"[=:]", raw_value, maxsplit=1)
    if len(parts) == 2:
        return parts[1].strip().strip("'\"")
    return raw_value.strip().strip("'\"")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = defaultdict(int)
    for char in value:
        counts[char] += 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _aws_sts_check(access_key: str, secret_key: str) -> ValidationResult:
    try:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1}),
        )
        identity = client.get_caller_identity()
        account = str(identity.get("Account") or "")
        arn = str(identity.get("Arn") or "")
        return ValidationResult(
            classification="likely_live",
            provider_family="aws",
            entity_type="AWS_SECRET_ACCESS_KEY",
            evidence=[f"STS GetCallerIdentity succeeded for account {account or 'unknown'} {arn}".strip()],
            confidence="high",
            provider_check_run=True,
        )
    except Exception as exc:
        return ValidationResult(
            classification="invalid_or_rejected",
            provider_family="aws",
            entity_type="AWS_SECRET_ACCESS_KEY",
            evidence=[f"STS GetCallerIdentity failed: {exc}"],
            confidence="medium",
            provider_check_run=True,
        )
