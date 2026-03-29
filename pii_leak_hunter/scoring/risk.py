from __future__ import annotations

from pii_leak_hunter.core.models import Finding
from pii_leak_hunter.detection.patterns import (
    ENTITY_TAGS,
    FINANCIAL_ENTITY_TYPES,
    HIGH_IMPACT_SECRET_ENTITY_TYPES,
)


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def score(finding: Finding) -> str:
    if finding.type == "identity_bundle":
        return "critical"
    if finding.type == "secret_pii_overlap":
        return "critical"
    if finding.type == "credential_bundle":
        return "critical"
    if finding.type == "control_plane_secret":
        return "critical"
    if finding.type == "masking_failure":
        entity_types = {entity.entity_type for entity in finding.entities}
        if entity_types & {"US_SSN", "ACCOUNT_NUMBER", "IBAN_CODE"}:
            return "critical"
        return "high"

    entity_types = {entity.entity_type for entity in finding.entities}
    if entity_types & HIGH_IMPACT_SECRET_ENTITY_TYPES:
        return "high"
    if entity_types & {"AWS_ACCESS_KEY_ID", "GCP_API_KEY", "TERRAFORM_CLOUD_TOKEN", "DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY"}:
        return "high"
    if entity_types & {"AWS_SECRET_ARN", "AWS_ROLE_ARN", "AWS_ARN", "KUBERNETES_API_SERVER"}:
        return "medium"
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


def enrich_finding_context(finding: Finding) -> None:
    entity_types = {entity.entity_type for entity in finding.entities}
    tags = sorted({tag for entity_type in entity_types for tag in ENTITY_TAGS.get(entity_type, [])})
    risk_reasons = _risk_reasons(finding.type, entity_types)
    remediation = _remediation_steps(finding.type, entity_types)
    finding.context.setdefault("exploitability_priority", exploitability_priority(finding))
    finding.context.setdefault("policy_tags", tags)
    finding.context.setdefault("risk_reasons", risk_reasons)
    finding.context.setdefault("remediation", remediation)
    finding.context.setdefault("blast_radius", _blast_radius(entity_types))


def exploitability_priority(finding: Finding) -> str:
    entity_types = {entity.entity_type for entity in finding.entities}
    if "PRIVATE_KEY_BLOB" in entity_types:
        return "P0"
    if finding.type in {"credential_bundle", "control_plane_secret"}:
        return "P0"
    if entity_types & {"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_STORAGE_CONNECTION_STRING", "KUBERNETES_BEARER_TOKEN"}:
        return "P1"
    if entity_types & {"AWS_ACCESS_KEY_ID", "GCP_API_KEY", "TERRAFORM_CLOUD_TOKEN", "DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY", "API_KEY"}:
        return "P2"
    if entity_types & {"AWS_SECRET_ARN", "AWS_ROLE_ARN", "AWS_ARN", "KUBERNETES_API_SERVER"}:
        return "P3"
    return "P2" if finding.severity in {"critical", "high"} else "P4"


def _risk_reasons(finding_type: str, entity_types: set[str]) -> list[str]:
    reasons: list[str] = []
    if finding_type == "credential_bundle":
        reasons.append("Access key material and secret key are exposed together.")
    if finding_type == "control_plane_secret":
        reasons.append("A Kubernetes API endpoint and bearer token appear in the same record.")
    if finding_type == "secret_pii_overlap":
        reasons.append("A secret and personal data appear together, raising account takeover and privacy risk.")
    if entity_types & {"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_STORAGE_CONNECTION_STRING"}:
        reasons.append("The exposed value grants direct cloud or storage access.")
    if entity_types & {"PRIVATE_KEY_BLOB", "KUBERNETES_BEARER_TOKEN"}:
        reasons.append("The exposed material can unlock privileged infrastructure access.")
    if entity_types & {"AWS_SECRET_ARN", "AWS_ROLE_ARN", "AWS_ARN"}:
        reasons.append("The record leaks cloud inventory or privilege context that helps attackers pivot.")
    return reasons


def _remediation_steps(finding_type: str, entity_types: set[str]) -> list[str]:
    steps: list[str] = []
    if finding_type in {"credential_bundle", "secret_pii_overlap", "control_plane_secret"}:
        steps.append("Rotate the exposed credential or token immediately and invalidate active sessions.")
    if entity_types & {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}:
        steps.append("Disable or rotate the IAM key material and review CloudTrail for misuse.")
    if entity_types & {"AWS_SECRET_ARN", "AWS_ROLE_ARN"}:
        steps.append("Review IAM permissions and Secrets Manager access policies tied to the leaked ARN.")
    if entity_types & {"KUBERNETES_BEARER_TOKEN", "KUBERNETES_API_SERVER"}:
        steps.append("Revoke the Kubernetes token, review RBAC bindings, and rotate kubeconfig material.")
    if entity_types & {"AZURE_STORAGE_CONNECTION_STRING", "AZURE_CLIENT_SECRET"}:
        steps.append("Rotate the Azure secret, audit storage/account access logs, and scope credentials down.")
    if entity_types & {"GCP_API_KEY"}:
        steps.append("Restrict or rotate the GCP key and review API usage by source IP and service.")
    if entity_types & {"PRIVATE_KEY_BLOB"}:
        steps.append("Replace the private key and remove any deployed copies from hosts, CI, and secrets stores.")
    if entity_types & {"DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY", "TERRAFORM_CLOUD_TOKEN"}:
        steps.append("Rotate the observability or IaC token and inspect recent automation activity.")
    if not steps:
        steps.append("Remove the secret from logs and add or fix masking/redaction controls.")
    return steps


def _blast_radius(entity_types: set[str]) -> str:
    if entity_types & {"KUBERNETES_BEARER_TOKEN", "KUBERNETES_API_SERVER", "PRIVATE_KEY_BLOB"}:
        return "control-plane"
    if entity_types & {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ROLE_ARN", "AWS_SECRET_ARN", "GCP_API_KEY", "AZURE_STORAGE_CONNECTION_STRING", "AZURE_CLIENT_SECRET"}:
        return "cloud-account"
    if entity_types & {"DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY", "TERRAFORM_CLOUD_TOKEN"}:
        return "platform"
    return "application"
