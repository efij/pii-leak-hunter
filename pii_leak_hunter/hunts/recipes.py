from __future__ import annotations

from dataclasses import dataclass, replace

from pii_leak_hunter.core.models import Finding, ScanResult
from pii_leak_hunter.scoring.risk import SEVERITY_ORDER
from pii_leak_hunter.ui.presentation import PRIORITY_ORDER


@dataclass(frozen=True, slots=True)
class HuntRecipe:
    recipe_id: str
    title: str
    description: str
    category: str
    finding_types: tuple[str, ...] = ()
    entity_types: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    min_severity: str | None = None
    min_priority: str | None = None
    keywords: tuple[str, ...] = ()
    provider_queries: dict[str, str] | None = None


def list_recipes() -> list[HuntRecipe]:
    return list(_RECIPES)


def recipe_choices() -> list[str]:
    return [recipe.recipe_id for recipe in _RECIPES]


def get_recipe(recipe_id: str | None) -> HuntRecipe | None:
    if not recipe_id:
        return None
    normalized = recipe_id.strip().lower()
    for recipe in _RECIPES:
        if recipe.recipe_id == normalized:
            return recipe
    return None


def apply_recipe(result: ScanResult, recipe_id: str | None) -> ScanResult:
    recipe = get_recipe(recipe_id)
    if recipe is None:
        return result
    filtered = [finding for finding in result.findings if _matches_recipe(finding, recipe)]
    metadata = dict(result.metadata)
    metadata["hunt_recipe"] = {
        "id": recipe.recipe_id,
        "title": recipe.title,
        "description": recipe.description,
        "category": recipe.category,
        "matched_findings": len(filtered),
        "total_findings": len(result.findings),
    }
    return replace(result, findings=filtered, metadata=metadata)


def _matches_recipe(finding: Finding, recipe: HuntRecipe) -> bool:
    if recipe.finding_types and finding.type not in recipe.finding_types:
        return False
    if recipe.sources and not any(finding.source.startswith(source) for source in recipe.sources):
        return False
    if recipe.min_severity and SEVERITY_ORDER.get(finding.severity, -1) < SEVERITY_ORDER[recipe.min_severity]:
        return False
    priority = str(finding.context.get("exploitability_priority", "P4"))
    if recipe.min_priority and PRIORITY_ORDER.get(priority, 99) > PRIORITY_ORDER[recipe.min_priority]:
        return False
    entity_types = {entity.entity_type for entity in finding.entities}
    if recipe.entity_types and not entity_types.intersection(recipe.entity_types):
        return False
    if recipe.keywords:
        haystack = " ".join(
            [
                finding.safe_summary,
                finding.type,
                str(finding.context),
                " ".join(entity_types),
            ]
        ).lower()
        if not any(keyword.lower() in haystack for keyword in recipe.keywords):
            return False
    return True


_RECIPES: tuple[HuntRecipe, ...] = (
    HuntRecipe(
        "prod-credentials",
        "Production Credential Leak",
        "High-signal hunt for live-looking credentials and privileged token bundles.",
        "credentials",
        entity_types=("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET", "GCP_API_KEY", "API_KEY"),
        min_priority="P2",
    ),
    HuntRecipe(
        "cloud-admin-pivot",
        "Cloud Pivot Material",
        "ARNs, IAM material, and cloud identifiers that help an attacker enumerate or pivot.",
        "cloud",
        entity_types=("AWS_ACCESS_KEY_ID", "AWS_SECRET_ARN", "AWS_ROLE_ARN", "AWS_ARN", "AZURE_CLIENT_SECRET", "GCP_API_KEY"),
        min_severity="medium",
    ),
    HuntRecipe(
        "private-keys",
        "Private Key Exposure",
        "Find private key blobs and related high-privilege signing material immediately.",
        "credentials",
        entity_types=("PRIVATE_KEY_BLOB",),
        min_priority="P0",
    ),
    HuntRecipe(
        "kube-control-plane",
        "Kubernetes Control Plane Exposure",
        "Kubernetes API endpoints, bearer tokens, and kubeconfig-style leaks.",
        "infrastructure",
        finding_types=("control_plane_secret",),
        entity_types=("KUBERNETES_API_SERVER", "KUBERNETES_BEARER_TOKEN"),
    ),
    HuntRecipe(
        "observability-tokens",
        "Observability Platform Tokens",
        "Datadog, New Relic, and similar observability token exposure.",
        "platform",
        entity_types=("DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY"),
    ),
    HuntRecipe(
        "iac-secrets",
        "Infrastructure-as-Code Tokens",
        "Terraform and infrastructure automation tokens with high lateral movement value.",
        "platform",
        entity_types=("TERRAFORM_CLOUD_TOKEN",),
        min_priority="P2",
    ),
    HuntRecipe(
        "identity-bundles",
        "Identity Bundle Exposure",
        "Names coupled with SSNs, DOBs, or financial identifiers in the same record.",
        "privacy",
        finding_types=("identity_bundle",),
        min_severity="high",
    ),
    HuntRecipe(
        "financial-pii",
        "Financial PII",
        "Banking identifiers, IBANs, account numbers, and payment-adjacent leaks.",
        "privacy",
        entity_types=("IBAN_CODE", "ACCOUNT_NUMBER", "ROUTING_NUMBER", "CREDIT_CARD", "TAX_ID"),
        min_severity="medium",
    ),
    HuntRecipe(
        "customer-contact-pii",
        "Customer Contact PII",
        "Email and phone leaks, useful for privacy triage in support and CRM systems.",
        "privacy",
        entity_types=("EMAIL_ADDRESS", "PHONE_NUMBER"),
        min_severity="medium",
    ),
    HuntRecipe(
        "session-and-auth",
        "Session And Auth Leakage",
        "API keys, bearer-like tokens, and auth identifiers with takeover potential.",
        "credentials",
        entity_types=("API_KEY", "KUBERNETES_BEARER_TOKEN", "AWS_SESSION_TOKEN"),
        min_priority="P2",
    ),
    HuntRecipe(
        "secret-plus-pii",
        "Secret + PII Collision",
        "The exact high-value overlap researchers want first: credentials and personal data together.",
        "compound",
        finding_types=("secret_pii_overlap",),
        min_severity="critical",
    ),
    HuntRecipe(
        "masking-failures",
        "Broken Redaction",
        "Find leaks where masking exists but fails, proving control breakdown rather than mere presence.",
        "controls",
        finding_types=("masking_failure",),
        min_severity="high",
    ),
    HuntRecipe(
        "database-secrets",
        "Database Access Material",
        "Connection strings and database-flavored credential exposure.",
        "credentials",
        entity_types=("AZURE_STORAGE_CONNECTION_STRING", "API_KEY"),
        keywords=("database", "postgres", "mysql", "snowflake", "jdbc"),
    ),
    HuntRecipe(
        "support-desk",
        "Support Desk PII & Secrets",
        "High-signal hunt for leaks in tickets, incident notes, and customer support conversations.",
        "workflow",
        sources=("zendesk", "servicenow", "jira"),
        min_severity="medium",
    ),
    HuntRecipe(
        "knowledge-base",
        "Knowledge Base Exposure",
        "Search docs and wikis for pasted credentials, runbooks, and sensitive snippets.",
        "workflow",
        sources=("notion", "confluence", "github", "googleworkspace"),
        min_severity="medium",
    ),
    HuntRecipe(
        "dev-collaboration",
        "Dev Collaboration Leakage",
        "Focus on GitHub, Jira, and Azure DevOps items where secrets are pasted into discussions or comments.",
        "workflow",
        sources=("github", "jira", "azuredevops"),
        min_severity="medium",
    ),
    HuntRecipe(
        "incident-war-room",
        "Incident War Room",
        "Prioritize critical and high issues from collaboration systems during active incidents.",
        "workflow",
        sources=("slack", "teams", "jira", "servicenow", "zendesk", "github", "azuredevops"),
        min_severity="high",
    ),
    HuntRecipe(
        "workspace-doc-leaks",
        "Workspace Document Leaks",
        "Drive, Docs, Sheets, and wiki pages with pasted secrets or sensitive operational data.",
        "workflow",
        sources=("googleworkspace", "notion", "confluence"),
        min_severity="medium",
    ),
    HuntRecipe(
        "payment-workflow",
        "Payments Workflow Exposure",
        "Payment, bank, beneficiary, and customer-finance leakage patterns.",
        "business",
        entity_types=("ACCOUNT_NUMBER", "ROUTING_NUMBER", "IBAN_CODE", "CREDIT_CARD"),
        keywords=("payment", "beneficiary", "customer", "bank"),
        min_severity="medium",
    ),
    HuntRecipe(
        "repeated-secrets",
        "Repeated Secret Spread",
        "Hunt repeated hashes and recurring secret material across multiple records and sources.",
        "graph",
        entity_types=("API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY"),
        min_priority="P2",
    ),
    HuntRecipe(
        "low-noise-criticals",
        "Low Noise Criticals",
        "Only the strongest incidents: bundles, private keys, and critical-risk leaks.",
        "triage",
        finding_types=("credential_bundle", "control_plane_secret", "secret_pii_overlap", "identity_bundle"),
        entity_types=("PRIVATE_KEY_BLOB",),
        min_severity="critical",
    ),
)
