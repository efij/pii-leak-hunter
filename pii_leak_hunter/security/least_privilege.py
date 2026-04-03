from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LeastPrivilegePreset:
    integration: str
    title: str
    minimum_access: str
    required_scopes: list[str]
    notes: list[str]


PRESETS: dict[str, LeastPrivilegePreset] = {
    "servicenow": LeastPrivilegePreset(
        integration="servicenow",
        title="ServiceNow read-only table access",
        minimum_access="Read-only API user scoped to the specific tables being scanned.",
        required_scopes=["table.read on target tables", "REST API access"],
        notes=[
            "Avoid admin roles.",
            "Prefer a dedicated integration user limited to incident/task/comment tables in scope.",
        ],
    ),
    "notion": LeastPrivilegePreset(
        integration="notion",
        title="Notion content-read integration",
        minimum_access="Internal integration with read content capability only.",
        required_scopes=["read content"],
        notes=[
            "Share only the pages or spaces that need scanning.",
            "Do not enable write capabilities.",
        ],
    ),
    "slack": LeastPrivilegePreset(
        integration="slack",
        title="Slack read-only history access",
        minimum_access="Bot token limited to channel history read access for approved channels.",
        required_scopes=["channels:history", "groups:history", "im:history", "mpim:history"],
        notes=["Restrict channel membership to the minimum set needed for scanning."],
    ),
    "googleworkspace": LeastPrivilegePreset(
        integration="googleworkspace",
        title="Google Workspace read access",
        minimum_access="Read-only OAuth token scoped to Drive metadata and file content export for approved items.",
        required_scopes=["https://www.googleapis.com/auth/drive.readonly"],
        notes=[
            "Start with Drive and Docs/Sheets export access only.",
            "Avoid Gmail or admin-wide scopes unless those surfaces are explicitly in scope.",
        ],
    ),
    "jira": LeastPrivilegePreset(
        integration="jira",
        title="Jira browse-only project access",
        minimum_access="API token for a service account with browse/read access to scoped projects.",
        required_scopes=["Browse Projects", "View Development Tools if comments link code artifacts"],
        notes=["Do not grant project admin or write permissions."],
    ),
    "confluence": LeastPrivilegePreset(
        integration="confluence",
        title="Confluence page-read access",
        minimum_access="Service account with read-only access to the spaces being scanned.",
        required_scopes=["read:confluence-content.summary", "read:confluence-content.all when page body retrieval is needed"],
        notes=["Scope the integration to the minimum set of spaces and avoid write permissions."],
    ),
    "azuredevops": LeastPrivilegePreset(
        integration="azuredevops",
        title="Azure DevOps read-only project access",
        minimum_access="PAT limited to work item, repository, and pull request read APIs in the target organization/project.",
        required_scopes=["Work Items Read", "Code Read", "Project and Team Read"],
        notes=["Avoid build, release, or write scopes unless those artifacts are explicitly in scope."],
    ),
    "github": LeastPrivilegePreset(
        integration="github",
        title="GitHub read-only app or token",
        minimum_access="GitHub App or token with metadata and read-only issues and pull request discussion access.",
        required_scopes=["metadata:read", "issues:read", "pull_requests:read", "contents:read"],
        notes=["Avoid broad classic PATs when a GitHub App can scope access tighter."],
    ),
    "gitlab": LeastPrivilegePreset(
        integration="gitlab",
        title="GitLab read_api token",
        minimum_access="Project or group token with read_api only.",
        required_scopes=["read_api"],
        notes=["Limit token scope to the group or project being scanned."],
    ),
    "linear": LeastPrivilegePreset(
        integration="linear",
        title="Linear read-only workspace access",
        minimum_access="Viewer-scoped API key limited to issue and comment retrieval.",
        required_scopes=["read issues", "read comments"],
        notes=["Use a dedicated service account outside admin groups."],
    ),
    "monday": LeastPrivilegePreset(
        integration="monday",
        title="monday.com board read access",
        minimum_access="API token for a member with read-only access to in-scope boards/docs.",
        required_scopes=["boards:read", "updates:read", "docs:read when needed"],
        notes=["Avoid account-wide admin tokens when board-level scoping is sufficient."],
    ),
    "teams": LeastPrivilegePreset(
        integration="teams",
        title="Microsoft Teams message read access",
        minimum_access="App registration with the narrowest Microsoft Graph channel/chat read permissions approved by the tenant.",
        required_scopes=["ChannelMessage.Read.All", "Chat.Read.All when chat scanning is needed"],
        notes=["Prefer channel-only access if chat scanning is out of scope."],
    ),
    "zendesk": LeastPrivilegePreset(
        integration="zendesk",
        title="Zendesk ticket read access",
        minimum_access="Read-only API token or OAuth client scoped to search tickets and comments.",
        required_scopes=["tickets:read", "users:read if requester context is needed"],
        notes=["Do not grant write/admin support scopes to the scanning identity."],
    ),
    "snowflake": LeastPrivilegePreset(
        integration="snowflake",
        title="Snowflake query read-only access",
        minimum_access="Programmatic access token or role limited to SELECT on in-scope schemas/tables.",
        required_scopes=["USAGE on warehouse/database/schema", "SELECT on target tables/views"],
        notes=["Avoid ACCOUNTADMIN and prefer a dedicated read-only role for scanning statements."],
    ),
    "cloudwatch": LeastPrivilegePreset(
        integration="cloudwatch",
        title="CloudWatch Logs read access",
        minimum_access="IAM role or user limited to CloudWatch Logs read APIs for approved log groups.",
        required_scopes=["logs:DescribeLogGroups", "logs:FilterLogEvents"],
        notes=["Prefer log-group prefixes or explicit group lists over account-wide access."],
    ),
}


def get_preset(name: str) -> LeastPrivilegePreset | None:
    return PRESETS.get(name.strip().lower())


def validate_preset(name: str, metadata: dict[str, str] | None = None) -> dict[str, str]:
    preset = get_preset(name)
    if preset is None:
        raise ValueError(f"No least-privilege preset found for integration: {name}")
    result = {
        "integration": preset.integration,
        "title": preset.title,
        "status": "informational",
        "minimum_access": preset.minimum_access,
    }
    if metadata and metadata.get("least_privilege_preset"):
        result["configured_preset"] = metadata["least_privilege_preset"]
    return result
