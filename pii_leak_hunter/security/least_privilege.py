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
    "jira": LeastPrivilegePreset(
        integration="jira",
        title="Jira browse-only project access",
        minimum_access="API token for a service account with browse/read access to scoped projects.",
        required_scopes=["Browse Projects", "View Development Tools if comments link code artifacts"],
        notes=["Do not grant project admin or write permissions."],
    ),
    "github": LeastPrivilegePreset(
        integration="github",
        title="GitHub read-only app or token",
        minimum_access="GitHub App or token with metadata and read-only issues/discussions access.",
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
