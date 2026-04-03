from __future__ import annotations

import os
from urllib.parse import urlparse
from dataclasses import dataclass


class ConfigurationError(RuntimeError):
    """Raised when required runtime configuration is missing."""


@dataclass(slots=True)
class CoralogixConfig:
    api_key: str
    region: str
    base_url: str

    @classmethod
    def from_env(cls) -> "CoralogixConfig":
        api_key = os.getenv("CORALOGIX_API_KEY", "").strip()
        region = os.getenv("CORALOGIX_REGION", "").strip()
        if not api_key:
            raise ConfigurationError("CORALOGIX_API_KEY is required for Coralogix scans.")
        if not region:
            raise ConfigurationError(
                "CORALOGIX_REGION is required for Coralogix scans. Use a region like us1/eu1 or paste your Coralogix app/API host."
            )
        base_url = _build_base_url(region)
        return cls(api_key=api_key, region=region, base_url=base_url)


@dataclass(slots=True)
class DatadogConfig:
    api_key: str
    app_key: str
    site: str
    base_url: str

    @classmethod
    def from_env(cls) -> "DatadogConfig":
        api_key = _required_env("DATADOG_API_KEY", "Datadog scans")
        app_key = _required_env("DATADOG_APP_KEY", "Datadog scans")
        site = os.getenv("DATADOG_SITE", "datadoghq.com").strip() or "datadoghq.com"
        return cls(api_key=api_key, app_key=app_key, site=site, base_url=_build_datadog_url(site))


@dataclass(slots=True)
class DynatraceConfig:
    api_token: str
    environment_url: str

    @classmethod
    def from_env(cls) -> "DynatraceConfig":
        api_token = _required_env("DYNATRACE_API_TOKEN", "Dynatrace scans")
        environment_url = _required_env("DYNATRACE_ENV_URL", "Dynatrace scans")
        return cls(api_token=api_token, environment_url=environment_url.rstrip("/"))


@dataclass(slots=True)
class SplunkConfig:
    base_url: str
    token: str | None = None
    username: str | None = None
    password: str | None = None

    @classmethod
    def from_env(cls) -> "SplunkConfig":
        base_url = _required_env("SPLUNK_BASE_URL", "Splunk scans").rstrip("/")
        token = os.getenv("SPLUNK_TOKEN", "").strip() or None
        username = os.getenv("SPLUNK_USERNAME", "").strip() or None
        password = os.getenv("SPLUNK_PASSWORD", "").strip() or None
        if not token and not (username and password):
            raise ConfigurationError(
                "Splunk scans require SPLUNK_TOKEN or both SPLUNK_USERNAME and SPLUNK_PASSWORD."
            )
        return cls(base_url=base_url, token=token, username=username, password=password)


@dataclass(slots=True)
class NewRelicConfig:
    api_key: str
    account_id: int
    region: str
    base_url: str

    @classmethod
    def from_env(cls) -> "NewRelicConfig":
        api_key = _required_env("NEW_RELIC_API_KEY", "New Relic scans")
        account_id = int(_required_env("NEW_RELIC_ACCOUNT_ID", "New Relic scans"))
        region = os.getenv("NEW_RELIC_REGION", "us").strip().lower() or "us"
        base_url = "https://api.eu.newrelic.com/graphql" if region == "eu" else "https://api.newrelic.com/graphql"
        return cls(api_key=api_key, account_id=account_id, region=region, base_url=base_url)


@dataclass(slots=True)
class ServiceNowConfig:
    username: str | None = None
    password: str | None = None
    bearer_token: str | None = None

    @classmethod
    def from_env(cls) -> "ServiceNowConfig":
        username = os.getenv("SERVICENOW_USERNAME", "").strip() or None
        password = os.getenv("SERVICENOW_PASSWORD", "").strip() or None
        bearer_token = os.getenv("SERVICENOW_BEARER_TOKEN", "").strip() or None
        if bearer_token:
            return cls(bearer_token=bearer_token)
        if username and password:
            return cls(username=username, password=password)
        raise ConfigurationError(
            "ServiceNow scans require SERVICENOW_BEARER_TOKEN or both SERVICENOW_USERNAME and SERVICENOW_PASSWORD."
        )


@dataclass(slots=True)
class NotionConfig:
    api_key: str
    notion_version: str = "2026-03-11"

    @classmethod
    def from_env(cls) -> "NotionConfig":
        api_key = _required_env("NOTION_API_KEY", "Notion scans")
        notion_version = os.getenv("NOTION_VERSION", "2026-03-11").strip() or "2026-03-11"
        return cls(api_key=api_key, notion_version=notion_version)


@dataclass(slots=True)
class CloudWatchConfig:
    region: str | None = None
    log_group_prefix: str | None = None
    log_groups: list[str] | None = None
    max_log_groups: int = 50

    @classmethod
    def from_env(cls) -> "CloudWatchConfig":
        region = os.getenv("AWS_REGION", "").strip() or os.getenv("AWS_DEFAULT_REGION", "").strip() or None
        log_group_prefix = os.getenv("AWS_CLOUDWATCH_LOG_GROUP_PREFIX", "").strip() or None
        groups_value = os.getenv("AWS_CLOUDWATCH_LOG_GROUPS", "").strip()
        log_groups = [item.strip() for item in groups_value.split(",") if item.strip()] or None
        max_log_groups = int(os.getenv("AWS_CLOUDWATCH_MAX_LOG_GROUPS", "50").strip() or "50")
        return cls(
            region=region,
            log_group_prefix=log_group_prefix,
            log_groups=log_groups,
            max_log_groups=max_log_groups,
        )


@dataclass(slots=True)
class ConfluenceConfig:
    base_url: str
    email: str | None = None
    api_token: str | None = None
    bearer_token: str | None = None

    @classmethod
    def from_env(cls) -> "ConfluenceConfig":
        base_url = _required_env("CONFLUENCE_BASE_URL", "Confluence scans").rstrip("/")
        bearer_token = os.getenv("CONFLUENCE_BEARER_TOKEN", "").strip() or None
        if bearer_token:
            return cls(base_url=base_url, bearer_token=bearer_token)
        email = os.getenv("CONFLUENCE_EMAIL", "").strip() or None
        api_token = os.getenv("CONFLUENCE_API_TOKEN", "").strip() or None
        if email and api_token:
            return cls(base_url=base_url, email=email, api_token=api_token)
        raise ConfigurationError(
            "Confluence scans require CONFLUENCE_BEARER_TOKEN or both CONFLUENCE_EMAIL and CONFLUENCE_API_TOKEN."
        )


@dataclass(slots=True)
class JiraConfig:
    base_url: str
    email: str | None = None
    api_token: str | None = None
    bearer_token: str | None = None

    @classmethod
    def from_env(cls) -> "JiraConfig":
        base_url = _required_env("JIRA_BASE_URL", "Jira scans").rstrip("/")
        bearer_token = os.getenv("JIRA_BEARER_TOKEN", "").strip() or None
        if bearer_token:
            return cls(base_url=base_url, bearer_token=bearer_token)
        email = os.getenv("JIRA_EMAIL", "").strip() or None
        api_token = os.getenv("JIRA_API_TOKEN", "").strip() or None
        if email and api_token:
            return cls(base_url=base_url, email=email, api_token=api_token)
        raise ConfigurationError("Jira scans require JIRA_BEARER_TOKEN or both JIRA_EMAIL and JIRA_API_TOKEN.")


@dataclass(slots=True)
class AzureDevOpsConfig:
    organization_url: str
    pat: str

    @classmethod
    def from_env(cls) -> "AzureDevOpsConfig":
        organization_url = _required_env("AZURE_DEVOPS_ORG_URL", "Azure DevOps scans").rstrip("/")
        pat = _required_env("AZURE_DEVOPS_PAT", "Azure DevOps scans")
        return cls(organization_url=organization_url, pat=pat)


@dataclass(slots=True)
class GitHubSourceConfig:
    token: str
    api_base_url: str = "https://api.github.com"

    @classmethod
    def from_env(cls) -> "GitHubSourceConfig":
        token = _required_env("GITHUB_TOKEN", "GitHub scans")
        api_base_url = os.getenv("GITHUB_API_URL", "https://api.github.com").strip() or "https://api.github.com"
        return cls(token=token, api_base_url=api_base_url.rstrip("/"))


@dataclass(slots=True)
class ZendeskConfig:
    base_url: str
    email: str | None = None
    api_token: str | None = None
    bearer_token: str | None = None

    @classmethod
    def from_env(cls) -> "ZendeskConfig":
        base_url = _required_env("ZENDESK_BASE_URL", "Zendesk scans").rstrip("/")
        bearer_token = os.getenv("ZENDESK_BEARER_TOKEN", "").strip() or None
        if bearer_token:
            return cls(base_url=base_url, bearer_token=bearer_token)
        email = os.getenv("ZENDESK_EMAIL", "").strip() or None
        api_token = os.getenv("ZENDESK_API_TOKEN", "").strip() or None
        if email and api_token:
            return cls(base_url=base_url, email=email, api_token=api_token)
        raise ConfigurationError(
            "Zendesk scans require ZENDESK_BEARER_TOKEN or both ZENDESK_EMAIL and ZENDESK_API_TOKEN."
        )


@dataclass(slots=True)
class SnowflakeConfig:
    account_url: str
    token: str
    warehouse: str | None = None
    database: str | None = None
    schema: str | None = None
    role: str | None = None

    @classmethod
    def from_env(cls) -> "SnowflakeConfig":
        account_url = _required_env("SNOWFLAKE_ACCOUNT_URL", "Snowflake scans").rstrip("/")
        token = _required_env("SNOWFLAKE_TOKEN", "Snowflake scans")
        warehouse = os.getenv("SNOWFLAKE_WAREHOUSE", "").strip() or None
        database = os.getenv("SNOWFLAKE_DATABASE", "").strip() or None
        schema = os.getenv("SNOWFLAKE_SCHEMA", "").strip() or None
        role = os.getenv("SNOWFLAKE_ROLE", "").strip() or None
        return cls(
            account_url=account_url,
            token=token,
            warehouse=warehouse,
            database=database,
            schema=schema,
            role=role,
        )


@dataclass(slots=True)
class SlackConfig:
    token: str
    base_url: str = "https://slack.com/api"

    @classmethod
    def from_env(cls) -> "SlackConfig":
        token = _required_env("SLACK_BOT_TOKEN", "Slack scans")
        base_url = os.getenv("SLACK_API_URL", "https://slack.com/api").strip() or "https://slack.com/api"
        return cls(token=token, base_url=base_url.rstrip("/"))


@dataclass(slots=True)
class GoogleWorkspaceConfig:
    token: str
    drive_base_url: str = "https://www.googleapis.com/drive/v3"

    @classmethod
    def from_env(cls) -> "GoogleWorkspaceConfig":
        token = _required_env("GOOGLE_WORKSPACE_TOKEN", "Google Workspace scans")
        drive_base_url = (
            os.getenv("GOOGLE_WORKSPACE_DRIVE_API_URL", "https://www.googleapis.com/drive/v3").strip()
            or "https://www.googleapis.com/drive/v3"
        )
        return cls(token=token, drive_base_url=drive_base_url.rstrip("/"))


@dataclass(slots=True)
class MondayConfig:
    token: str
    api_url: str = "https://api.monday.com/v2"

    @classmethod
    def from_env(cls) -> "MondayConfig":
        token = _required_env("MONDAY_API_TOKEN", "monday.com scans")
        api_url = os.getenv("MONDAY_API_URL", "https://api.monday.com/v2").strip() or "https://api.monday.com/v2"
        return cls(token=token, api_url=api_url.rstrip("/"))


@dataclass(slots=True)
class TeamsConfig:
    token: str
    graph_base_url: str = "https://graph.microsoft.com/v1.0"

    @classmethod
    def from_env(cls) -> "TeamsConfig":
        token = _required_env("TEAMS_GRAPH_TOKEN", "Microsoft Teams scans")
        graph_base_url = (
            os.getenv("TEAMS_GRAPH_API_URL", "https://graph.microsoft.com/v1.0").strip()
            or "https://graph.microsoft.com/v1.0"
        )
        return cls(token=token, graph_base_url=graph_base_url.rstrip("/"))


def _build_base_url(region: str) -> str:
    normalized = region.strip().rstrip("/")
    if normalized.startswith("http://") or normalized.startswith("https://"):
        normalized = urlparse(normalized).netloc or normalized
    normalized = normalized.lower()

    hostname_mapping = {
        "app.coralogix.us": "api.us1.coralogix.com",
        "app.cx498.coralogix.com": "api.us2.coralogix.com",
        "coralogix.com": "api.eu1.coralogix.com",
        "app.eu2.coralogix.com": "api.eu2.coralogix.com",
        "app.coralogix.in": "api.ap1.coralogix.com",
        "app.coralogixsg.com": "api.ap2.coralogix.com",
        "app.ap3.coralogix.com": "api.ap3.coralogix.com",
    }
    for suffix, api_host in hostname_mapping.items():
        if normalized == suffix or normalized.endswith(f".{suffix}"):
            return f"https://{api_host}"
    region_mapping = {
        "us1": "https://api.us1.coralogix.com",
        "us2": "https://api.us2.coralogix.com",
        "eu1": "https://api.eu1.coralogix.com",
        "eu2": "https://api.eu2.coralogix.com",
        "ap1": "https://api.ap1.coralogix.com",
        "ap2": "https://api.ap2.coralogix.com",
        "ap3": "https://api.ap3.coralogix.com",
        "us1.coralogix.com": "https://api.us1.coralogix.com",
        "us2.coralogix.com": "https://api.us2.coralogix.com",
        "eu1.coralogix.com": "https://api.eu1.coralogix.com",
        "eu2.coralogix.com": "https://api.eu2.coralogix.com",
        "ap1.coralogix.com": "https://api.ap1.coralogix.com",
        "ap2.coralogix.com": "https://api.ap2.coralogix.com",
        "ap3.coralogix.com": "https://api.ap3.coralogix.com",
        "api.us1.coralogix.com": "https://api.us1.coralogix.com",
        "api.us2.coralogix.com": "https://api.us2.coralogix.com",
        "api.eu1.coralogix.com": "https://api.eu1.coralogix.com",
        "api.eu2.coralogix.com": "https://api.eu2.coralogix.com",
        "api.ap1.coralogix.com": "https://api.ap1.coralogix.com",
        "api.ap2.coralogix.com": "https://api.ap2.coralogix.com",
        "api.ap3.coralogix.com": "https://api.ap3.coralogix.com",
    }
    if normalized in region_mapping:
        return region_mapping[normalized]
    if "." in normalized:
        return f"https://{normalized}"
    return f"https://api.{normalized}.coralogix.com"


def _build_datadog_url(site: str) -> str:
    if site.startswith("http://") or site.startswith("https://"):
        return site.rstrip("/")
    if site.startswith("api."):
        return f"https://{site}"
    return f"https://api.{site}"


def _required_env(name: str, purpose: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is required for {purpose}.")
    return value
