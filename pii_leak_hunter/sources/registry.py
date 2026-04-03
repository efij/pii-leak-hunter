from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from pii_leak_hunter.sources.azure_devops import AzureDevOpsSource
from pii_leak_hunter.sources.confluence import ConfluenceSource
from pii_leak_hunter.sources.base import BaseSource
from pii_leak_hunter.sources.filesystem import FilesystemSource
from pii_leak_hunter.sources.github import GitHubSource
from pii_leak_hunter.sources.google_workspace import GoogleWorkspaceSource
from pii_leak_hunter.sources.jira import JiraSource
from pii_leak_hunter.sources.monday import MondaySource
from pii_leak_hunter.sources.notion import NotionSource
from pii_leak_hunter.sources.postgres import PostgresSource
from pii_leak_hunter.sources.s3 import S3Source
from pii_leak_hunter.sources.servicenow import ServiceNowSource
from pii_leak_hunter.sources.slack import SlackSource
from pii_leak_hunter.sources.snowflake import SnowflakeSource
from pii_leak_hunter.sources.teams import TeamsSource
from pii_leak_hunter.sources.zendesk import ZendeskSource


def build_source(target: str) -> BaseSource:
    parsed = urlparse(target)
    if parsed.scheme == "file":
        return FilesystemSource(_file_uri_to_path(target))
    if parsed.scheme in {"postgres", "postgresql"}:
        return PostgresSource(target)
    if parsed.scheme == "s3":
        return S3Source(target)
    if parsed.scheme == "confluence":
        return ConfluenceSource(target)
    if parsed.scheme == "jira":
        return JiraSource(target)
    if parsed.scheme in {"ado", "azuredevops"}:
        return AzureDevOpsSource(target)
    if parsed.scheme == "github":
        return GitHubSource(target)
    if parsed.scheme in {"googleworkspace", "gworkspace"}:
        return GoogleWorkspaceSource(target)
    if parsed.scheme == "monday":
        return MondaySource(target)
    if parsed.scheme == "servicenow":
        return ServiceNowSource(target)
    if parsed.scheme == "notion":
        return NotionSource(target)
    if parsed.scheme == "slack":
        return SlackSource(target)
    if parsed.scheme in {"teams", "msteams", "microsoftteams"}:
        return TeamsSource(target)
    if parsed.scheme == "zendesk":
        return ZendeskSource(target)
    if parsed.scheme == "snowflake":
        return SnowflakeSource(target)
    if parsed.scheme == "" and Path(target).exists():
        return FilesystemSource(target)
    raise ValueError(f"Unsupported scan target: {target}")


def is_target_source(target: str | None) -> bool:
    if not target:
        return False
    parsed = urlparse(target)
    if parsed.scheme in {
        "file",
        "postgres",
        "postgresql",
        "s3",
        "confluence",
        "jira",
        "ado",
        "azuredevops",
        "github",
        "googleworkspace",
        "gworkspace",
        "monday",
        "servicenow",
        "notion",
        "slack",
        "teams",
        "msteams",
        "microsoftteams",
        "zendesk",
        "snowflake",
    }:
        return True
    return parsed.scheme == "" and Path(target).exists()


def _file_uri_to_path(uri: str) -> str:
    parsed = urlparse(uri)
    host = parsed.netloc
    path = parsed.path
    if host:
        return f"//{host}{path}"
    return path
