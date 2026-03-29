from __future__ import annotations

import os
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
            raise ConfigurationError("CORALOGIX_REGION is required for Coralogix scans.")
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


def _build_base_url(region: str) -> str:
    if region.startswith("http://") or region.startswith("https://"):
        return region.rstrip("/")
    if "." in region:
        return f"https://{region.rstrip('/')}"
    return f"https://api.{region}.coralogix.com"


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
