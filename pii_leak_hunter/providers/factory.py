from __future__ import annotations

from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.providers.cloudwatch import CloudWatchProvider
from pii_leak_hunter.providers.coralogix import CoralogixProvider
from pii_leak_hunter.providers.datadog import DatadogProvider
from pii_leak_hunter.providers.dynatrace import DynatraceProvider
from pii_leak_hunter.providers.new_relic import NewRelicProvider
from pii_leak_hunter.providers.splunk import SplunkProvider
from pii_leak_hunter.utils.config import (
    CoralogixConfig,
    CloudWatchConfig,
    DatadogConfig,
    DynatraceConfig,
    NewRelicConfig,
    SplunkConfig,
)


SUPPORTED_PROVIDERS = ("coralogix", "cloudwatch", "datadog", "dynatrace", "splunk", "newrelic")
DEFAULT_PROVIDER_LOOKBACK = "-24h"
DEFAULT_PROVIDER_QUERIES = {
    "coralogix": "source logs",
    "cloudwatch": "*",
    "datadog": "*",
    "dynatrace": "*",
    "splunk": "*",
    "newrelic": "*",
}
PROVIDER_QUERY_HINTS = {
    "coralogix": 'Optional: source logs | filter log_obj.applicationName == "your-service"',
    "cloudwatch": 'Optional: "?ERROR ?Exception" filter pattern',
    "datadog": "Optional: service:mailer-service",
    "dynatrace": 'Optional: contains(content, "mailer-service")',
    "splunk": 'Optional: index=main service="mailer-service"',
    "newrelic": "Optional: `service.name` = 'mailer-service'",
}


def build_provider(name: str) -> BaseProvider:
    normalized = normalize_provider_name(name)
    if normalized == "coralogix":
        return CoralogixProvider(CoralogixConfig.from_env())
    if normalized == "cloudwatch":
        return CloudWatchProvider(CloudWatchConfig.from_env())
    if normalized == "datadog":
        return DatadogProvider(DatadogConfig.from_env())
    if normalized == "dynatrace":
        return DynatraceProvider(DynatraceConfig.from_env())
    if normalized == "splunk":
        return SplunkProvider(SplunkConfig.from_env())
    if normalized == "newrelic":
        return NewRelicProvider(NewRelicConfig.from_env())
    raise ValueError(f"Unsupported provider: {name}")


def normalize_provider_name(name: str) -> str:
    return name.strip().lower().replace("-", "")


def default_provider_query(name: str) -> str:
    return DEFAULT_PROVIDER_QUERIES.get(normalize_provider_name(name), "*")


def provider_query_hint(name: str) -> str:
    return PROVIDER_QUERY_HINTS.get(normalize_provider_name(name), "Optional provider-native filter")


def resolve_provider_scan_options(
    name: str,
    query: str | None = None,
    start: str | None = None,
) -> tuple[str, str]:
    normalized_query = query.strip() if query and query.strip() else default_provider_query(name)
    normalized_start = start.strip() if start and start.strip() else DEFAULT_PROVIDER_LOOKBACK
    return normalized_query, normalized_start
