from __future__ import annotations

from pii_leak_hunter.providers.base import BaseProvider
from pii_leak_hunter.providers.coralogix import CoralogixProvider
from pii_leak_hunter.providers.datadog import DatadogProvider
from pii_leak_hunter.providers.dynatrace import DynatraceProvider
from pii_leak_hunter.providers.new_relic import NewRelicProvider
from pii_leak_hunter.providers.splunk import SplunkProvider
from pii_leak_hunter.utils.config import (
    CoralogixConfig,
    DatadogConfig,
    DynatraceConfig,
    NewRelicConfig,
    SplunkConfig,
)


SUPPORTED_PROVIDERS = ("coralogix", "datadog", "dynatrace", "splunk", "newrelic")


def build_provider(name: str) -> BaseProvider:
    normalized = normalize_provider_name(name)
    if normalized == "coralogix":
        return CoralogixProvider(CoralogixConfig.from_env())
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
