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


def _build_base_url(region: str) -> str:
    if region.startswith("http://") or region.startswith("https://"):
        return region.rstrip("/")
    if "." in region:
        return f"https://{region.rstrip('/')}"
    return f"https://api.{region}.coralogix.com"
