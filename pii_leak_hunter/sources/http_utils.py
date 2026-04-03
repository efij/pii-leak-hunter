from __future__ import annotations

import base64
import time
from typing import Any

import httpx


def request_json_with_retries(
    client: httpx.Client,
    *,
    method: str,
    url: str,
    label: str,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    auth: tuple[str, str] | None = None,
    allow_list: bool = False,
) -> Any:
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            response = client.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                auth=auth,
            )
            if response.status_code in {429, 500, 502, 503, 504}:
                raise httpx.HTTPStatusError(
                    f"Retryable {label} response: {response.status_code}",
                    request=response.request,
                    response=response,
                )
            response.raise_for_status()
            payload = response.json()
            if allow_list and isinstance(payload, list):
                return payload
            if not isinstance(payload, dict):
                raise ValueError(f"{label} response must be a JSON object.")
            return payload
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            time.sleep(0.2 * attempt)
    raise RuntimeError(f"{label} fetch failed after 3 attempts: {last_error}") from last_error


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"
