from __future__ import annotations

import hashlib
import hmac
import secrets


class HashingService:
    """Per-run HMAC hashing so values correlate only inside one scan."""

    def __init__(self, secret: bytes | None = None) -> None:
        self._secret = secret or secrets.token_bytes(32)

    def hash_value(self, value: str) -> str:
        digest = hmac.new(self._secret, value.encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()
