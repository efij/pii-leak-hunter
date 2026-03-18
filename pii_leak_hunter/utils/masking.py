from __future__ import annotations

import re


MASK_TOKEN_RE = re.compile(r"(?:[\*xX#]\s*){3,}([A-Za-z0-9]{2,6})")


def mask_value(value: str, visible: int = 2) -> str:
    if len(value) <= visible:
        return "*" * len(value)
    visible_tail = value[-visible:]
    return "*" * max(len(value) - visible, 0) + visible_tail


def masked_preview(text: str, start: int, end: int, radius: int = 20) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    sensitive = text[start:end]
    preview = text[left:start] + mask_value(sensitive) + text[end:right]
    return sanitize_preview(preview.replace("\n", " "))


def extract_mask_candidates(text: str) -> set[str]:
    candidates: set[str] = set()
    for match in MASK_TOKEN_RE.finditer(text):
        tail = re.sub(r"\W+", "", match.group(1))
        if tail:
            candidates.add(tail[-4:])
    return candidates


def digits_only(value: str) -> str:
    return re.sub(r"\D+", "", value)


def sanitize_preview(preview: str) -> str:
    from pii_leak_hunter.detection.patterns import PATTERNS

    scrubbed = preview
    for pattern in PATTERNS.values():
        scrubbed = pattern.sub(lambda match: mask_value(match.group(0)), scrubbed)
    return scrubbed
