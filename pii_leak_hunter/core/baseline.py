from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pii_leak_hunter.core.models import Finding, ScanResult


def apply_baseline(result: ScanResult, baseline_path: str, new_only: bool = False) -> ScanResult:
    known_signatures = _load_baseline_signatures(baseline_path)
    filtered: list[Finding] = []
    new_count = 0
    existing_count = 0
    for finding in result.findings:
        signature = finding_signature(finding)
        status = "existing" if signature in known_signatures else "new"
        finding.context["baseline_status"] = status
        finding.context["finding_signature"] = signature
        if status == "new":
            new_count += 1
        else:
            existing_count += 1
        if not new_only or status == "new":
            filtered.append(finding)
    result.findings = filtered
    result.metadata["baseline"] = {
        "source": baseline_path,
        "new_findings": new_count,
        "existing_findings": existing_count,
        "new_only": new_only,
    }
    return result


def write_baseline(result: ScanResult, path: str) -> None:
    payload = {
        "signatures": sorted({finding_signature(finding) for finding in result.findings}),
        "metadata": result.metadata,
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def finding_signature(finding: Finding) -> str:
    entity_types = ",".join(sorted(entity.entity_type for entity in finding.entities))
    hashes = ",".join(sorted(_stable_entity_fingerprint(entity) for entity in finding.entities))
    return f"{finding.type}|{finding.source}|{entity_types}|{hashes}"


def _load_baseline_signatures(path: str) -> set[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    signatures = payload.get("signatures", [])
    if not isinstance(signatures, list):
        raise ValueError("Baseline file must contain a signatures list.")
    return {str(item) for item in signatures}


def _stable_entity_fingerprint(entity) -> str:
    if entity.raw_value is not None:
        return hashlib.sha256(entity.raw_value.encode("utf-8")).hexdigest()
    return entity.value_hash
