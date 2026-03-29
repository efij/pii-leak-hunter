from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pii_leak_hunter.core.models import Finding, ScanResult


def apply_baseline(result: ScanResult, baseline_path: str, new_only: bool = False) -> ScanResult:
    payload = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    return apply_baseline_payload(result, payload, new_only=new_only, baseline_source=baseline_path)


def apply_baseline_payload(
    result: ScanResult,
    payload: dict[str, Any],
    new_only: bool = False,
    baseline_source: str = "uploaded",
) -> ScanResult:
    known_signatures = extract_baseline_signatures(payload)
    filtered: list[Finding] = []
    new_count = 0
    existing_count = 0
    current_signatures: set[str] = set()
    for finding in result.findings:
        signature = finding_signature(finding)
        current_signatures.add(signature)
        status = "existing" if signature in known_signatures else "new"
        finding.context["baseline_status"] = status
        finding.context["finding_signature"] = signature
        if status == "new":
            new_count += 1
        else:
            existing_count += 1
        if not new_only or status == "new":
            filtered.append(finding)
    resolved_count = len(known_signatures - current_signatures)
    result.findings = filtered
    result.metadata["baseline"] = {
        "source": baseline_source,
        "new_findings": new_count,
        "existing_findings": existing_count,
        "unchanged_findings": existing_count,
        "resolved_findings": resolved_count,
        "total_baseline_signatures": len(known_signatures),
        "total_current_signatures": len(current_signatures),
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


def extract_baseline_signatures(payload: dict[str, Any]) -> set[str]:
    signatures = payload.get("signatures")
    if isinstance(signatures, list):
        return {str(item) for item in signatures}
    findings = payload.get("findings")
    if isinstance(findings, list):
        return {
            _mapping_signature(item)
            for item in findings
            if isinstance(item, dict)
        }
    raise ValueError("Baseline file must contain a signatures list or findings payload.")


def _stable_entity_fingerprint(entity) -> str:
    if entity.raw_value is not None:
        return hashlib.sha256(entity.raw_value.encode("utf-8")).hexdigest()
    return entity.value_hash


def _mapping_signature(payload: dict[str, Any]) -> str:
    finding_type = str(payload.get("type", "entity_detection"))
    source = str(payload.get("source", "unknown"))
    entities = payload.get("entities", [])
    entity_types: list[str] = []
    hashes: list[str] = []
    if isinstance(entities, list):
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            entity_type = entity.get("entity_type")
            if entity_type is not None:
                entity_types.append(str(entity_type))
            raw_value = entity.get("raw_value")
            value_hash = entity.get("value_hash")
            if isinstance(raw_value, str):
                hashes.append(hashlib.sha256(raw_value.encode("utf-8")).hexdigest())
            elif value_hash is not None:
                hashes.append(str(value_hash))
    entity_types_key = ",".join(sorted(entity_types))
    hashes_key = ",".join(sorted(hashes))
    return f"{finding_type}|{source}|{entity_types_key}|{hashes_key}"
