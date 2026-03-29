from __future__ import annotations

import json
import zipfile
from pathlib import Path

from pii_leak_hunter.core.models import ScanResult
from pii_leak_hunter.output.markdown_writer import write_markdown


def write_evidence_pack(result: ScanResult, path: str, include_values: bool = False) -> None:
    target = Path(path)
    if target.suffix.lower() == ".zip":
        _write_zip_pack(result, target, include_values=include_values)
        return
    target.mkdir(parents=True, exist_ok=True)
    _write_pack_files(result, target, include_values=include_values)


def _write_zip_pack(result: ScanResult, path: Path, include_values: bool) -> None:
    temp_dir = path.with_suffix("")
    temp_dir.mkdir(parents=True, exist_ok=True)
    _write_pack_files(result, temp_dir, include_values=include_values)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for child in sorted(temp_dir.iterdir()):
            archive.write(child, arcname=child.name)
    for child in temp_dir.iterdir():
        child.unlink()
    temp_dir.rmdir()


def _write_pack_files(result: ScanResult, directory: Path, include_values: bool) -> None:
    summary_path = directory / "summary.json"
    report_path = directory / "report.md"
    evidence_path = directory / "evidence.json"
    summary_path.write_text(
        json.dumps(
            {
                "source": result.source,
                "records_scanned": result.records_scanned,
                "severity_counts": result.severity_counts(),
                "metadata": result.metadata,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    evidence_path.write_text(
        json.dumps(result.to_safe_dict(include_values=include_values), indent=2),
        encoding="utf-8",
    )
    write_markdown(result, str(report_path), include_values=include_values)
