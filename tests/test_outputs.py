import json
from pathlib import Path

from pii_leak_hunter.core.pipeline import Pipeline
from pii_leak_hunter.loader.file_loader import load_file
from pii_leak_hunter.output.csv_writer import write_csv
from pii_leak_hunter.output.json_writer import write_json
from pii_leak_hunter.output.markdown_writer import write_markdown
from pii_leak_hunter.output.sarif_writer import write_sarif


def test_output_writers_mask_values_by_default(tmp_path: Path) -> None:
    result = Pipeline().run(load_file("fixtures/demo_logs.ndjson"), source="fixture")

    json_path = tmp_path / "findings.json"
    md_path = tmp_path / "findings.md"
    csv_path = tmp_path / "findings.csv"
    sarif_path = tmp_path / "findings.sarif"

    write_json(result, str(json_path))
    write_markdown(result, str(md_path))
    write_csv(result, str(csv_path))
    write_sarif(result, str(sarif_path))

    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "123-45-6789" not in json.dumps(json_payload)
    assert "123-45-6789" not in md_path.read_text(encoding="utf-8")
    assert "123-45-6789" not in csv_path.read_text(encoding="utf-8")
    assert '"version": "2.1.0"' in sarif_path.read_text(encoding="utf-8")
