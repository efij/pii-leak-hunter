from __future__ import annotations

from html import escape
from pathlib import Path

from pii_leak_hunter.core.models import ScanResult
from pii_leak_hunter.ui.presentation import (
    build_diff_summary,
    exploitability_counts,
    group_findings,
    top_triage_rows,
    top_entity_families,
)


def write_html_report(
    result: ScanResult,
    path: str,
    include_values: bool = False,
    baseline: ScanResult | None = None,
) -> None:
    groups = group_findings(result.findings)
    diff = build_diff_summary(result)
    severity_counts = result.severity_counts()
    exploitability = exploitability_counts(result.findings)
    top_entities = top_entity_families(result.findings)
    triage_rows = top_triage_rows(result.findings)
    cards = "".join(
        _metric_card(label, count, tone)
        for label, count, tone in (
            ("Critical", severity_counts.get("critical", 0), "critical"),
            ("High", severity_counts.get("high", 0), "high"),
            ("Medium", severity_counts.get("medium", 0), "medium"),
            ("Low", severity_counts.get("low", 0), "low"),
        )
    )
    delta = ""
    if diff.active:
        delta = """
        <section class="panel">
          <div class="section-head">
            <h2>Baseline Diff</h2>
            <p>Changes against the uploaded safe baseline artifact.</p>
          </div>
          <div class="stats-grid">
            %s%s%s
          </div>
        </section>
        """ % (
            _metric_card("New", diff.new, "critical"),
            _metric_card("Unchanged", diff.unchanged, "neutral"),
            _metric_card("Resolved", diff.resolved, "low"),
        )

    findings_markup = ["<section class=\"panel\"><div class=\"section-head\"><h2>Findings</h2><p>Masked previews and hashes only.</p></div>"]
    if not groups:
        findings_markup.append("<p class=\"empty\">No findings detected.</p>")
    for group in groups:
        findings_markup.append(
            """
            <article class="finding-card tone-%s">
              <div class="finding-top">
                <div>
                  <span class="chip chip-%s">%s</span>
                  <span class="chip chip-priority">%s</span>
                  <h3>%s</h3>
                </div>
                <div class="meta-stack">
                  <span>%s occurrence%s</span>
                  <span>%s</span>
                </div>
              </div>
              <p class="preview">%s</p>
              <div class="meta-grid">
                <div><strong>Entities</strong><span>%s</span></div>
                <div><strong>Hashes</strong><span>%s</span></div>
                <div><strong>Baseline</strong><span>%s</span></div>
              </div>
              %s
            </article>
            """
            % (
                escape(group.severity),
                escape(group.severity),
                escape(group.severity.upper()),
                escape(group.priority),
                escape(group.title),
                group.count,
                "" if group.count == 1 else "s",
                escape(group.finding_type.replace("_", " ")),
                escape(group.preview or "Masked preview unavailable."),
                escape(", ".join(group.entity_types) or "n/a"),
                escape(", ".join(group.hashes) or "n/a"),
                escape(", ".join(group.baseline_statuses) or "current"),
                _finding_details(group.findings, include_values=include_values),
            )
        )
    findings_markup.append("</section>")

    metadata_lines = "".join(
        f"<li><strong>{escape(str(key))}</strong><span>{escape(str(value))}</span></li>"
        for key, value in sorted(result.metadata.items())
        if key != "baseline"
    )
    exploitability_markup = "".join(
        f"<li><span>{escape(priority)}</span><strong>{count}</strong></li>"
        for priority, count in exploitability
    ) or "<li><span>P4</span><strong>0</strong></li>"
    top_entities_markup = "".join(
        f"<li><span>{escape(entity)}</span><strong>{count}</strong></li>"
        for entity, count in top_entities
    ) or "<li><span>None</span><strong>0</strong></li>"
    triage_markup = "".join(
        f"<li><span>{escape(str(row['priority']))} / {escape(str(row['bucket']))}</span><strong>{escape(str(row['summary']))[:120]}</strong></li>"
        for row in triage_rows[:8]
    ) or "<li><span>P4 / backlog</span><strong>No findings</strong></li>"

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PII Leak Hunter Audit Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f2ea;
      --panel: #fffdf8;
      --text: #171411;
      --muted: #6e655d;
      --line: #ddd2c4;
      --accent: #be5b36;
      --critical: #9d2b15;
      --high: #c1551c;
      --medium: #c48a18;
      --low: #2a7e54;
      --neutral: #6f655a;
      --shadow: 0 18px 40px rgba(23, 20, 17, 0.08);
      --radius: 20px;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: linear-gradient(180deg, #f8f5ef 0%%, #f1ebe1 100%%);
      color: var(--text);
      line-height: 1.5;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 48px 24px 64px;
    }}
    h1, h2, h3 {{ margin: 0; text-wrap: balance; }}
    p {{ margin: 0; color: var(--muted); }}
    .hero {{
      display: grid;
      gap: 16px;
      padding: 30px;
      border-radius: 28px;
      background: radial-gradient(circle at top left, rgba(190, 91, 54, 0.18), transparent 42%%), var(--panel);
      border: 1px solid rgba(190, 91, 54, 0.18);
      box-shadow: var(--shadow);
    }}
    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      font-variant-numeric: tabular-nums;
    }}
    .hero-meta span, .chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(190, 91, 54, 0.08);
      color: var(--text);
      font-size: 14px;
    }}
    .chip-critical {{ background: rgba(157, 43, 21, 0.12); color: var(--critical); }}
    .chip-high {{ background: rgba(193, 85, 28, 0.12); color: var(--high); }}
    .chip-medium {{ background: rgba(196, 138, 24, 0.12); color: #8b6109; }}
    .chip-low {{ background: rgba(42, 126, 84, 0.12); color: var(--low); }}
    .chip-priority {{ background: rgba(23, 20, 17, 0.08); }}
    .panel {{
      margin-top: 24px;
      padding: 26px;
      border-radius: var(--radius);
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      margin-bottom: 18px;
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
    }}
    .stat {{
      padding: 18px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: #fff;
    }}
    .stat .label {{
      display: block;
      margin-bottom: 8px;
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .stat .value {{
      font-size: 38px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }}
    .tone-critical .value {{ color: var(--critical); }}
    .tone-high .value {{ color: var(--high); }}
    .tone-medium .value {{ color: #8b6109; }}
    .tone-low .value {{ color: var(--low); }}
    .tone-neutral .value {{ color: var(--neutral); }}
    .two-col {{
      display: grid;
      grid-template-columns: 1.5fr 1fr;
      gap: 18px;
    }}
    .meta-list, .ladder {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 10px;
    }}
    .meta-list li, .ladder li {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 12px;
      border-radius: 14px;
      background: #fff;
      border: 1px solid var(--line);
    }}
    .finding-card {{
      margin-top: 16px;
      padding: 20px;
      border-radius: 18px;
      background: #fff;
      border: 1px solid var(--line);
    }}
    .finding-top {{
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: start;
    }}
    .finding-top h3 {{ margin-top: 10px; }}
    .meta-stack {{
      display: grid;
      gap: 6px;
      color: var(--muted);
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .preview {{
      margin-top: 14px;
      color: var(--text);
      font-family: "SFMono-Regular", "Consolas", monospace;
      background: #faf6ef;
      border-radius: 14px;
      padding: 14px;
      border: 1px dashed var(--line);
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .meta-grid {{
      margin-top: 14px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    .meta-grid div {{
      padding: 12px;
      border-radius: 14px;
      background: #faf7f1;
      border: 1px solid var(--line);
      display: grid;
      gap: 6px;
    }}
    .detail-list {{
      list-style: none;
      padding: 0;
      margin: 16px 0 0;
      display: grid;
      gap: 12px;
    }}
    .detail-list li {{
      padding-top: 12px;
      border-top: 1px solid #ebe1d4;
    }}
    .detail-list strong {{
      display: block;
      margin-bottom: 6px;
    }}
    .detail-list code {{
      font-family: "SFMono-Regular", "Consolas", monospace;
      word-break: break-word;
    }}
    .empty {{
      padding: 16px;
      border-radius: 14px;
      background: #fff;
      border: 1px dashed var(--line);
    }}
    @media print {{
      body {{ background: #fff; }}
      main {{ max-width: none; padding: 24px; }}
      .panel, .hero {{ box-shadow: none; }}
    }}
    @media (max-width: 820px) {{
      .two-col {{
        grid-template-columns: 1fr;
      }}
      .finding-top {{
        flex-direction: column;
      }}
      .meta-stack {{
        text-align: left;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <p>PII Leak Hunter Audit Report</p>
      <h1>Masked incident review for {escape(result.source)}</h1>
      <p>Safe-by-default report with obfuscated findings, severity context, exploitability ranking, and remediation guidance.</p>
      <div class="hero-meta">
        <span>Records Scanned: <strong>{result.records_scanned}</strong></span>
        <span>Findings: <strong>{len(result.findings)}</strong></span>
        <span>Obfuscation: <strong>{"unsafe" if include_values else "safe"}</strong></span>
      </div>
    </section>

    <section class="panel">
      <div class="section-head">
        <h2>Severity Totals</h2>
        <p>Prioritized for triage and sharing.</p>
      </div>
      <div class="stats-grid">{cards}</div>
    </section>

    {delta}

    <section class="panel">
      <div class="section-head">
        <h2>Overview</h2>
        <p>Risk posture at a glance.</p>
      </div>
      <div class="two-col">
        <div>
          <h3>Exploitability Ladder</h3>
          <ul class="ladder">{exploitability_markup}</ul>
        </div>
        <div>
          <h3>Top Entity Families</h3>
          <ul class="ladder">{top_entities_markup}</ul>
        </div>
      </div>
      <div class="two-col" style="margin-top: 18px;">
        <div>
          <h3>Triage Queue</h3>
          <ul class="ladder">{triage_markup}</ul>
        </div>
        <div>
          <h3>Source Metadata</h3>
          <ul class="meta-list">{metadata_lines or '<li><strong>metadata</strong><span>none</span></li>'}</ul>
        </div>
      </div>
      <div class="two-col" style="margin-top: 18px;">
        <div>
          <h3>Report Guarantees</h3>
          <ul class="meta-list">
            <li><strong>Raw Values</strong><span>{"Shown only in unsafe mode" if include_values else "Never shown"}</span></li>
            <li><strong>Finding Display</strong><span>Grouped by incident family or repeated hash</span></li>
            <li><strong>Shareability</strong><span>Print-friendly HTML for browser PDF export</span></li>
          </ul>
        </div>
      </div>
    </section>

    {''.join(findings_markup)}
  </main>
</body>
</html>
"""
    Path(path).write_text(html, encoding="utf-8")


def _metric_card(label: str, value: int, tone: str) -> str:
    return (
        '<div class="stat tone-%s"><span class="label">%s</span><span class="value">%s</span></div>'
        % (escape(tone), escape(label), escape(str(value)))
    )


def _finding_details(findings, *, include_values: bool) -> str:
    items: list[str] = ['<ul class="detail-list">']
    for finding in findings[:8]:
        policy_tags = ", ".join(str(tag) for tag in finding.context.get("policy_tags", []))
        remediation = "; ".join(str(step) for step in finding.context.get("remediation", []))
        reasons = "; ".join(str(reason) for reason in finding.context.get("risk_reasons", []))
        items.append("<li>")
        items.append(f"<strong>{escape(finding.record_id)}</strong>")
        items.append(f"<div>{escape(finding.safe_summary)}</div>")
        items.append(
            "<div><code>%s</code></div>"
            % escape(", ".join(entity.masked_preview for entity in finding.entities if entity.masked_preview))
        )
        items.append(
            "<div>Blast radius: <strong>%s</strong> | Tags: <strong>%s</strong></div>"
            % (
                escape(str(finding.context.get("blast_radius", "application"))),
                escape(policy_tags or "n/a"),
            )
        )
        if reasons:
            items.append(f"<div>Why it matters: {escape(reasons)}</div>")
        if remediation:
            items.append(f"<div>Remediation: {escape(remediation)}</div>")
        if include_values:
            raw_values = [entity.raw_value for entity in finding.entities if entity.raw_value]
            if raw_values:
                items.append(f"<div>Raw values: <code>{escape(', '.join(raw_values))}</code></div>")
        items.append("</li>")
    items.append("</ul>")
    return "".join(items)
