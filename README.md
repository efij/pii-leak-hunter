# PII Leak Hunter

**PII Leak Hunter** is an open-source tool for detecting **PII leaks, masking failures, cloud and infrastructure secrets, and dangerous exposure patterns** across logs, files, SaaS records, and operational data sources.

It helps security, AppSec, SecOps, DevSecOps and platform teams identify what should never have reached logs in the first place.

## Highlights

- Detect PII, cloud secrets, infra secrets, and composite exposures.
- Correlate higher-risk scenarios like credential bundles, masking failures, secret+PII overlap, and control-plane leaks.
- Scan local files, compressed archives, databases, object storage, log platforms, and selected SaaS sources.
- Triage findings in a polished Streamlit web console with in-session provider config, target builders, scan progress, grouped findings, baseline diff, a visual exposure graph, and asset-aware context.
- Export safe HTML audit reports, SARIF, and evidence packs for triage, PRs, and security reviews.
- Track least-privilege guidance, exploitability scores, built-in hunt recipes, and first/last-seen spread to focus on the leaks that matter first.

---

## 🔥 Features

- Detect **PII in logs** (SSN, tax IDs, IBAN, cards, etc.)
- Detect **masking failures** (partial or broken redaction)
- Detect **identity bundles** (KYC-level exposure)
- Detect **secrets + PII combinations**
- Detect **cloud and infrastructure secrets** (AWS keys, ARNs, Secrets Manager references, Kubernetes tokens, private keys, IaC tokens)
- **PII detection powered by [Microsoft Presidio](https://github.com/microsoft/presidio) + custom NLP recognizers**
- **Presidio-powered detection + custom recognizers**
- **Safe previews by default** (no raw sensitive data exposed)
- **CLI for automation, CI/CD, and scripting**
- **Streamlit web console** for source selection, credential entry, progress tracking, triage, baseline comparison, and visual exposure graphing
- **Exploitability triage** with priority, score, and triage bucket
- **Hunt recipes** with 20 built-in, modular high-signal workflows for researchers
- **Asset mapping + timeline context** so grouped findings show service/project/env hints and when the leak first or last appeared
- **Static HTML audit report** with masked evidence, exploitability ladder, and print-friendly layout
- Output formats:
  - JSON
  - CSV
  - SARIF
  - Markdown summary
  - HTML audit report
  - Evidence pack (`.zip`)
- Built-in **demo/fixture datasets** for safe testing and screenshots

---

## 🧱 Built with

- [Microsoft Presidio](https://github.com/microsoft/presidio) – PII detection and analysis  
- Python 3.10+  

---

## 🧩 Supported providers

### Current
- **Coralogix** (v1)
- **AWS CloudWatch Logs**
- **Datadog**
- **Dynatrace**
- **Splunk**
- **New Relic**
- **ServiceNow**
- **Notion**
- **Confluence**
- **Jira**
- **Azure DevOps**
- **GitHub**
- **Slack**
- **Google Workspace**
- **Monday**
- **Microsoft Teams**
- **Zendesk**
- **Snowflake**

### Coming soon
- Additional provider tuning and provider-specific query helpers
- Intercom

---

## 🎯 Use cases

- Sensitive data hunting in logs  
- Validating secure logging and masking controls  
- Supporting **Shift-Left DLP (SLDLP)** initiatives  
- Detecting privacy and compliance issues  
- Investigating incidents involving data exposure  
- Post-deployment validation (detect leaks after release)

---

## 🧠 Positioning

PII Leak Hunter is:

- **SLDLP-aligned** (Shift-Left Data Loss Prevention)
- **DSPM-adjacent** (logs are a real data surface)
- **Compliance-supportive** (PCI DSS, GDPR, SOC 2, HIPAA, ISO 27001)
- **Provider-agnostic** (Coralogix-first, multi-provider roadmap)
- **Researcher-friendly** (triage-first, graph-first, workflow-aware)

---

## 🚫 What it is not

- Not a SIEM  
- Not a DSPM platform  
- Not an auto-remediation system  
- Not limited to fintech  

---

## ⚡ Quick start

### 1. Install

```bash
git clone https://github.com/efij/pii-leak-hunter.git
cd pii-leak-hunter

python -m venv .venv
source .venv/bin/activate

pip install -e .
```

---

### 2. Configure

Set your Coralogix credentials:

```bash
export CORALOGIX_API_KEY=your_api_key
export CORALOGIX_REGION=us1
```

`CORALOGIX_REGION` can be either a short region like `us1` or `eu1`, an API host, or your full Coralogix app URL.

Other supported providers use these environment variables:

```bash
# Datadog
export DATADOG_API_KEY=your_api_key
export DATADOG_APP_KEY=your_application_key
export DATADOG_SITE=your_site

# Dynatrace
export DYNATRACE_API_TOKEN=your_api_token
export DYNATRACE_ENV_URL=https://your_environment_url

# Splunk
export SPLUNK_BASE_URL=https://your_splunk_url
export SPLUNK_TOKEN=your_token

# New Relic
export NEW_RELIC_API_KEY=your_user_key
export NEW_RELIC_ACCOUNT_ID=1234567
export NEW_RELIC_REGION=us
```

---

### 3. Run scan (Coralogix)

```bash
pii-leak-hunter scan --out-json findings.json --out-csv findings.csv --fail-on critical
```

That default remote flow means:

- no provider query is required
- the scan window defaults to the past 24 hours
- the engine hunts for secrets, PII, masking failures, and risky combinations across whatever logs are returned
- Coralogix uses a `source logs` DataPrime query by default so “scan everything” does not rely on Lucene wildcard behavior
- If that default Coralogix query comes back empty, the scanner now retries the same window with Lucene wildcard and archive-tier fallbacks before declaring the window empty
- For longer Coralogix windows, the scanner automatically retries archive search when frequent search comes back empty
- When a Coralogix chunk hits the batch cap, the scanner splits the time range and keeps going instead of stopping at the first full batch

Run scan with another provider without knowing its query language:

```bash
pii-leak-hunter scan --provider datadog
```

Run a high-signal recipe instead of sifting through every finding manually:

```bash
pii-leak-hunter scan --provider cloudwatch --recipe prod-credentials
pii-leak-hunter scan github://owner --recipe dev-collaboration
pii-leak-hunter scan slack://workspace?channel_query=incident --recipe incident-war-room
pii-leak-hunter scan googleworkspace://drive --recipe workspace-doc-leaks
pii-leak-hunter recipes
```

The built-in recipes are modular and live in `pii_leak_hunter/hunts/recipes.py`, so adding a new hunt is a small registry change rather than a CLI rewrite.

### 4. Provider and source guidance

- CloudWatch is implemented as a log provider because it behaves like a log backend and fits the existing remote scan path.
- Slack, Google Workspace, Confluence, Jira, Azure DevOps, GitHub, Monday, Microsoft Teams, Zendesk, ServiceNow, and Notion are implemented as sources because they expose messages, documents, tickets, pages, work items, and collaboration threads rather than time-windowed log streams.
- Snowflake is implemented as a read-only source using the SQL API. It scans explicit statements or table queries, which keeps access narrow and predictable.
- GitHub scanning focuses on issues, pull requests, issue comments, and PR review comments. Leave the repository blank to scan all visible repos under an owner. Repository blob and history scanning are still better handled by dedicated tools like gitleaks.
- Azure DevOps scanning covers work items plus pull request titles, descriptions, and review threads across the matching repos in a project.
- Google Workspace support intentionally starts with Drive, Docs, and Sheets content. This complements Google DLP by bringing Workspace findings into the same triage, graph, and cross-source correlation flow as your other systems.
- Monday and Microsoft Teams support focus on the collaboration surface where researchers actually find pasted secrets: boards, item updates, channel messages, and replies.

If you do want to narrow the scope, the provider filter is still available:

```bash
pii-leak-hunter scan --provider datadog --query 'service:your-service'
pii-leak-hunter scan --provider splunk --query 'index=main service="your-service"' --from '-6h'
```

Run scan with a unified target:

```bash
pii-leak-hunter scan fixtures/demo_logs.ndjson
pii-leak-hunter scan file:///absolute/path/to/logs/
pii-leak-hunter scan postgres://user:pass@host:5432/dbname?schema=public&row_limit=1000
pii-leak-hunter scan s3://bucket/path/to/logs/
pii-leak-hunter scan 'servicenow://your-instance-host?table=incident&query=active=true'
pii-leak-hunter scan 'notion://workspace?query=prod&page_size=25'
pii-leak-hunter scan 'github://your-org'
pii-leak-hunter scan 'azuredevops://workspace?organization_url=https://dev.azure.com/your-org&project=security'
pii-leak-hunter scan 'monday://workspace?query=incident'
pii-leak-hunter scan 'teams://workspace?team_query=security'
```

---

### 4. Run UI (Streamlit)

```bash
streamlit run pii_leak_hunter/ui/app.py
```

The web console now includes:

- Remote provider scans with in-session credential fields
- Target / URI builders for local paths, Postgres, S3, ServiceNow, Notion, Confluence, Jira, Azure DevOps, GitHub, Slack, Google Workspace, Monday, Microsoft Teams, Zendesk, and Snowflake
- Local file upload scans
- Default “scan all logs for leaks” mode for remote providers, with optional custom provider filters
- Optional baseline artifact upload from prior safe JSON or evidence packs
- Session scan history and active scan summary
- Visible scan progress instead of fire-and-forget button clicks, including elapsed time, ETA, and a live one-line status for Coralogix window scans
- A `Scan Details` section with the effective provider query, syntax, time window, and parsed row counts for remote scans
- Bounded Coralogix scan batches with partial results and resume support for long-running windows
- Severity and exploitability overview cards
- Grouped findings drill-down with raw values shown in the GUI by default for easier validation
- Built-in least-privilege presets for major integrations
- One-click export for HTML audit reports, JSON, CSV, Markdown, SARIF, and evidence packs

---

### 5. Scan local logs

```bash
pii-leak-hunter scan-file logs.ndjson
```

`scan-file` also supports directories and compressed inputs:

```bash
pii-leak-hunter scan-file ./logs/
pii-leak-hunter scan-file ./rotated/app.ndjson.gz
pii-leak-hunter scan-file ./archives/logs.zip
```

Baseline / diff mode:

```bash
pii-leak-hunter scan-file fixtures/demo_logs.ndjson --baseline-out baseline.json
pii-leak-hunter scan-file fixtures/demo_logs.ndjson --baseline-in baseline.json --new-only
```

Evidence pack export:

```bash
pii-leak-hunter scan-file fixtures/demo_logs.ndjson --out-evidence evidence.zip
```

The Streamlit web console can also generate:

- A standalone HTML audit report for sharing with security, engineering, and leadership
- Filtered exports based on the current findings view
- Baseline-aware triage showing `new`, `unchanged`, and `resolved` findings

Least-privilege presets:

```bash
pii-leak-hunter least-privilege servicenow
pii-leak-hunter least-privilege notion
```

### 6. Run with Docker

Build the image:

```bash
docker build -t pii-leak-hunter .
```

Run the CLI:

```bash
docker run --rm \
  -e DATADOG_API_KEY \
  -e DATADOG_APP_KEY \
  -e DATADOG_SITE \
  pii-leak-hunter \
  pii-leak-hunter scan --provider datadog
```

Run the Streamlit UI:

```bash
docker run --rm -p 8501:8501 \
  -e CORALOGIX_API_KEY \
  -e CORALOGIX_REGION \
  pii-leak-hunter \
  streamlit run pii_leak_hunter/ui/app.py --server.address=0.0.0.0
```

---

## 📊 Example findings

- Unmasked SSN in production logs → **critical**
- Masking failure (raw + masked present) → **critical**
- IBAN with beneficiary context → **high**
- Identity bundle (name + DOB + SSN) → **critical**
- Secret + PII in same payload → **critical**
- AWS access key + secret key in one record → **critical**
- Kubernetes API endpoint + bearer token → **critical**

---

## 🖥️ Web Console

The web console is designed for fast human triage rather than raw data dumping.

- `Remote Provider`: pick Coralogix, Datadog, Dynatrace, Splunk, or New Relic, then enter credentials directly in the UI for the current session
- `Target / URI`: scan host paths or build Postgres, S3, ServiceNow, and Notion targets without assembling the URI by hand
- `Upload File`: upload local artifacts for direct scanning
- `Overview`: review severity totals, exploitability ladder, top entity families, and source metadata
- `Findings`: filter by severity, exploitability, and baseline status, then inspect grouped incidents with raw matches shown by default in the GUI
- `Reports`: export a self-contained HTML audit report plus the existing machine-readable formats, with a separate toggle if you intentionally want raw values in downloads
- `Coralogix resume`: continue a partial wide-window scan instead of restarting from zero

The GUI now shows raw values by default so you can validate findings quickly. Downloads remain guarded unless `Unsafe: include raw values in exports` is explicitly enabled.

---

## 🧾 HTML Audit Report

The HTML audit report is meant to be the default shareable artifact.

- Self-contained single file
- Safe by default with masked previews and hashes
- Severity totals and exploitability ordering
- Grouped incident presentation for repeated leaks
- Remediation steps, blast radius, and policy tags
- Print-friendly layout for browser “Save as PDF”

---

## 🔐 Safety

- No raw sensitive data shown by default  
- Values are masked in output  
- Hash-based correlation only  
- Read-only scanning (no mutations to log providers)  

To show raw values (not recommended):

```bash
--unsafe-show-values
```

---

## 🧱 Detection approach

PII Leak Hunter combines:

- Pattern matching (regex)
- Context-aware detection
- Field-based heuristics
- Multi-entity correlation
- Custom fintech-aware recognizers
- Cloud/infra secret classification
- Blast-radius tagging and remediation hints
- Exploitability-first prioritization
- Baseline/diff workflow
- Exportable evidence packs

This avoids the limitations of regex-only tools.

---

## 🧪 Demo & screenshots

The repository includes **synthetic datasets** for:

- safe demos
- UI screenshots
- CI testing

No real sensitive data is included.

---

## 🛣 Roadmap

- [x] Coralogix provider  
- [x] Datadog provider  
- [x] Dynatrace provider  
- [x] Splunk provider  
- [x] New Relic provider  
- [x] CLI + Streamlit UI  
- [x] ServiceNow source
- [x] Notion source
- [x] Baseline / diff mode
- [x] Evidence packs
- [x] Least-privilege presets
- [ ] CI/CD integration templates  
- [ ] Advanced detection tuning  

---

## 🤝 Contributing

Contributions are welcome.

Focus areas:
- new recognizers
- provider adapters
- performance improvements
- false-positive reduction
- UI enhancements

Please ensure:
- no real PII is included in tests
- all new logic includes tests
- changes remain simple (KISS)

---

## 📄 License

MIT License

---

## 🧠 Final note

> **PII Leak Hunter helps teams detect sensitive data leaks in logs and validate secure logging controls before they become incidents.**
