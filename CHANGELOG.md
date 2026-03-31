# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning.

## [5.0.1] - 2026-03-31

### Fixed
- Datadog remote scans now use the current `v2` logs search API instead of the older request shape that could return immediate `400 Bad Request` responses.
- Default Datadog “all logs for leaks” scans now omit the provider query field entirely instead of sending a wildcard query that may be rejected.
- Datadog API failures now include returned error details when available so the GUI shows a more useful failure message.

## [5.0.0] - 2026-03-31

### Added
- A full multi-source Streamlit scan console with tabs for remote providers, target or URI builders, uploaded files, and least-privilege guidance.
- In-session credential and connection forms for Coralogix, Datadog, Dynatrace, Splunk, New Relic, ServiceNow, Notion, and optional AWS-backed S3 scans.
- GUI target builders for local paths, Postgres, S3, ServiceNow, and Notion.
- Visible scan progress, active scan summary, and recent scan history in the GUI.
- GUI baseline artifact export so a web-driven scan can feed the incremental workflow without dropping to the CLI.

### Changed
- The Streamlit UI now covers the main scan flows that previously required CLI or shell environment setup.
- The web console now behaves like an operator console instead of a thin demo layer.
- README guidance now documents session-only provider configuration and the richer GUI workflow.

## [4.0.0] - 2026-03-31

### Added
- Default remote-provider scan mode that hunts across all logs without requiring provider query syntax.
- Shared provider scan defaults for queryless remote scans and a default `-24h` lookback window.
- Streamlit remote scan UX for “all logs for leaks” with optional custom provider filters.

### Changed
- `scan --provider <name>` now works without `--query` or `--from`; both are optional overrides.
- The web console now mirrors the CLI behavior so remote provider scans work even when the operator does not know the provider query language.
- Documentation now teaches the default remote scan flow first and treats provider-native filters as optional narrowing.

## [3.0.0] - 2026-03-30

### Added
- A polished Streamlit web console for scanning, grouped triage, least-privilege guidance, and report export.
- A self-contained HTML audit report with severity totals, exploitability ladder, grouped findings, masked evidence, remediation, and print-friendly styling.
- Shared presentation helpers for grouped finding views and exploitability/entity summaries.
- Baseline artifact upload support in the web console, including safe JSON scan payloads and evidence pack zip files.
- Richer baseline diff metadata with `new`, `unchanged`, and `resolved` counts.

### Changed
- The web UI now supports grouped findings, baseline-aware filtering, and report downloads that follow the active findings view.
- Baseline handling now accepts both classic baseline signature files and safe exported finding payloads.
- Documentation now reflects the Streamlit web console and HTML audit report workflow.

## [2.5.0] - 2026-03-29

### Added
- Cloud and infrastructure secret detection for AWS, Azure, GCP, Kubernetes, Terraform, private keys, and observability tokens.
- Exploitability-first prioritization with explicit `P0` to `P4` priority metadata.
- Credential-bundle and control-plane secret correlation.
- Baseline and diff workflow with `--baseline-in`, `--baseline-out`, and `--new-only`.
- Evidence pack export with masked JSON and Markdown artifacts.
- Least-privilege presets and validation helpers for integrations including ServiceNow, Notion, monday, Linear, Teams, Slack, Jira, GitHub, and GitLab.
- New `ServiceNow` and `Notion` scan sources.
- Safer, richer finding context including remediation, blast radius, policy tags, and risk reasons.

### Changed
- Improved the unified `scan <target>` flow and kept the existing `scan-file` and `scan --provider ...` behavior compatible.
- Extended Markdown reports and the UI to expose exploitability metadata.
- Refined project documentation around sources, evidence packs, and least-privilege guidance.

## [2.0.0] - 2026-03-20

### Added
- Docker support for CLI and Streamlit usage.
- Additional remote providers: Datadog, Dynatrace, Splunk, and New Relic.
- Unified source abstraction for filesystem paths, `file://`, `postgres://`, and `s3://` targets.
- Recursive and compressed file scanning for `.gz`, `.bz2`, and `.zip`.
- Initial Postgres and S3 scan sources.

### Changed
- Expanded the CLI and UI to support more source types and provider selection.

## [1.0.0] - 2026-03-18

### Added
- Initial MVP scanner for PII, masking failures, identity bundles, and secret+PII overlap.
- Coralogix provider, local file scanning, CLI, Streamlit UI, and safe output writers.
- Synthetic fixtures and automated test coverage for the MVP pipeline.
