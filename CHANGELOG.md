# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning.

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
