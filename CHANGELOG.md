# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning.

## [7.3.0] - 2026-04-17

### Added
- 15 more practical hunt diff signature families, bringing the pack to 80. The new signatures focus on source-aware and asset-aware drift, including source/provider changes, source/blast-radius changes, asset/environment/provider combinations, provider-family severity drift, and source-aware entity movement.

### Changed
- Hunt reruns now make it easier to spot when a known leak family moves to a more dangerous source, starts showing up under a different provider family, or begins clustering around a higher-risk asset/environment combination.

### Verification
- `.venv312/bin/python -m pytest`
- `.venv312/bin/python -m compileall pii_leak_hunter tests`

## [7.2.0] - 2026-04-05

### Added
- 15 more practical hunt diff signature families, bringing the pack to 65. The new signatures cover campaign hash complexity, entity/provider drift, entity/validation drift, source/provider drift, source/validation drift, asset/finding-type drift, source-aware asset severity shifts, and environment-aware drift.

### Changed
- Hunt reruns now surface more investigator-useful movement such as a leak family shifting environments, the same source beginning to carry a different provider family, or an existing asset starting to show a more dangerous finding type.

### Verification
- `.venv312/bin/python -m pytest`
- `.venv312/bin/python -m compileall pii_leak_hunter tests`

## [7.1.0] - 2026-04-04

### Added
- 20 more practical hunt diff signature families, bringing the total pack to 50. The new signatures cover campaign growth buckets, source spread, asset spread, validation drift, provider-family drift, source priority/severity shifts, finding-type drift, and richer asset/provider combinations.

### Changed
- The Streamlit UI now follows a simpler scan -> summary -> campaigns -> reports -> details flow instead of presenting one long wall of controls and metadata.
- The public hunt API now exports diff-signature constants and live-hunt helpers from the package boundary, which makes the CLI and Streamlit imports more stable.

### Verification
- `.venv312/bin/python -m pytest`
- `.venv312/bin/python -m compileall pii_leak_hunter tests`

## [7.0.0] - 2026-04-04

### Added
- First-class asset context with stable asset keys and connector-aware mapping fields across collaboration systems, SaaS tools, and cloud-backed records.
- Timeline and spread analysis for repeated entities and campaign clusters, including first seen, last seen, source spread, and asset spread.
- Validation engine with offline secret checks plus read-only provider validation hooks, currently including AWS pairing-aware STS validation and Datadog API key validation.
- Campaign clustering above raw findings, with cluster metadata now available in scan results, reports, and the exposure graph.
- Live Hunt mode with safe hunt artifacts, cluster-level diffing, and a new `pii-leak-hunter hunt ...` CLI command.
- 30 hunt diff signature families so reruns can detect meaningful change across exact clusters, repeated hashes, assets, sources, asset drift, first/last-seen day, severity, priority, blast radius, validation class, and provider family.

### Changed
- The Streamlit UI now surfaces hunt deltas, top growing campaigns, cluster validation, spread summaries, and hunt artifact downloads.
- HTML and Markdown reports now include campaigns, spread, validation, and hunt-level summaries instead of only flat finding lists.
- The exposure graph now promotes clusters and assets as first-class nodes instead of treating assets as optional leaves.
- This is now versioned as a major release because the scan result shape and primary investigation workflow moved from finding-first to campaign-first.
- The CLI and Streamlit UI now show the running version and direct repository identity, and the CLI help text is clearer about platform usage and hunt diff behavior.

### Verification
- `.venv312/bin/python -m pytest`
- `.venv312/bin/python -m compileall pii_leak_hunter tests`

## [6.2.0] - 2026-04-04

### Added
- monday.com source support for scanning boards, items, and item updates through the GraphQL API.
- Microsoft Teams source support for scanning joined-team channels and replies through Microsoft Graph.

### Changed
- GitHub source coverage now supports owner-wide scans when the repository is left blank, and it now includes PR review comments in addition to issues, pull requests, and issue comments.
- Azure DevOps source coverage now includes pull request titles, descriptions, and review threads across matching repositories in a project instead of stopping at work items.
- The Streamlit target builder now presents platform-level labels for Azure DevOps, GitHub, Slack, Google Workspace, Monday, Microsoft Teams, Zendesk, and Snowflake.
- README guidance now describes the connectors at the platform level while still documenting the exact collaboration surfaces each one scans.

### Verification
- `.venv312/bin/python -m pytest`
- `.venv312/bin/python -m compileall pii_leak_hunter tests`

## [6.1.0] - 2026-04-04

### Added
- Slack source support for channel history scanning, with session-only bot token handling in the Streamlit UI and URI-based scanning in the CLI.
- Google Workspace source support focused on Drive, Docs, and Sheets content via the Drive API, including exported content scanning for native Google file types.
- Lightweight asset mapping on findings so researchers can immediately see service, project, environment, account, cluster, channel, and table context when present in the source record.
- Timeline-aware grouped findings in the UI, including first seen, last seen, and cross-source spread hints.

### Changed
- The Streamlit target builder now includes Slack and Google Workspace forms.
- Hunt recipes now include Workspace-focused and collaboration-focused flows that cover Slack and Google Workspace.
- Google Workspace is positioned as a complement to native Google DLP rather than a replacement, so findings can still be correlated across non-Google systems.

### Verification
- `.venv312/bin/python -m pytest`
- `.venv312/bin/python -m compileall pii_leak_hunter tests`

## [6.0.0] - 2026-04-03

### Added
- A modular hunt recipe framework with 20 built-in high-signal recipes, optional recipe filtering from the CLI and Streamlit UI, and a simple registry model for adding more recipes cleanly.
- A visual exposure graph in the Streamlit UI plus graph JSON export, linking sources, records, findings, and repeated entity hashes into a single investigation surface.
- Stronger exploitability triage with numeric exploitability scores, triage buckets, and a dedicated triage queue in the UI and HTML report.
- New remote log provider support for AWS CloudWatch Logs.
- New content and data source adapters for Confluence, Jira, Azure DevOps work items, GitHub issues and PR discussions, Zendesk, and Snowflake SQL API queries.

### Changed
- The Streamlit target builder now includes dedicated forms for Confluence, Jira, Azure DevOps, GitHub, Zendesk, and Snowflake, while the provider panel now includes CloudWatch configuration.
- Least-privilege presets now cover the newly added integrations so teams can wire them up without over-scoping access.
- GitHub scanning is intentionally scoped to issues, pull requests, and comments rather than repository blobs or history, since dedicated tools like gitleaks already own repo secret scanning better.

### Verification
- `.venv312/bin/python -m pytest`
- `.venv312/bin/python -m compileall pii_leak_hunter tests`

## [5.0.10] - 2026-03-31

### Fixed
- Coralogix short-window scans no longer stop after a single empty `source logs` attempt; the provider now retries Lucene wildcard and archive-tier variants before reporting zero parsed records.

## [5.0.9] - 2026-03-31

### Changed
- Coralogix scans now run in bounded window batches instead of one unbounded recursive pass, which makes progress reporting more stable and prevents “forever” runs.
- Partial Coralogix results can now be resumed from the Streamlit UI, so long scans no longer have to finish in one shot before findings become useful.
- Streamlit upload and export helpers now clean up temporary files immediately instead of leaving them behind on disk.

## [5.0.8] - 2026-03-31

### Changed
- Coralogix scans in the Streamlit UI now emit live runtime progress with a moving progress bar, chunk/tier status, elapsed time, and ETA instead of a static “connecting and loading records” message.
- Coralogix provider callbacks now report per-window activity so the UI can show what is happening while broad scans are still in flight.

## [5.0.7] - 2026-03-31

### Changed
- The Streamlit GUI now shows raw matched values by default so findings can be validated in-app without relying on masked-only previews.
- GUI exports remain separately guarded behind an explicit unsafe export toggle, so on-screen validation no longer forces raw values into downloaded artifacts.

## [5.0.6] - 2026-03-31

### Fixed
- Coralogix no longer stops after a single limit-sized batch for broad DataPrime scans. The provider now splits time windows when a chunk hits the record cap and aggregates the child windows.
- Default Coralogix batch size was raised from `500` to `5000`, which reduces under-sampling before adaptive splitting kicks in.
- Coralogix provider diagnostics now include the number of scanned windows so wide lookbacks are easier to reason about in the CLI and Streamlit UI.

## [5.0.5] - 2026-03-31

### Fixed
- Coralogix long-window scans now fall back from `TIER_FREQUENT_SEARCH` to `TIER_ARCHIVE` when the initial query returns no parsed records, which improves `720h`-style scans.
- Provider diagnostics now include the per-tier attempts used during a Coralogix scan so it is clear whether the tool searched frequent storage, archive, or both.

## [5.0.4] - 2026-03-31

### Fixed
- Coralogix scans now parse DataPrime rows that arrive under `result.results[].userData`, which fixes false `0 record(s)` runs when logs were actually returned.
- Default Coralogix “scan everything” mode now uses a DataPrime `source logs` query instead of a Lucene wildcard.
- The CLI and Streamlit UI now preserve provider fetch details such as the effective query, syntax, window, and parsed row counts so zero-result runs are easier to diagnose.

## [5.0.3] - 2026-03-31

### Changed
- Replaced user-facing tenant-style host examples with generic placeholders in the README, Streamlit UI, and Coralogix regression tests.
- Simplified provider form defaults so the UI no longer pre-fills concrete vendor-style URLs where a user-specific host is required.

## [5.0.2] - 2026-03-31

### Fixed
- Coralogix scans now use the current DataPrime query endpoint instead of the older logs search endpoint that could fail in both the CLI and Streamlit UI.
- Coralogix request payloads now send the documented query metadata, including absolute UTC time windows, so default `-24h` lookbacks work reliably.
- Coralogix responses now handle NDJSON-style query output instead of assuming a legacy JSON object shape.
- `CORALOGIX_REGION` now accepts short region codes, API hosts, and full Coralogix app URLs.
- The Streamlit Coralogix credential form now makes the accepted host and region formats explicit.

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
