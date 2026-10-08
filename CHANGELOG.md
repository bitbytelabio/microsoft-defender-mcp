# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-08

### Breaking Changes

- **Granular mode removed**: The legacy 88-tool granular catalog has been removed. The server now exclusively exposes domain-oriented action tools (up to 10 tools depending on category enablement; 6 tools under `--read-only`).
- **`--tool-mode` and `DEFENDER_TOOL_MODE` removed**: The CLI option `--tool-mode` and environment variable `DEFENDER_TOOL_MODE` have been removed. If provided (even if empty), server startup exits non-zero with an explicit migration error message.
- **`defender_response` hidden by default**: Mutating response actions (`collect_investigation_package`, `stop_and_quarantine_file`, `live_response_run`, `upload_library_file`, `library_file_delete`) are now hidden from `tools/list` unless explicitly enabled via `--enable-live-response` (`DEFENDER_ENABLE_LIVE_RESPONSE=true`) and `--read-only` is not set.
- **Every `defender_response` call is confirmed and audited**: destructive actions now ask the human user to confirm through MCP form elicitation. Clients without elicitation support get `confirmation_unavailable` unless the server runs with `--disable-human-confirmation`. Each attempt is written to the audit log first; if the log cannot be written, the call is rejected with `audit_unavailable`.
- **`upload_library_file` justification**: `description` is the audited justification for this action and must contain at least 10 characters after trimming.

### Added

- **Consolidated Domain-Tool Catalog**:
  - `defender_hunting` (read-only): Advanced Hunting KQL query execution (`run`).
  - `defender_ti` (read-only): Threat intelligence lookups (39 TI actions) and new `custom_indicator_list` action.
  - `defender_incidents_alerts` (read-only): XDR and Endpoint alerts and incidents investigation (10 actions).
  - `defender_machines` (read-only): Endpoint device inventory and indicator correlation, plus new read pivots: `find_by_ip`, `machine_alerts`, `machine_vulnerabilities`, `machine_missing_kbs`.
  - `defender_vulnerabilities` (read-only): Threat & Vulnerability Management (TVM) software, vulnerabilities, recommendations, remediation tasks, and exposure scores (20 actions).
  - `defender_forensics` (read-only): Forensic artifact inspection and local staging, plus new actions: `investigation_list`, `investigation_get`, `library_file_list`.
  - `defender_response` (mutating, destructive): Live Response session execution, library file management (`upload_library_file`, new `library_file_delete`), investigation package collection, and file quarantine. Gated by `--enable-live-response`.
  - `defender_device_response` (new, mutating, destructive): Device containment and management actions: `isolate`, `unisolate`, `restrict_app_execution`, `unrestrict_app_execution`, `run_av_scan`, `start_investigation`, `cancel_machine_action`, `tag_add`, `tag_remove`, `set_device_value`, and `offboard`. Gated by `--enable-device-response`; `offboard` additionally requires `--enable-offboarding`.
  - `defender_indicators` (new, mutating, destructive): Custom indicator lifecycle management: `submit` (create/update), `delete`, and `batch_delete`. Gated by `--enable-indicators`.
  - `defender_triage` (new, mutating, non-destructive): Alert and incident triage write-back: `endpoint_alert_update`, `endpoint_alert_batch_update`, `endpoint_alert_comment`, `xdr_alert_update`, `xdr_alert_comment`, `xdr_incident_update`, `xdr_incident_comment`. Gated by `--enable-triage`.
- **Delegated User Sign-In (`--auth-mode user`)**:
  - Interactive browser sign-in with PKCE and device code flow fallback (`--sign-in-flow <auto|browser|device-code>`).
  - Multi-audience token acquisition for Microsoft Graph and Defender for Endpoint APIs using individual user authority and device group scoping.
  - In-memory credential caching and single-flight silent background token renewal without persistent token storage.
- **Human Confirmation via MCP Elicitation**:
  - Interactive confirmation prompt (`Form` elicitation mode) required before running destructive actions on `defender_response`, `defender_device_response`, and `defender_indicators`.
  - `--disable-human-confirmation` (`DEFENDER_DISABLE_HUMAN_CONFIRMATION=true`) flag to bypass prompts for trusted automated pipelines (records `turned_off` in audit log).
  - `defender_triage` is non-destructive and requires no confirmation prompt.
- **Mutation Audit Log (`--audit-log`)**:
  - Append-only JSON Lines audit file created with mode `0600` (parent directory `0700`).
  - Fails closed: intent records must be committed to disk before any mutating request is dispatched upstream.
  - Records timestamp, attempt ID, tool, action, targets, parameters, justification, acting identity, confirmation outcome, and operation result without ever logging credential secrets or tokens.
- **Category Enablement Flags**:
  - `--enable-device-response` (`DEFENDER_ENABLE_DEVICE_RESPONSE`)
  - `--enable-offboarding` (`DEFENDER_ENABLE_OFFBOARDING`, requires `--enable-device-response`)
  - `--enable-indicators` (`DEFENDER_ENABLE_INDICATORS`)
  - `--enable-triage` (`DEFENDER_ENABLE_TRIAGE`)
  - `--disable-human-confirmation` (`DEFENDER_DISABLE_HUMAN_CONFIRMATION`)
  - `--audit-log` (`DEFENDER_AUDIT_LOG`)
  - `--auth-mode` (`DEFENDER_AUTH_MODE`)
  - `--sign-in-flow` (`DEFENDER_SIGN_IN_FLOW`)

### Granular Tool Migration Table

| Removed granular tool | Domain tool | `action` |
|-----------------------|-------------|----------|
| `defender_advanced_hunting_run` | `defender_hunting` | `run` |
| `defender_ti_intel_profiles_list` | `defender_ti` | `intel_profiles_list` |
| `defender_ti_intel_profile_get` | `defender_ti` | `intel_profile_get` |
| `defender_ti_intel_profile_indicators_list` | `defender_ti` | `intel_profile_indicators_list` |
| `defender_ti_intel_profile_indicator_get` | `defender_ti` | `intel_profile_indicator_get` |
| `defender_ti_intel_profile_indicators_global_list` | `defender_ti` | `intel_profile_indicators_global_list` |
| `defender_ti_articles_list` | `defender_ti` | `articles_list` |
| `defender_ti_article_get` | `defender_ti` | `article_get` |
| `defender_ti_article_indicators_list` | `defender_ti` | `article_indicators_list` |
| `defender_ti_article_indicator_get` | `defender_ti` | `article_indicator_get` |
| `defender_ti_article_indicators_global_list` | `defender_ti` | `article_indicators_global_list` |
| `defender_ti_host_get` | `defender_ti` | `host_get` |
| `defender_ti_host_reputation_get` | `defender_ti` | `host_reputation_get` |
| `defender_ti_host_components_list` | `defender_ti` | `host_components_list` |
| `defender_ti_host_component_get` | `defender_ti` | `host_component_get` |
| `defender_ti_host_cookies_list` | `defender_ti` | `host_cookies_list` |
| `defender_ti_host_cookie_get` | `defender_ti` | `host_cookie_get` |
| `defender_ti_host_ports_list` | `defender_ti` | `host_ports_list` |
| `defender_ti_host_port_get` | `defender_ti` | `host_port_get` |
| `defender_ti_host_trackers_list` | `defender_ti` | `host_trackers_list` |
| `defender_ti_host_tracker_get` | `defender_ti` | `host_tracker_get` |
| `defender_ti_host_subdomains_list` | `defender_ti` | `host_subdomains_list` |
| `defender_ti_host_ssl_certs_list` | `defender_ti` | `host_ssl_certs_list` |
| `defender_ti_host_whois_get` | `defender_ti` | `host_whois_get` |
| `defender_ti_host_whois_history_list` | `defender_ti` | `host_whois_history_list` |
| `defender_ti_host_pairs_list` | `defender_ti` | `host_pairs_list` |
| `defender_ti_host_pair_get` | `defender_ti` | `host_pair_get` |
| `defender_ti_host_child_pairs_list` | `defender_ti` | `host_child_pairs_list` |
| `defender_ti_host_parent_pairs_list` | `defender_ti` | `host_parent_pairs_list` |
| `defender_ti_host_passive_dns_list` | `defender_ti` | `host_passive_dns_list` |
| `defender_ti_host_passive_dns_reverse_list` | `defender_ti` | `host_passive_dns_reverse_list` |
| `defender_ti_ssl_certs_list` | `defender_ti` | `ssl_certs_list` |
| `defender_ti_ssl_cert_get` | `defender_ti` | `ssl_cert_get` |
| `defender_ti_ssl_cert_related_hosts_list` | `defender_ti` | `ssl_cert_related_hosts_list` |
| `defender_ti_whois_records_list` | `defender_ti` | `whois_records_list` |
| `defender_ti_whois_record_get` | `defender_ti` | `whois_record_get` |
| `defender_ti_passive_dns_get` | `defender_ti` | `passive_dns_get` |
| `defender_ti_vulnerability_get` | `defender_ti` | `vulnerability_get` |
| `defender_ti_vulnerability_components_list` | `defender_ti` | `vulnerability_components_list` |
| `defender_ti_vulnerability_component_get` | `defender_ti` | `vulnerability_component_get` |
| `defender_endpoint_machine_list` | `defender_machines` | `machine_list` |
| `defender_endpoint_machine_get` | `defender_machines` | `machine_get` |
| `defender_endpoint_machine_logged_on_users` | `defender_machines` | `logged_on_users` |
| `defender_endpoint_machine_find_by_tag` | `defender_machines` | `find_by_tag` |
| `defender_endpoint_machine_list_software` | `defender_machines` | `installed_software` |
| `defender_endpoint_machine_security_recommendations` | `defender_machines` | `security_recommendations` |
| `defender_endpoint_software_list` | `defender_vulnerabilities` | `software_list` |
| `defender_endpoint_software_get` | `defender_vulnerabilities` | `software_get` |
| `defender_endpoint_software_machines` | `defender_vulnerabilities` | `software_machines` |
| `defender_endpoint_software_vulnerabilities` | `defender_vulnerabilities` | `software_vulnerabilities` |
| `defender_endpoint_software_missing_kbs` | `defender_vulnerabilities` | `software_missing_kbs` |
| `defender_endpoint_software_distribution` | `defender_vulnerabilities` | `software_distribution` |
| `defender_endpoint_vulnerability_list` | `defender_vulnerabilities` | `vulnerability_list` |
| `defender_endpoint_vulnerability_get_by_cve` | `defender_vulnerabilities` | `vulnerability_get_by_cve` |
| `defender_endpoint_vulnerability_get_machines` | `defender_vulnerabilities` | `vulnerability_get_machines` |
| `defender_endpoint_vulnerability_get_by_machine_software` | `defender_vulnerabilities` | `vulnerability_get_by_machine_software` |
| `defender_endpoint_recommendation_list` | `defender_vulnerabilities` | `recommendation_list` |
| `defender_endpoint_recommendation_get` | `defender_vulnerabilities` | `recommendation_get` |
| `defender_endpoint_recommendation_machines` | `defender_vulnerabilities` | `recommendation_machines` |
| `defender_endpoint_recommendation_vulnerabilities` | `defender_vulnerabilities` | `recommendation_vulnerabilities` |
| `defender_endpoint_recommendation_by_software` | `defender_vulnerabilities` | `recommendation_by_software` |
| `defender_endpoint_remediation_list` | `defender_vulnerabilities` | `remediation_list` |
| `defender_endpoint_remediation_get` | `defender_vulnerabilities` | `remediation_get` |
| `defender_endpoint_remediation_exposed_devices` | `defender_vulnerabilities` | `remediation_exposed_devices` |
| `defender_endpoint_exposure_score` | `defender_vulnerabilities` | `exposure_score` |
| `defender_endpoint_exposure_score_by_machine_groups` | `defender_vulnerabilities` | `exposure_score_by_machine_groups` |
| `defender_endpoint_ip_statistics` | `defender_machines` | `ip_statistics` |
| `defender_endpoint_ip_related_alerts` | `defender_incidents_alerts` | `ip_related_alerts` |
| `defender_endpoint_domain_statistics` | `defender_machines` | `domain_statistics` |
| `defender_endpoint_domain_related_machines` | `defender_machines` | `domain_related_machines` |
| `defender_endpoint_domain_related_alerts` | `defender_incidents_alerts` | `domain_related_alerts` |
| `defender_endpoint_file_get` | `defender_machines` | `file_get` |
| `defender_endpoint_file_statistics` | `defender_machines` | `file_statistics` |
| `defender_endpoint_file_related_machines` | `defender_machines` | `file_related_machines` |
| `defender_endpoint_file_related_alerts` | `defender_incidents_alerts` | `file_related_alerts` |
| `defender_endpoint_user_related_alerts` | `defender_incidents_alerts` | `user_related_alerts` |
| `defender_endpoint_user_related_machines` | `defender_machines` | `user_related_machines` |
| `defender_endpoint_alert_list` | `defender_incidents_alerts` | `endpoint_alert_list` |
| `defender_endpoint_alert_get` | `defender_incidents_alerts` | `endpoint_alert_get` |
| `defender_endpoint_machine_action_list` | `defender_forensics` | `machine_action_list` |
| `defender_endpoint_machine_action_get_status` | `defender_forensics` | `machine_action_get_status` |
| `defender_xdr_alert_list` | `defender_incidents_alerts` | `xdr_alert_list` |
| `defender_xdr_alert_get` | `defender_incidents_alerts` | `xdr_alert_get` |
| `defender_xdr_incident_list` | `defender_incidents_alerts` | `xdr_incident_list` |
| `defender_xdr_incident_get` | `defender_incidents_alerts` | `xdr_incident_get` |
| `defender_library_file_upload` | `defender_response` | `upload_library_file` |
| `defender_endpoint_live_response_run` | `defender_response` | `live_response_run` |
| `defender_endpoint_live_response_get_result` | `defender_forensics` | `live_response_get_result` |
