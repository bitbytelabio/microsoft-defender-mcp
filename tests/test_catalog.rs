//! Domain-Tool Catalog integration tests (quickstart Q1, Q2, SC-009).

mod common;

use common::McpProcess;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};

const READ_ONLY_TOOLS: [&str; 6] = [
    "defender_hunting",
    "defender_ti",
    "defender_incidents_alerts",
    "defender_machines",
    "defender_vulnerabilities",
    "defender_forensics",
];

/// The 88 tool names removed in 1.0.0 (contracts/migration-table.md, left column).
fn extract_removed_tool_names() -> HashSet<String> {
    [
        "defender_advanced_hunting_run",
        "defender_ti_intel_profiles_list",
        "defender_ti_intel_profile_get",
        "defender_ti_intel_profile_indicators_list",
        "defender_ti_intel_profile_indicator_get",
        "defender_ti_intel_profile_indicators_global_list",
        "defender_ti_articles_list",
        "defender_ti_article_get",
        "defender_ti_article_indicators_list",
        "defender_ti_article_indicator_get",
        "defender_ti_article_indicators_global_list",
        "defender_ti_host_get",
        "defender_ti_host_reputation_get",
        "defender_ti_host_components_list",
        "defender_ti_host_component_get",
        "defender_ti_host_cookies_list",
        "defender_ti_host_cookie_get",
        "defender_ti_host_ports_list",
        "defender_ti_host_port_get",
        "defender_ti_host_trackers_list",
        "defender_ti_host_tracker_get",
        "defender_ti_host_subdomains_list",
        "defender_ti_host_ssl_certs_list",
        "defender_ti_host_whois_get",
        "defender_ti_host_whois_history_list",
        "defender_ti_host_pairs_list",
        "defender_ti_host_pair_get",
        "defender_ti_host_child_pairs_list",
        "defender_ti_host_parent_pairs_list",
        "defender_ti_host_passive_dns_list",
        "defender_ti_host_passive_dns_reverse_list",
        "defender_ti_ssl_certs_list",
        "defender_ti_ssl_cert_get",
        "defender_ti_ssl_cert_related_hosts_list",
        "defender_ti_whois_records_list",
        "defender_ti_whois_record_get",
        "defender_ti_passive_dns_get",
        "defender_ti_vulnerability_get",
        "defender_ti_vulnerability_components_list",
        "defender_ti_vulnerability_component_get",
        "defender_endpoint_machine_list",
        "defender_endpoint_machine_get",
        "defender_endpoint_machine_logged_on_users",
        "defender_endpoint_machine_find_by_tag",
        "defender_endpoint_machine_list_software",
        "defender_endpoint_machine_security_recommendations",
        "defender_endpoint_software_list",
        "defender_endpoint_software_get",
        "defender_endpoint_software_machines",
        "defender_endpoint_software_vulnerabilities",
        "defender_endpoint_software_missing_kbs",
        "defender_endpoint_software_distribution",
        "defender_endpoint_vulnerability_list",
        "defender_endpoint_vulnerability_get_by_cve",
        "defender_endpoint_vulnerability_get_machines",
        "defender_endpoint_vulnerability_get_by_machine_software",
        "defender_endpoint_recommendation_list",
        "defender_endpoint_recommendation_get",
        "defender_endpoint_recommendation_machines",
        "defender_endpoint_recommendation_vulnerabilities",
        "defender_endpoint_recommendation_by_software",
        "defender_endpoint_remediation_list",
        "defender_endpoint_remediation_get",
        "defender_endpoint_remediation_exposed_devices",
        "defender_endpoint_exposure_score",
        "defender_endpoint_exposure_score_by_machine_groups",
        "defender_endpoint_ip_statistics",
        "defender_endpoint_ip_related_alerts",
        "defender_endpoint_domain_statistics",
        "defender_endpoint_domain_related_machines",
        "defender_endpoint_domain_related_alerts",
        "defender_endpoint_file_get",
        "defender_endpoint_file_statistics",
        "defender_endpoint_file_related_machines",
        "defender_endpoint_file_related_alerts",
        "defender_endpoint_user_related_alerts",
        "defender_endpoint_user_related_machines",
        "defender_endpoint_alert_list",
        "defender_endpoint_alert_get",
        "defender_endpoint_machine_action_list",
        "defender_endpoint_machine_action_get_status",
        "defender_xdr_alert_list",
        "defender_xdr_alert_get",
        "defender_xdr_incident_list",
        "defender_xdr_incident_get",
        "defender_library_file_upload",
        "defender_endpoint_live_response_run",
        "defender_endpoint_live_response_get_result",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[test]
fn test_default_config_lists_exactly_six_read_only_tools() {
    let mut server = McpProcess::start(&[], &[]);
    let names = server.tool_names();
    let mut sorted_names = names.clone();
    sorted_names.sort();

    let mut expected = READ_ONLY_TOOLS.to_vec();
    expected.sort();

    assert_eq!(sorted_names, expected, "default catalog mismatch");
    assert!(server.shutdown().success());
}

#[test]
fn test_read_only_with_all_flags_lists_six_tools_and_prints_stderr_notice() {
    let mut server = McpProcess::start(
        &[
            "--read-only",
            "--enable-live-response",
            "--enable-device-response",
            "--enable-offboarding",
            "--enable-indicators",
            "--enable-triage",
        ],
        &[],
    );
    let names = server.tool_names();
    let mut sorted_names = names.clone();
    sorted_names.sort();

    let mut expected = READ_ONLY_TOOLS.to_vec();
    expected.sort();

    assert_eq!(sorted_names, expected);
    let stderr = server.captured_stderr();
    assert!(
        stderr.contains("NOTE: --read-only overrides --enable-…; no mutating tools are exposed."),
        "expected NOTE line in stderr: {stderr}"
    );
    assert!(server.shutdown().success());
}

#[test]
fn test_enable_live_response_lists_seven_tools() {
    let mut server = McpProcess::start(&["--enable-live-response"], &[]);
    let names = server.tool_names();
    assert_eq!(names.len(), 7, "expected 7 tools; got: {names:?}");
    assert!(names.contains(&"defender_response".to_string()));
    for r in &READ_ONLY_TOOLS {
        assert!(names.contains(&r.to_string()), "missing read tool {r}");
    }
    assert!(server.shutdown().success());
}

#[test]
fn test_tool_annotations_match_contracts_catalog() {
    let mut server = McpProcess::start(&["--enable-live-response"], &[]);
    let tools = server.tools();

    for tool in tools {
        let name = tool["name"].as_str().expect("tool name");
        let a = &tool["annotations"];
        assert!(a.is_object(), "annotations missing for {name}");

        let read_only_hint = a["readOnlyHint"].as_bool().expect("readOnlyHint");
        let destructive_hint = a["destructiveHint"].as_bool().expect("destructiveHint");
        let idempotent_hint = a["idempotentHint"].as_bool().expect("idempotentHint");
        let open_world_hint = a["openWorldHint"].as_bool().expect("openWorldHint");

        if name == "defender_response" {
            assert!(!read_only_hint, "{name} must not be read-only");
            assert!(destructive_hint, "{name} must be destructive");
            assert!(!idempotent_hint, "{name} must not be idempotent");
            assert!(open_world_hint, "{name} must be open world");
        } else if READ_ONLY_TOOLS.contains(&name) {
            assert!(read_only_hint, "{name} must be read-only");
            assert!(!destructive_hint, "{name} must not be destructive");
            assert!(idempotent_hint, "{name} must be idempotent");
            assert!(open_world_hint, "{name} must be open world");
        }
    }

    assert!(server.shutdown().success());
}

#[test]
fn test_no_removed_granular_names_in_catalog() {
    let removed = extract_removed_tool_names();
    assert_eq!(removed.len(), 88, "expected 88 removed tools");

    let mut server = McpProcess::start(&["--enable-live-response"], &[]);
    let names = server.tool_names();

    for name in names {
        assert!(
            !removed.contains(&name),
            "catalog lists removed tool: {name}"
        );
    }

    assert!(server.shutdown().success());
}

#[test]
fn test_call_granular_tool_returns_unknown_tool_error() {
    let mut server = McpProcess::start(&["--enable-live-response"], &[]);
    let resp = server.call_tool("defender_endpoint_machine_list", json!({}));
    assert!(
        resp.get("error").is_some(),
        "calling granular tool must return JSON-RPC error, got: {resp}"
    );
    let err = &resp["error"];
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("tool not found"),
        "expected tool not found error, got: {err}"
    );
    assert!(server.shutdown().success());
}

// =========================================================================
// T022: --enable-device-response configuration (US1)
// =========================================================================

#[test]
fn test_enable_device_response_lists_seven_tools_with_annotations() {
    let mut server = McpProcess::start(&["--enable-device-response"], &[]);
    let tools = server.tools();
    assert_eq!(tools.len(), 7, "expected 7 tools; got: {tools:?}");

    let device_tool = tools
        .iter()
        .find(|t| t["name"] == "defender_device_response")
        .expect("defender_device_response tool must be listed");

    let a = &device_tool["annotations"];
    assert_eq!(a["title"], "Defender Device Response");
    assert_eq!(a["readOnlyHint"], false);
    assert_eq!(a["destructiveHint"], true);
    assert_eq!(a["idempotentHint"], false);
    assert_eq!(a["openWorldHint"], true);

    for r in &READ_ONLY_TOOLS {
        assert!(
            tools.iter().any(|t| t["name"] == *r),
            "missing read-only tool {r}"
        );
    }

    assert!(server.shutdown().success());
}

// =========================================================================
// T039: --enable-indicators configuration (US3)
// =========================================================================

#[test]
fn test_enable_indicators_lists_seven_tools_with_annotations() {
    let mut server = McpProcess::start(&["--enable-indicators"], &[]);
    let tools = server.tools();
    assert_eq!(tools.len(), 7, "expected 7 tools; got: {tools:?}");

    let ind_tool = tools
        .iter()
        .find(|t| t["name"] == "defender_indicators")
        .expect("defender_indicators tool must be listed");

    let a = &ind_tool["annotations"];
    assert_eq!(a["title"], "Defender Custom Indicators");
    assert_eq!(a["readOnlyHint"], false);
    assert_eq!(a["destructiveHint"], true);
    assert_eq!(a["idempotentHint"], false);
    assert_eq!(a["openWorldHint"], true);

    for r in &READ_ONLY_TOOLS {
        assert!(
            tools.iter().any(|t| t["name"] == *r),
            "missing read-only tool {r}"
        );
    }

    assert!(server.shutdown().success());
}

// =========================================================================
// T046: --enable-triage configuration (US4)
// =========================================================================

#[test]
fn test_enable_triage_lists_seven_tools_with_annotations() {
    let mut server = McpProcess::start(&["--enable-triage"], &[]);
    let tools = server.tools();
    assert_eq!(tools.len(), 7, "expected 7 tools; got: {tools:?}");

    let triage_tool = tools
        .iter()
        .find(|t| t["name"] == "defender_triage")
        .expect("defender_triage tool must be listed");

    let a = &triage_tool["annotations"];
    assert_eq!(a["title"], "Defender Triage");
    assert_eq!(a["readOnlyHint"], false);
    assert_eq!(a["destructiveHint"], false);
    assert_eq!(a["idempotentHint"], false);
    assert_eq!(a["openWorldHint"], true);

    for r in &READ_ONLY_TOOLS {
        assert!(
            tools.iter().any(|t| t["name"] == *r),
            "missing read-only tool {r}"
        );
    }

    assert!(server.shutdown().success());
}

// =========================================================================
// T057: offboarding configurations (US6)
// =========================================================================

#[test]
fn test_offboarding_catalog_configurations() {
    // 1. --enable-device-response alone: description omits offboard
    {
        let mut server = McpProcess::start(&["--enable-device-response"], &[]);
        let tools = server.tools();
        let tool = tools
            .iter()
            .find(|t| t["name"] == "defender_device_response")
            .expect("defender_device_response present");
        let desc = tool["description"].as_str().expect("description");
        assert!(
            !desc.contains("offboard"),
            "description must omit offboard when --enable-offboarding is absent: {desc}"
        );
        assert!(server.shutdown().success());
    }

    // 2. --enable-device-response --enable-offboarding: description includes offboard
    {
        let mut server =
            McpProcess::start(&["--enable-device-response", "--enable-offboarding"], &[]);
        let tools = server.tools();
        let tool = tools
            .iter()
            .find(|t| t["name"] == "defender_device_response")
            .expect("defender_device_response present");
        let desc = tool["description"].as_str().expect("description");
        assert!(
            desc.contains("offboard"),
            "description must include offboard when --enable-offboarding is present: {desc}"
        );
        assert!(server.shutdown().success());
    }

    // 3. --read-only --enable-device-response --enable-offboarding: tool is absent
    {
        let mut server = McpProcess::start(
            &[
                "--read-only",
                "--enable-device-response",
                "--enable-offboarding",
            ],
            &[],
        );
        let names = server.tool_names();
        assert!(
            !names.contains(&"defender_device_response".to_string()),
            "--read-only must suppress defender_device_response: {names:?}"
        );
        assert_eq!(names.len(), 6);
        assert!(server.shutdown().success());
    }
}

// =========================================================================
// T061: all-categories 10-tool catalog, annotations, serverInfo, instructions
// =========================================================================

#[test]
fn test_all_categories_enabled_lists_ten_tools_full_annotations_and_server_info() {
    let flags = &[
        "--enable-live-response",
        "--enable-device-response",
        "--enable-offboarding",
        "--enable-indicators",
        "--enable-triage",
    ];

    // First: inspect initialize response directly using server_command
    {
        let mut child = common::server_command(flags, &[])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn server");

        let mut stdin = child.stdin.take().expect("child stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("child stdout"));

        let init_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "catalog-test", "version": "1.0" }
            }
        });
        writeln!(stdin, "{init_req}").expect("write initialize");
        stdin.flush().expect("flush initialize");

        let mut line = String::new();
        stdout
            .read_line(&mut line)
            .expect("read initialize response");
        let init_resp: Value = serde_json::from_str(&line).expect("valid JSON initialize response");
        let result = &init_resp["result"];

        // Assert literal "1.0.0"
        let ver = result["serverInfo"]["version"]
            .as_str()
            .expect("version string");
        assert_eq!(ver, "1.0.0", "serverInfo.version must be literal '1.0.0'");

        // Assert instructions contain NO migration-table name
        let instructions = result["instructions"]
            .as_str()
            .expect("instructions string");
        let removed = extract_removed_tool_names();
        for name in &removed {
            assert!(
                !instructions.contains(name.as_str()),
                "instructions must contain no migration-table name, found '{name}' in:\n{instructions}"
            );
        }

        drop(stdin);
        drop(stdout);
        let _ = child.wait();
    }

    // Second: test tools/list with all 10 tools and full annotations
    let mut server = McpProcess::start(flags, &[]);
    let tools = server.tools();
    assert_eq!(tools.len(), 10, "expected exactly 10 tools; got: {tools:?}");

    let expected_tools: [(&str, &str, bool, bool, bool, bool); 10] = [
        (
            "defender_hunting",
            "Defender Hunting",
            true,
            false,
            true,
            true,
        ),
        (
            "defender_ti",
            "Defender Threat Intelligence",
            true,
            false,
            true,
            true,
        ),
        (
            "defender_incidents_alerts",
            "Defender Incidents & Alerts",
            true,
            false,
            true,
            true,
        ),
        (
            "defender_machines",
            "Defender Machines",
            true,
            false,
            true,
            true,
        ),
        (
            "defender_vulnerabilities",
            "Defender Vulnerabilities",
            true,
            false,
            true,
            true,
        ),
        (
            "defender_forensics",
            "Defender Forensics",
            true,
            false,
            true,
            true,
        ),
        (
            "defender_response",
            "Defender Response",
            false,
            true,
            false,
            true,
        ),
        (
            "defender_device_response",
            "Defender Device Response",
            false,
            true,
            false,
            true,
        ),
        (
            "defender_indicators",
            "Defender Custom Indicators",
            false,
            true,
            false,
            true,
        ),
        (
            "defender_triage",
            "Defender Triage",
            false,
            false,
            false,
            true,
        ),
    ];

    for (name, title, ro, dest, idemp, ow) in expected_tools {
        let tool = tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("missing expected tool '{name}' in 10-tool catalog"));
        let a = &tool["annotations"];
        assert_eq!(a["title"], title, "title mismatch for {name}");
        assert_eq!(a["readOnlyHint"], ro, "readOnlyHint mismatch for {name}");
        assert_eq!(
            a["destructiveHint"], dest,
            "destructiveHint mismatch for {name}"
        );
        assert_eq!(
            a["idempotentHint"], idemp,
            "idempotentHint mismatch for {name}"
        );
        assert_eq!(a["openWorldHint"], ow, "openWorldHint mismatch for {name}");
    }

    // Ensure offboard is in the device-response description
    let dev_tool = tools
        .iter()
        .find(|t| t["name"] == "defender_device_response")
        .unwrap();
    let dev_desc = dev_tool["description"].as_str().expect("description");
    assert!(
        dev_desc.contains("offboard"),
        "defender_device_response description must contain 'offboard': {dev_desc}"
    );

    assert!(server.shutdown().success());
}
