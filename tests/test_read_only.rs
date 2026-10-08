//! Hybrid read-only enforcement over real MCP stdio: mutating tools are hidden from discovery
//! and calls by name are rejected locally with a structured `read_only_violation`.
//!
//! Upstream base URLs point at a closed loopback port and no token is ever requested, so any
//! attempt to reach the network would surface as a connection/auth error instead of the
//! read-only violation asserted here.

mod common;

use common::McpProcess;
use serde_json::{Value, json};

fn assert_read_only_violation(resp: &Value) {
    let result = &resp["result"];
    assert_eq!(result["isError"], json!(true), "{resp}");
    assert_eq!(
        result["structuredContent"]["code"],
        json!("read_only_violation"),
        "{resp}"
    );
}

#[test]
fn test_granular_read_only_hides_and_blocks_mutators() {
    let mut server = McpProcess::start(&["--read-only", "--enable-live-response"], &[]);
    let names = server.tool_names();
    assert_eq!(names.len(), 86);
    assert!(!names.iter().any(|n| n == "defender_library_file_upload"));
    assert!(
        !names
            .iter()
            .any(|n| n == "defender_endpoint_live_response_run")
    );

    let resp = server.call_tool(
        "defender_endpoint_live_response_run",
        json!({
            "machine_id": "1e5bc9d7e413ddd7902c2932e418702b84d0cc07",
            "commands": [{ "type": "GetFile", "params": [{ "key": "Path", "value": "C:\\x" }] }],
            "comment": "Incident 4124 evidence collection"
        }),
    );
    assert_read_only_violation(&resp);

    let resp = server.call_tool(
        "defender_library_file_upload",
        json!({ "file_name": "a.ps1", "file_content": "x", "description": "d" }),
    );
    assert_read_only_violation(&resp);
    assert!(server.shutdown().success());
}

#[test]
fn test_consolidated_read_only_hides_and_blocks_defender_response() {
    let mut server = McpProcess::start(&["--tool-mode", "consolidated", "--read-only"], &[]);
    let names = server.tool_names();
    assert_eq!(names.len(), 6);
    assert!(!names.iter().any(|n| n == "defender_response"));

    let resp = server.call_tool(
        "defender_response",
        json!({
            "action": "collect_investigation_package",
            "machine_id": "1e5bc9d7e413ddd7902c2932e418702b84d0cc07",
            "comment": "Incident 4124 triage collection"
        }),
    );
    assert_read_only_violation(&resp);
    assert!(server.shutdown().success());
}

#[test]
fn test_unknown_tool_in_active_mode_is_not_routed() {
    // Granular tool names are not reachable in consolidated mode.
    let mut server = McpProcess::start(&["--tool-mode", "consolidated"], &[]);
    let resp = server.call_tool("defender_endpoint_machine_list", json!({}));
    assert!(resp.get("error").is_some(), "{resp}");
    assert!(server.shutdown().success());
}
