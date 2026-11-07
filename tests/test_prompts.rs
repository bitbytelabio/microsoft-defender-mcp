//! Investigation skills served as MCP prompts.

mod common;

use common::McpProcess;
use serde_json::{Value, json};

const SKILLS: [&str; 5] = [
    "compromised_user_skill",
    "incident_investigation_skill",
    "ioc_sweep_skill",
    "kql_hunting_skill",
    "persistence_hunt_skill",
];

fn prompt_text(resp: &Value) -> &str {
    resp["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no prompt text in {resp}"))
}

#[test]
fn test_prompts_are_listed_with_their_arguments() {
    let mut server = McpProcess::start(&["--read-only"], &[]);
    let resp = server.request("prompts/list", json!({}));
    let prompts = resp["result"]["prompts"].as_array().expect("prompts array");
    let mut names: Vec<&str> = prompts.iter().filter_map(|p| p["name"].as_str()).collect();
    names.sort();
    assert_eq!(names, SKILLS);

    let ioc = prompts
        .iter()
        .find(|p| p["name"] == "ioc_sweep_skill")
        .unwrap();
    let args: Vec<(&str, bool)> = ioc["arguments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["name"].as_str().unwrap(),
                a["required"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    assert!(args.contains(&("indicators", true)));
    assert!(args.contains(&("lookback", false)));
    assert!(server.shutdown().success());
}

#[test]
fn test_ioc_sweep_renders_classified_kql() {
    let mut server = McpProcess::start(&["--read-only"], &[]);
    let resp = server.request(
        "prompts/get",
        json!({ "name": "ioc_sweep_skill", "arguments": { "indicators": "1.2.3.4, evil[.]example[.]com", "lookback": "3d" } }),
    );
    let text = prompt_text(&resp);
    assert!(text.contains("# Indicator (IOC) Sweep"));
    assert!(text.contains("let lookback = 3d;"));
    assert!(text.contains("let ips = dynamic([\"1.2.3.4\"]);"));
    assert!(text.contains("let domains = dynamic([\"evil.example.com\"]);"));
    assert!(text.contains("DeviceNetworkEvents"));
    assert!(server.shutdown().success());
}

#[test]
fn test_prompt_arguments_are_validated() {
    let mut server = McpProcess::start(&["--read-only"], &[]);
    let resp = server.request(
        "prompts/get",
        json!({ "name": "compromised_user_skill", "arguments": { "account": "a\" | take 1" } }),
    );
    assert!(resp.get("error").is_some(), "expected an error: {resp}");

    let resp = server.request(
        "prompts/get",
        json!({ "name": "compromised_user_skill", "arguments": { "account": "jdoe@contoso.com", "lookback": "14d" } }),
    );
    let text = prompt_text(&resp);
    assert!(text.contains("AccountUpn =~ \"jdoe@contoso.com\""));
    assert!(text.contains("ago(14d)"));
    assert!(!text.contains("<account>"));
    assert!(server.shutdown().success());
}

#[test]
fn test_kql_hunting_skill_needs_no_arguments() {
    let mut server = McpProcess::start(&[], &[]);
    let resp = server.request("prompts/get", json!({ "name": "kql_hunting_skill" }));
    assert!(prompt_text(&resp).contains("DeviceProcessEvents"));
    assert!(server.shutdown().success());
}

#[test]
fn test_hunting_skill_is_a_resource() {
    let mut server = McpProcess::start(&["--read-only"], &[]);
    let resp = server.request("resources/list", json!({}));
    let resources = resp["result"]["resources"]
        .as_array()
        .unwrap_or_else(|| panic!("no resources in {resp}"));
    let skill = resources
        .iter()
        .find(|r| r["uri"] == "skill://ms-defender/kql-hunting")
        .unwrap_or_else(|| panic!("skill not listed: {resp}"));
    assert_eq!(skill["mimeType"], "text/markdown");

    let resp = server.request(
        "resources/read",
        json!({ "uri": "skill://ms-defender/kql-hunting" }),
    );
    let text = resp["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no skill text in {resp}"));
    for needle in [
        "defender_hunting",
        "validate",
        "maxRows",
        "truncated",
        "timespan",
        "arg_min",
        "dcount(DeviceName)",
    ] {
        assert!(text.contains(needle), "skill lacks {needle}");
    }

    let resp = server.request(
        "resources/read",
        json!({ "uri": "skill://ms-defender/other" }),
    );
    assert!(resp.get("error").is_some(), "expected an error: {resp}");
    assert!(server.shutdown().success());
}

#[test]
fn test_instructions_are_short_and_point_to_the_skill() {
    let server = common::test_server("http://127.0.0.1:9", common::base_config());
    let info = rmcp::ServerHandler::get_info(&server);
    let instructions = info.instructions.expect("instructions");
    // Agent runtimes truncate longer instructions (omp keeps 4000 characters).
    assert!(
        instructions.chars().count() < 4000,
        "instructions are {} characters",
        instructions.chars().count()
    );
    assert!(instructions.contains("skill://ms-defender/kql-hunting"));
    for tool in [
        "defender_hunting",
        "defender_ti",
        "defender_incidents_alerts",
        "defender_machines",
        "defender_vulnerabilities",
        "defender_forensics",
        "defender_response",
        "defender_device_response",
        "defender_indicators",
        "defender_triage",
    ] {
        assert!(instructions.contains(tool), "instructions lack {tool}");
    }
    let caps = info.capabilities;
    assert!(caps.tools.is_some() && caps.prompts.is_some() && caps.resources.is_some());
    assert_eq!(info.server_info.name, "microsoft-defender-mcp");
}
