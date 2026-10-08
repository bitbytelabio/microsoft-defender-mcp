//! Consolidated catalog: exactly 7 domain tools with exact MCP safety annotations.

mod common;

use common::{base_config, test_server};
use microsoft_defender_mcp_server::cli::ToolMode;

const READ_ONLY_TOOLS: [&str; 6] = [
    "defender_forensics",
    "defender_hunting",
    "defender_incidents_alerts",
    "defender_machines",
    "defender_ti",
    "defender_vulnerabilities",
];

#[test]
fn test_consolidated_tool_listing() {
    let config = microsoft_defender_mcp_server::cli::ServerConfig {
        tool_mode: ToolMode::Consolidated,
        ..base_config()
    };
    let tools = test_server("http://127.0.0.1:9", config).list_tools_for_config();

    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    names.sort_unstable();
    let mut expected: Vec<&str> = READ_ONLY_TOOLS.to_vec();
    expected.push("defender_response");
    expected.sort_unstable();
    assert_eq!(names, expected);

    for tool in &tools {
        let name = tool.name.as_ref();
        let a = tool.annotations.as_ref().expect("annotations");
        let mutating = name == "defender_response";
        assert_eq!(a.read_only_hint, Some(!mutating), "{name} readOnlyHint");
        assert_eq!(a.destructive_hint, Some(mutating), "{name} destructiveHint");
        assert_eq!(a.idempotent_hint, Some(!mutating), "{name} idempotentHint");
        assert_eq!(a.open_world_hint, Some(true), "{name} openWorldHint");
        assert!(
            tool.description.as_deref().is_some_and(|d| !d.is_empty()),
            "{name} needs a description"
        );
    }
}

#[test]
fn test_consolidated_read_only_listing_omits_defender_response() {
    let config = microsoft_defender_mcp_server::cli::ServerConfig {
        tool_mode: ToolMode::Consolidated,
        read_only: true,
        ..base_config()
    };
    let tools = test_server("http://127.0.0.1:9", config).list_tools_for_config();
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    names.sort_unstable();
    assert_eq!(names, READ_ONLY_TOOLS);
}
