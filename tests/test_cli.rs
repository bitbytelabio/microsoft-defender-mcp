//! CLI flags, environment fallbacks, and precedence, exercised through the real binary.

mod common;

use clap::Parser;
use common::{McpProcess, server_command};
use microsoft_defender_mcp_server::cli::{Cli, ServerConfig, ToolMode, is_loopback_address};

#[test]
fn test_help_lists_new_flags_and_exits_zero_without_credentials() {
    let out = server_command(&["--help"], &[])
        .env_remove("AZURE_TENANT_ID")
        .env_remove("AZURE_CLIENT_ID")
        .env_remove("AZURE_CLIENT_SECRET")
        .output()
        .expect("run --help");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--transport",
        "--bind-address",
        "--tool-mode",
        "--read-only",
        "--enable-live-response",
        "--allowed-commands",
        "--quarantine-dir",
        "DEFENDER_READ_ONLY",
        "DEFENDER_TOOL_MODE",
    ] {
        assert!(help.contains(flag), "--help is missing {flag}:\n{help}");
    }
}

#[test]
fn test_version_prints_crate_version() {
    let out = server_command(&["--version"], &[])
        .output()
        .expect("run --version");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_invalid_tool_mode_is_a_startup_error() {
    let out = server_command(&["--tool-mode", "compact"], &[])
        .output()
        .expect("run with invalid flag");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--tool-mode"));
}

#[test]
fn test_env_selects_consolidated_read_only_catalog() {
    let mut server = McpProcess::start(
        &[],
        &[
            ("DEFENDER_TOOL_MODE", "consolidated"),
            ("DEFENDER_READ_ONLY", "true"),
        ],
    );
    let names = server.tool_names();
    assert_eq!(names.len(), 6, "{names:?}");
    assert!(!names.iter().any(|n| n == "defender_response"));
    assert!(server.shutdown().success());
}

#[test]
fn test_cli_flag_overrides_environment() {
    let mut server = McpProcess::start(
        &["--tool-mode", "granular"],
        &[("DEFENDER_TOOL_MODE", "consolidated")],
    );
    assert_eq!(server.tool_names().len(), 88);
    assert!(server.shutdown().success());
}

#[test]
fn test_read_only_forces_live_response_off() {
    let cli = Cli::try_parse_from([
        "microsoft-defender-mcp-server",
        "--read-only",
        "--enable-live-response",
    ])
    .expect("parse flags");
    let config = ServerConfig::from_cli(cli);
    assert!(config.read_only);
    assert!(!config.live_response_enabled);
    assert_eq!(config.tool_mode, ToolMode::Granular);
}

#[test]
fn test_allowed_commands_are_trimmed_and_split() {
    let cli = Cli::try_parse_from([
        "microsoft-defender-mcp-server",
        "--allowed-commands",
        " GetFile, RunScript ,,",
    ])
    .expect("parse flags");
    let config = ServerConfig::from_cli(cli);
    assert_eq!(
        config.live_response_allowed_commands,
        Some(vec!["GetFile".to_string(), "RunScript".to_string()])
    );
}

#[test]
fn test_loopback_detection() {
    assert!(is_loopback_address("127.0.0.1:8000"));
    assert!(is_loopback_address("[::1]:8000"));
    assert!(is_loopback_address("localhost:8000"));
    assert!(!is_loopback_address("0.0.0.0:8000"));
    assert!(!is_loopback_address("10.1.2.3:8000"));
    assert!(!is_loopback_address("example.com:8000"));
}
