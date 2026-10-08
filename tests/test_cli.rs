//! CLI flags, environment fallbacks, precedence, and configuration derivation.

mod common;

use std::path::PathBuf;

use clap::Parser;
use common::server_command;
use microsoft_defender_mcp_server::cli::{
    AuthConfig, Cli, MutationCategories, ServerConfig, SignInFlow, is_loopback_address,
    resolve_audit_path,
};

#[test]
fn test_help_lists_all_new_flags_and_env_vars_and_no_tool_mode() {
    let out = server_command(&["--help"], &[])
        .env_remove("AZURE_TENANT_ID")
        .env_remove("AZURE_CLIENT_ID")
        .env_remove("AZURE_CLIENT_SECRET")
        .output()
        .expect("run --help");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);

    let expected_flags = [
        "--transport",
        "--bind-address",
        "--read-only",
        "--enable-live-response",
        "--allowed-commands",
        "--enable-device-response",
        "--enable-offboarding",
        "--enable-indicators",
        "--enable-triage",
        "--disable-human-confirmation",
        "--audit-log",
        "--auth-mode",
        "--sign-in-flow",
        "--quarantine-dir",
    ];

    let expected_envs = [
        "TRANSPORT",
        "BIND_ADDRESS",
        "DEFENDER_READ_ONLY",
        "DEFENDER_ENABLE_LIVE_RESPONSE",
        "DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS",
        "DEFENDER_ENABLE_DEVICE_RESPONSE",
        "DEFENDER_ENABLE_OFFBOARDING",
        "DEFENDER_ENABLE_INDICATORS",
        "DEFENDER_ENABLE_TRIAGE",
        "DEFENDER_DISABLE_HUMAN_CONFIRMATION",
        "DEFENDER_AUDIT_LOG",
        "DEFENDER_AUTH_MODE",
        "DEFENDER_SIGN_IN_FLOW",
        "DEFENDER_QUARANTINE_DIR",
    ];

    for flag in expected_flags {
        assert!(
            help.contains(flag),
            "--help is missing flag {flag}:\n{help}"
        );
    }

    for env_var in expected_envs {
        assert!(
            help.contains(env_var),
            "--help is missing env var {env_var}:\n{help}"
        );
    }

    assert!(
        !help.contains("--tool-mode"),
        "--help must not list removed --tool-mode"
    );
    assert!(
        !help.contains("DEFENDER_TOOL_MODE"),
        "--help must not list removed DEFENDER_TOOL_MODE"
    );
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
fn test_tombstone_flag_exits_nonzero_with_removal_message() {
    let out = server_command(&["--tool-mode", "consolidated"], &[])
        .output()
        .expect("run with --tool-mode");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("granular mode no longer exists"),
        "stderr missing expected removal message: {stderr}"
    );
}

#[test]
fn test_tombstone_env_var_exits_nonzero_with_removal_message() {
    let out = server_command(&[], &[("DEFENDER_TOOL_MODE", "granular")])
        .output()
        .expect("run with DEFENDER_TOOL_MODE");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("granular mode no longer exists"),
        "stderr missing expected removal message: {stderr}"
    );
}

#[test]
fn test_tombstone_empty_env_var_exits_nonzero_with_removal_message() {
    let out = server_command(&[], &[("DEFENDER_TOOL_MODE", "")])
        .output()
        .expect("run with empty DEFENDER_TOOL_MODE");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("granular mode no longer exists"),
        "stderr missing expected removal message: {stderr}"
    );
}

#[test]
fn test_offboarding_without_device_response_fails_clap_validation() {
    let res = Cli::try_parse_from(["microsoft-defender-mcp-server", "--enable-offboarding"]);
    assert!(
        res.is_err(),
        "clap must reject --enable-offboarding without device response"
    );
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("--enable-device-response"),
        "clap error must mention required --enable-device-response: {err_str}"
    );
}

#[test]
fn test_sign_in_flow_with_app_mode_exits_nonzero_at_startup() {
    let out = server_command(&["--auth-mode", "app", "--sign-in-flow", "browser"], &[])
        .output()
        .expect("run with invalid sign-in-flow");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--sign-in-flow requires --auth-mode user"),
        "stderr missing expected error: {stderr}"
    );
}

#[test]
fn test_read_only_zeroes_every_mutation_category() {
    let cli = Cli::try_parse_from([
        "microsoft-defender-mcp-server",
        "--read-only",
        "--enable-live-response",
        "--enable-device-response",
        "--enable-offboarding",
        "--enable-indicators",
        "--enable-triage",
    ])
    .expect("parse flags");
    let config = ServerConfig::from_cli(cli);
    assert!(config.read_only);
    assert!(!config.categories.any());
    assert!(!config.categories.live_response);
    assert!(!config.categories.device_response);
    assert!(!config.categories.offboarding);
    assert!(!config.categories.indicators);
    assert!(!config.categories.triage);
}

#[test]
fn test_server_config_derivation_all_enabled() {
    let cli = Cli::try_parse_from([
        "microsoft-defender-mcp-server",
        "--enable-live-response",
        "--enable-device-response",
        "--enable-offboarding",
        "--enable-indicators",
        "--enable-triage",
        "--disable-human-confirmation",
        "--auth-mode",
        "user",
        "--sign-in-flow",
        "browser",
    ])
    .expect("parse flags");
    let config = ServerConfig::from_cli(cli);
    assert!(!config.read_only);
    assert!(config.categories.any());
    assert!(config.categories.live_response);
    assert!(config.categories.device_response);
    assert!(config.categories.offboarding);
    assert!(config.categories.indicators);
    assert!(config.categories.triage);
    assert!(!config.confirm_destructive);
    assert_eq!(
        config.auth,
        AuthConfig::User {
            flow: SignInFlow::Browser
        }
    );
}

#[test]
fn test_offboarding_requires_device_response_in_category_derivation() {
    let cats = MutationCategories::from_flags(false, false, false, true, false, false);
    assert!(!cats.offboarding, "offboarding requires device_response");

    let cats_with_dr = MutationCategories::from_flags(false, false, true, true, false, false);
    assert!(cats_with_dr.device_response);
    assert!(cats_with_dr.offboarding);
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

/// Resolve the default audit path against a fixed set of environment values.
fn audit_path_with(vars: &[(&str, &str)]) -> PathBuf {
    resolve_audit_path(|key| {
        vars.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| std::ffi::OsString::from(v))
    })
}

#[test]
fn test_default_audit_path_resolution_order() {
    let all = [
        ("XDG_STATE_HOME", "/custom/xdg"),
        ("HOME", "/custom/home"),
        ("LOCALAPPDATA", "C:\\custom\\appdata"),
    ];
    assert_eq!(
        audit_path_with(&all),
        PathBuf::from("/custom/xdg/microsoft-defender-mcp/audit.jsonl")
    );
    assert_eq!(
        audit_path_with(&all[1..]),
        PathBuf::from("/custom/home/.local/state/microsoft-defender-mcp/audit.jsonl")
    );
    assert_eq!(
        audit_path_with(&all[2..]),
        PathBuf::from("C:\\custom\\appdata").join("microsoft-defender-mcp/audit.jsonl")
    );
    assert_eq!(
        audit_path_with(&[]),
        PathBuf::from("./microsoft-defender-mcp-audit.jsonl")
    );
    // Empty values count as unset.
    assert_eq!(
        audit_path_with(&[("XDG_STATE_HOME", ""), ("HOME", "/custom/home")]),
        PathBuf::from("/custom/home/.local/state/microsoft-defender-mcp/audit.jsonl")
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
