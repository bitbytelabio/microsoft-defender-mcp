//! Command-line flags (with environment fallbacks) and the resolved [`ServerConfig`].
//!
//! Precedence: CLI flag > environment variable > default. `--read-only` always wins over
//! `--enable-live-response`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::constants::{
    DEFAULT_BIND_ADDRESS, DEFAULT_QUARANTINE_DIR, DEFAULT_TOOL_MODE, ENV_BIND_ADDRESS,
    ENV_LIVE_RESPONSE_ALLOWED_COMMANDS, ENV_LIVE_RESPONSE_ENABLED, ENV_QUARANTINE_DIR,
    ENV_READ_ONLY, ENV_TOOL_MODE, ENV_TRANSPORT,
};

/// MCP tool catalog exposure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ToolMode {
    /// The 88 granular tools (backward-compatible default).
    Granular,
    /// The 7 action-based domain tools.
    Consolidated,
}

/// MCP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportMode {
    /// Standard input/output (local MCP clients).
    Stdio,
    /// Streamable HTTP on `--bind-address` (no built-in authentication).
    Http,
}

/// Command-line arguments for the Microsoft Defender MCP server.
#[derive(Debug, Parser)]
#[command(
    name = "microsoft-defender-mcp-server",
    about = "Rust MCP server for Microsoft Defender XDR and Defender for Endpoint APIs",
    version
)]
pub struct Cli {
    /// MCP transport
    #[arg(long, value_enum, default_value = "stdio", env = ENV_TRANSPORT)]
    pub transport: TransportMode,

    /// Socket address for the streamable HTTP transport
    #[arg(long, default_value = DEFAULT_BIND_ADDRESS, env = ENV_BIND_ADDRESS)]
    pub bind_address: String,

    /// Tool catalog: 88 granular tools or 7 consolidated action-based tools
    #[arg(long, value_enum, default_value = DEFAULT_TOOL_MODE, env = ENV_TOOL_MODE)]
    pub tool_mode: ToolMode,

    /// Hide mutating tools from discovery and reject mutating calls locally before any network request
    #[arg(long, env = ENV_READ_ONLY)]
    pub read_only: bool,

    /// Enable mutating response tools (Live Response, library upload, investigation package collection, stop-and-quarantine)
    #[arg(long, env = ENV_LIVE_RESPONSE_ENABLED)]
    pub enable_live_response: bool,

    /// Comma-separated Live Response command allowlist (PutFile, RunScript, GetFile)
    #[arg(long, env = ENV_LIVE_RESPONSE_ALLOWED_COMMANDS)]
    pub allowed_commands: Option<String>,

    /// Directory for downloaded investigation packages and quarantined files (created with mode 0700)
    #[arg(long, default_value = DEFAULT_QUARANTINE_DIR, env = ENV_QUARANTINE_DIR)]
    pub quarantine_dir: PathBuf,
}

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub transport: TransportMode,
    pub bind_address: String,
    pub tool_mode: ToolMode,
    pub read_only: bool,
    /// Effective mutation gate; always `false` when `read_only` is set.
    pub live_response_enabled: bool,
    pub live_response_allowed_commands: Option<Vec<String>>,
    pub quarantine_dir: PathBuf,
}

impl ServerConfig {
    pub fn from_cli(cli: Cli) -> Self {
        let live_response_allowed_commands = cli
            .allowed_commands
            .map(|list| {
                list.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|list| !list.is_empty());

        Self {
            transport: cli.transport,
            bind_address: cli.bind_address,
            tool_mode: cli.tool_mode,
            read_only: cli.read_only,
            live_response_enabled: cli.enable_live_response && !cli.read_only,
            live_response_allowed_commands,
            quarantine_dir: cli.quarantine_dir,
        }
    }
}

/// Whether `bind_address` (`host:port`, `[v6]:port`, or a bare host) is a loopback address.
pub fn is_loopback_address(bind_address: &str) -> bool {
    if let Ok(sock) = bind_address.parse::<SocketAddr>() {
        return sock.ip().is_loopback();
    }
    let host = bind_address
        .rsplit_once(':')
        .map_or(bind_address, |(host, _)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Print a security warning to stderr when HTTP transport binds beyond loopback.
pub fn warn_if_non_loopback(bind_address: &str) {
    if !is_loopback_address(bind_address) {
        eprintln!(
            "SECURITY WARNING: HTTP transport is bound to '{bind_address}', which is not a loopback address. \
             The streamable HTTP transport has no built-in authentication or encryption; expose it only \
             behind an authenticated reverse proxy or encrypted network boundary."
        );
    }
}
