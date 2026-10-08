//! Command-line flags (with environment fallbacks) and the resolved [`ServerConfig`].
//!
//! Precedence: CLI flag > environment variable > default. `--read-only` always overrides
//! every enablement flag.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::constants::{
    DEFAULT_BIND_ADDRESS, DEFAULT_QUARANTINE_DIR, ENV_AUDIT_LOG, ENV_AUTH_MODE, ENV_BIND_ADDRESS,
    ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_DEVICE_RESPONSE_ENABLED, ENV_DISABLE_HUMAN_CONFIRMATION,
    ENV_INDICATORS_ENABLED, ENV_LIVE_RESPONSE_ALLOWED_COMMANDS, ENV_LIVE_RESPONSE_ENABLED,
    ENV_OFFBOARDING_ENABLED, ENV_QUARANTINE_DIR, ENV_READ_ONLY, ENV_SIGN_IN_FLOW, ENV_TENANT_ID,
    ENV_TRANSPORT, ENV_TRIAGE_ENABLED,
};

/// MCP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportMode {
    /// Standard input/output (local MCP clients).
    Stdio,
    /// Streamable HTTP on `--bind-address` (no built-in authentication).
    Http,
}

/// Authentication mode for the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize)]
#[value(rename_all = "snake_case")]
pub enum AuthMode {
    /// Client credentials grant with client secret.
    App,
    /// Delegated sign-in under the analyst's own identity.
    User,
}

/// Interactive sign-in flow for `--auth-mode user`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[value(rename_all = "kebab-case")]
pub enum SignInFlow {
    /// Try browser flow, falling back to device-code flow if headless or launch fails.
    #[default]
    Auto,
    /// Interactive browser flow with PKCE.
    Browser,
    /// Device authorization code flow.
    DeviceCode,
}

/// Authentication configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthConfig {
    /// Application identity using client credentials.
    App,
    /// Delegated analyst identity using authorization code or device code.
    User { flow: SignInFlow },
}

/// Setting for the audit log path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditLogSetting {
    /// Explicitly specified by the user via `--audit-log` or `DEFENDER_AUDIT_LOG`.
    Explicit(PathBuf),
    /// Resolved default location.
    Default(PathBuf),
}

impl AuditLogSetting {
    /// Returns the resolved path.
    pub fn path(&self) -> &std::path::Path {
        match self {
            Self::Explicit(p) | Self::Default(p) => p,
        }
    }

    /// Whether this setting was explicitly specified.
    pub fn is_explicit(&self) -> bool {
        matches!(self, Self::Explicit(_))
    }
}

/// Resolves the default audit log file path per platform conventions.
pub fn default_audit_path() -> PathBuf {
    resolve_audit_path(|key| std::env::var_os(key))
}

/// Resolves the default audit log path from `XDG_STATE_HOME`, then `HOME`, then
/// `LOCALAPPDATA`, falling back to the working directory. `var` looks up an environment
/// variable; empty values count as unset.
pub fn resolve_audit_path(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    let var = |key: &str| var(key).filter(|s| !s.is_empty());
    if let Some(xdg) = var("XDG_STATE_HOME") {
        PathBuf::from(xdg)
            .join("microsoft-defender-mcp")
            .join("audit.jsonl")
    } else if let Some(home) = var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("microsoft-defender-mcp")
            .join("audit.jsonl")
    } else if let Some(local_app_data) = var("LOCALAPPDATA") {
        PathBuf::from(local_app_data)
            .join("microsoft-defender-mcp")
            .join("audit.jsonl")
    } else {
        PathBuf::from("./microsoft-defender-mcp-audit.jsonl")
    }
}

/// Mutating tools exposed by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutatingTool {
    Response,
    DeviceResponse,
    Indicators,
    Triage,
}

impl MutatingTool {
    /// Every mutating tool, in catalog order.
    pub const ALL: [Self; 4] = [
        Self::Response,
        Self::DeviceResponse,
        Self::Indicators,
        Self::Triage,
    ];

    /// The mutating tool with this MCP name, if any.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// Returns the MCP tool name for this mutating tool.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Response => "defender_response",
            Self::DeviceResponse => "defender_device_response",
            Self::Indicators => "defender_indicators",
            Self::Triage => "defender_triage",
        }
    }

    /// Whether actions under this tool are considered destructive (requiring confirmation).
    pub fn destructive(&self) -> bool {
        !matches!(self, Self::Triage)
    }

    /// The CLI flag that enables this tool's category.
    pub fn enable_flag(&self) -> &'static str {
        match self {
            Self::Response => "--enable-live-response",
            Self::DeviceResponse => "--enable-device-response",
            Self::Indicators => "--enable-indicators",
            Self::Triage => "--enable-triage",
        }
    }
}

/// Effective mutation categories profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MutationCategories {
    pub live_response: bool,
    pub device_response: bool,
    pub offboarding: bool,
    pub indicators: bool,
    pub triage: bool,
}

impl MutationCategories {
    /// Derives effective mutation categories from CLI flags.
    ///
    /// Invariant: `read_only => !any()`.
    /// `offboarding` requires both `--enable-offboarding` and effective `device_response`.
    pub fn from_flags(
        read_only: bool,
        enable_live_response: bool,
        enable_device_response: bool,
        enable_offboarding: bool,
        enable_indicators: bool,
        enable_triage: bool,
    ) -> Self {
        if read_only {
            return Self::default();
        }
        let live_response = enable_live_response;
        let device_response = enable_device_response;
        let offboarding = enable_offboarding && device_response;
        let indicators = enable_indicators;
        let triage = enable_triage;
        Self {
            live_response,
            device_response,
            offboarding,
            indicators,
            triage,
        }
    }

    /// Whether any mutating tool category is enabled.
    pub fn any(&self) -> bool {
        self.live_response || self.device_response || self.indicators || self.triage
    }

    /// Whether the specified tool is enabled in this configuration.
    pub fn tool_enabled(&self, tool: MutatingTool) -> bool {
        match tool {
            MutatingTool::Response => self.live_response,
            MutatingTool::DeviceResponse => self.device_response,
            MutatingTool::Indicators => self.indicators,
            MutatingTool::Triage => self.triage,
        }
    }
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

    /// Hide mutating tools from discovery and reject mutating calls locally before any network request
    #[arg(long, env = ENV_READ_ONLY)]
    pub read_only: bool,

    /// Enable mutating response tools (Live Response, library upload, investigation package collection, stop-and-quarantine)
    #[arg(long, env = ENV_LIVE_RESPONSE_ENABLED)]
    pub enable_live_response: bool,

    /// Comma-separated Live Response command allowlist (PutFile, RunScript, GetFile)
    #[arg(long, env = ENV_LIVE_RESPONSE_ALLOWED_COMMANDS)]
    pub allowed_commands: Option<String>,

    /// Enable device containment and lifecycle actions (`defender_device_response`)
    #[arg(long, env = ENV_DEVICE_RESPONSE_ENABLED)]
    pub enable_device_response: bool,

    /// Enable offboarding action on device response (`requires --enable-device-response`)
    #[arg(
        long,
        env = ENV_OFFBOARDING_ENABLED,
        requires = "enable_device_response"
    )]
    pub enable_offboarding: bool,

    /// Enable tenant-wide custom indicator management (`defender_indicators`)
    #[arg(long, env = ENV_INDICATORS_ENABLED)]
    pub enable_indicators: bool,

    /// Enable alert and incident triage write-back (`defender_triage`)
    #[arg(long, env = ENV_TRIAGE_ENABLED)]
    pub enable_triage: bool,

    /// Turn off human confirmation prompts for destructive actions
    #[arg(long, env = ENV_DISABLE_HUMAN_CONFIRMATION)]
    pub disable_human_confirmation: bool,

    /// Path to append-only JSON Lines audit file
    #[arg(long, env = ENV_AUDIT_LOG)]
    pub audit_log: Option<PathBuf>,

    /// Authentication mode (`app` or `user`)
    #[arg(long, value_enum, default_value = "app", env = ENV_AUTH_MODE)]
    pub auth_mode: AuthMode,

    /// Sign-in flow for `--auth-mode user` (`auto`, `browser`, or `device-code`)
    #[arg(long, value_enum, env = ENV_SIGN_IN_FLOW)]
    pub sign_in_flow: Option<SignInFlow>,

    /// Directory for downloaded investigation packages and quarantined files (created with mode 0700)
    #[arg(long, default_value = DEFAULT_QUARANTINE_DIR, env = ENV_QUARANTINE_DIR)]
    pub quarantine_dir: PathBuf,

    /// Tombstone argument for removed tool-mode option.
    #[arg(long = "tool-mode", hide = true)]
    pub tool_mode_tombstone: Option<String>,
}

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub transport: TransportMode,
    pub bind_address: String,
    pub read_only: bool,
    pub categories: MutationCategories,
    pub live_response_allowed_commands: Option<Vec<String>>,
    pub quarantine_dir: PathBuf,
    pub audit_log: AuditLogSetting,
    pub confirm_destructive: bool,
    pub auth: AuthConfig,
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

        let categories = MutationCategories::from_flags(
            cli.read_only,
            cli.enable_live_response,
            cli.enable_device_response,
            cli.enable_offboarding,
            cli.enable_indicators,
            cli.enable_triage,
        );

        let audit_log = match cli.audit_log {
            Some(path) => AuditLogSetting::Explicit(path),
            None => AuditLogSetting::Default(default_audit_path()),
        };

        let auth = match cli.auth_mode {
            AuthMode::App => AuthConfig::App,
            AuthMode::User => AuthConfig::User {
                flow: cli.sign_in_flow.unwrap_or(SignInFlow::Auto),
            },
        };

        Self {
            transport: cli.transport,
            bind_address: cli.bind_address,
            read_only: cli.read_only,
            categories,
            live_response_allowed_commands,
            quarantine_dir: cli.quarantine_dir,
            audit_log,
            confirm_destructive: !cli.disable_human_confirmation,
            auth,
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

/// Validates credential environment variables required for the selected authentication mode.
pub fn validate_credentials(auth_mode: AuthMode) -> Result<(), String> {
    let tenant_id = std::env::var(ENV_TENANT_ID)
        .map_err(|_| format!("{ENV_TENANT_ID} environment variable is required"))?;
    if tenant_id.trim().is_empty() {
        return Err(format!("{ENV_TENANT_ID} environment variable is required"));
    }

    let client_id = std::env::var(ENV_CLIENT_ID)
        .map_err(|_| format!("{ENV_CLIENT_ID} environment variable is required"))?;
    if client_id.trim().is_empty() {
        return Err(format!("{ENV_CLIENT_ID} environment variable is required"));
    }

    match auth_mode {
        AuthMode::App => {
            let client_secret = std::env::var(ENV_CLIENT_SECRET)
                .map_err(|_| format!("{ENV_CLIENT_SECRET} environment variable is required"))?;
            if client_secret.trim().is_empty() {
                return Err(format!(
                    "{ENV_CLIENT_SECRET} environment variable is required"
                ));
            }
        }
        AuthMode::User => {
            let tenant_lower = tenant_id.trim().to_ascii_lowercase();
            if tenant_lower == "common" || tenant_lower == "organizations" {
                return Err("AZURE_TENANT_ID cannot be 'common' or 'organizations'".to_string());
            }
            if std::env::var_os(ENV_CLIENT_SECRET).is_some() {
                eprintln!("NOTE: AZURE_CLIENT_SECRET is ignored in --auth-mode user.");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutation_categories_read_only_invariant() {
        let categories = MutationCategories::from_flags(
            true, // read_only
            true, // live_response
            true, // device_response
            true, // offboarding
            true, // indicators
            true, // triage
        );
        assert!(!categories.any());
        assert!(!categories.live_response);
        assert!(!categories.device_response);
        assert!(!categories.offboarding);
        assert!(!categories.indicators);
        assert!(!categories.triage);
        assert!(!categories.tool_enabled(MutatingTool::Response));
        assert!(!categories.tool_enabled(MutatingTool::DeviceResponse));
        assert!(!categories.tool_enabled(MutatingTool::Indicators));
        assert!(!categories.tool_enabled(MutatingTool::Triage));
    }

    #[test]
    fn test_mutation_categories_offboarding_requires_device_response() {
        // Offboarding flag true, but device response false -> offboarding false
        let cat1 = MutationCategories::from_flags(false, false, false, true, false, false);
        assert!(!cat1.offboarding);
        assert!(!cat1.device_response);
        assert!(!cat1.any());

        // Offboarding flag true, and device response true -> offboarding true
        let cat2 = MutationCategories::from_flags(false, false, true, true, false, false);
        assert!(cat2.offboarding);
        assert!(cat2.device_response);
        assert!(cat2.any());
        assert!(cat2.tool_enabled(MutatingTool::DeviceResponse));
    }

    #[test]
    fn test_mutating_tool_destructive() {
        assert!(MutatingTool::Response.destructive());
        assert!(MutatingTool::DeviceResponse.destructive());
        assert!(MutatingTool::Indicators.destructive());
        assert!(!MutatingTool::Triage.destructive());
    }

    #[test]
    fn test_server_config_derivation() {
        let cli = Cli {
            transport: TransportMode::Stdio,
            bind_address: "127.0.0.1:8000".to_string(),
            read_only: false,
            enable_live_response: true,
            allowed_commands: Some("PutFile,RunScript".to_string()),
            enable_device_response: true,
            enable_offboarding: true,
            enable_indicators: false,
            enable_triage: false,
            disable_human_confirmation: true,
            audit_log: Some(PathBuf::from("/custom/audit.jsonl")),
            auth_mode: AuthMode::App,
            sign_in_flow: None,
            quarantine_dir: PathBuf::from("./quarantine"),
            tool_mode_tombstone: None,
        };

        let config = ServerConfig::from_cli(cli);
        assert!(!config.read_only);
        assert!(config.categories.live_response);
        assert!(config.categories.device_response);
        assert!(config.categories.offboarding);
        assert!(!config.categories.indicators);
        assert!(!config.categories.triage);
        assert!(!config.confirm_destructive);
        assert_eq!(config.auth, AuthConfig::App);
        assert!(config.audit_log.is_explicit());
        assert_eq!(
            config.audit_log.path(),
            std::path::Path::new("/custom/audit.jsonl")
        );
        assert_eq!(
            config.live_response_allowed_commands,
            Some(vec!["PutFile".to_string(), "RunScript".to_string()])
        );
    }

    static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_sign_in_flow_default_is_auto() {
        assert_eq!(SignInFlow::default(), SignInFlow::Auto);
    }

    #[test]
    fn test_validate_credentials_app_mode() {
        let _lock = TEST_ENV_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var(ENV_TENANT_ID, "test-tenant");
            std::env::set_var(ENV_CLIENT_ID, "test-client");
            std::env::set_var(ENV_CLIENT_SECRET, "test-secret");
        }
        assert!(validate_credentials(AuthMode::App).is_ok());

        unsafe {
            std::env::remove_var(ENV_CLIENT_SECRET);
        }
        let err = validate_credentials(AuthMode::App).unwrap_err();
        assert!(err.contains("AZURE_CLIENT_SECRET environment variable is required"));
    }

    #[test]
    fn test_validate_credentials_user_mode_rejects_common_and_organizations() {
        let _lock = TEST_ENV_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var(ENV_CLIENT_ID, "test-client");
            std::env::set_var(ENV_TENANT_ID, "common");
        }
        let err_common = validate_credentials(AuthMode::User).unwrap_err();
        assert_eq!(
            err_common,
            "AZURE_TENANT_ID cannot be 'common' or 'organizations'"
        );

        unsafe {
            std::env::set_var(ENV_TENANT_ID, "organizations");
        }
        let err_orgs = validate_credentials(AuthMode::User).unwrap_err();
        assert_eq!(
            err_orgs,
            "AZURE_TENANT_ID cannot be 'common' or 'organizations'"
        );

        unsafe {
            std::env::set_var(ENV_TENANT_ID, "72f988bf-1234-5678-9abc-def012345678");
            std::env::set_var(ENV_CLIENT_SECRET, "should-be-ignored");
        }
        assert!(validate_credentials(AuthMode::User).is_ok());
    }
}
