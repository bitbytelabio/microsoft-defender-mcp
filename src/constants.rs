//! Shared constants for the Microsoft Defender MCP server.

/// Default Microsoft Graph API base URL.
pub const GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";

/// Override environment variable for the Graph base URL (testing).
pub const ENV_GRAPH_BASE_URL: &str = "GRAPH_BASE_URL";

/// Default Defender for Endpoint API base URL.
pub const ENDPOINT_BASE_URL: &str = "https://api.securitycenter.microsoft.com";

/// Override environment variable for the Endpoint base URL (testing).
pub const ENV_ENDPOINT_BASE_URL: &str = "DEFENDER_ENDPOINT_BASE_URL";

/// OAuth2 scope for Microsoft Graph.
pub const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";

/// OAuth2 scope for Defender for Endpoint APIs.
pub const ENDPOINT_SCOPE: &str = "https://api.securitycenter.microsoft.com/.default";

/// Environment variable names for Azure credentials.
pub const ENV_TENANT_ID: &str = "AZURE_TENANT_ID";
pub const ENV_CLIENT_ID: &str = "AZURE_CLIENT_ID";
pub const ENV_CLIENT_SECRET: &str = "AZURE_CLIENT_SECRET";

/// Default number of results per page for list tools.
pub const DEFAULT_TOP: i32 = 50;

/// Maximum allowed `top` value for Graph/TI list tools.
pub const MAX_TOP: i32 = 1000;

/// Maximum allowed `top` value for Endpoint list tools.
pub const ENDPOINT_MAX_TOP: i32 = 10_000;

/// Maximum allowed `skip` value.
pub const MAX_SKIP: i32 = 100_000;

/// HTTP request timeout in seconds.
/// Set to 210s to provide 30s headroom above Microsoft Graph Advanced Hunting's 180s (3-minute) execution timeout.
pub const REQUEST_TIMEOUT_SECS: u64 = 210;

/// Token cache safety margin in seconds.
pub const TOKEN_EXPIRY_BUFFER_SECS: i64 = 60;

/// Transport selection environment variable.
pub const ENV_TRANSPORT: &str = "TRANSPORT";

/// Default local staging directory for downloaded forensic artifacts.
pub const DEFAULT_QUARANTINE_DIR: &str = "./quarantine_artifacts";

/// Default socket address for streamable HTTP transport.
pub const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:8000";

/// Environment variable for read-only mode.
pub const ENV_READ_ONLY: &str = "DEFENDER_READ_ONLY";

/// Environment variable for HTTP bind address.
pub const ENV_BIND_ADDRESS: &str = "BIND_ADDRESS";

/// Environment variable for quarantine directory.
pub const ENV_QUARANTINE_DIR: &str = "DEFENDER_QUARANTINE_DIR";

/// Gate for Live Response tools.
pub const ENV_LIVE_RESPONSE_ENABLED: &str = "DEFENDER_ENABLE_LIVE_RESPONSE";

/// Optional allowlist of Live Response command types (comma-separated).
pub const ENV_LIVE_RESPONSE_ALLOWED_COMMANDS: &str = "DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS";

/// Gate for device containment and lifecycle actions (`defender_device_response`).
pub const ENV_DEVICE_RESPONSE_ENABLED: &str = "DEFENDER_ENABLE_DEVICE_RESPONSE";

/// Gate for the irreversible `offboard` action; requires device response.
pub const ENV_OFFBOARDING_ENABLED: &str = "DEFENDER_ENABLE_OFFBOARDING";

/// Gate for tenant-wide custom indicators (`defender_indicators`).
pub const ENV_INDICATORS_ENABLED: &str = "DEFENDER_ENABLE_INDICATORS";

/// Gate for alert and incident triage write-back (`defender_triage`).
pub const ENV_TRIAGE_ENABLED: &str = "DEFENDER_ENABLE_TRIAGE";

/// Turns off the human-confirmation prompt for destructive actions.
pub const ENV_DISABLE_HUMAN_CONFIRMATION: &str = "DEFENDER_DISABLE_HUMAN_CONFIRMATION";

/// Path of the append-only JSON Lines audit log.
pub const ENV_AUDIT_LOG: &str = "DEFENDER_AUDIT_LOG";

/// Authentication mode (`app` or `user`).
pub const ENV_AUTH_MODE: &str = "DEFENDER_AUTH_MODE";

/// Interactive sign-in flow for `--auth-mode user`.
pub const ENV_SIGN_IN_FLOW: &str = "DEFENDER_SIGN_IN_FLOW";

/// Override for the Entra ID authority base URL (testing).
pub const ENV_AUTHORITY_BASE_URL: &str = "DEFENDER_AUTHORITY_BASE_URL";

/// Removed in 1.0.0; checked only to fail startup with a migration message.
pub const ENV_REMOVED_TOOL_MODE: &str = "DEFENDER_TOOL_MODE";

/// Default Entra ID authority base URL.
pub const AUTHORITY_BASE_URL: &str = "https://login.microsoftonline.com";

/// Maximum indicator IDs per `batch_delete` request (documented upstream).
pub const MAX_INDICATOR_BATCH: usize = 500;

/// Maximum alert IDs per endpoint alert batch update. Server policy: the upstream limit is
/// undocumented.
pub const MAX_ALERT_BATCH: usize = 500;

/// Maximum age in days of the `find_by_ip` timestamp.
pub const FIND_BY_IP_MAX_AGE_DAYS: i64 = 30;

/// Seconds to wait for the user to answer a confirmation prompt.
pub const ELICITATION_TIMEOUT_SECS: u64 = 300;

/// Seconds to wait for the browser sign-in redirect.
pub const BROWSER_SIGN_IN_TIMEOUT_SECS: u64 = 300;

/// Default look-back hours for IP/domain/file statistics.
pub const DEFAULT_LOOK_BACK_HOURS: i32 = 720;

/// Maximum look-back hours.
pub const MAX_LOOK_BACK_HOURS: i32 = 720;

/// Maximum Live Response commands array size.
pub const MAX_LIVE_RESPONSE_COMMANDS: usize = 20;

/// Minimum justification length for every mutating action.
pub const MIN_JUSTIFICATION_LEN: usize = 10;

/// Maximum library file upload size in bytes (20 MB).
pub const MAX_LIBRARY_FILE_SIZE: usize = 20 * 1024 * 1024;

/// API path for library file upload.
pub const LIBRARY_FILES_PATH: &str = "/api/libraryfiles";
