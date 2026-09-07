//! Shared constants for the Microsoft Defender MCP server.

/// Default Microsoft Graph API base URL.
pub const GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";

/// Override environment variable for the Graph base URL (testing).
pub const ENV_GRAPH_BASE_URL: &str = "GRAPH_BASE_URL";

/// Default Defender for Endpoint API base URL.
pub const ENDPOINT_BASE_URL: &str = "https://api.securitycenter.microsoft.com";

/// Override environment variable for the Endpoint base URL (testing).
pub const ENV_ENDPOINT_BASE_URL: &str = "DEFENDER_ENDPOINT_BASE_URL";

/// Default OAuth2 token endpoint template.
/// `{tenant}` will be replaced at runtime.
pub const TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token";

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

/// Maximum response size in characters before truncation (future use).
#[allow(dead_code)]
pub const CHARACTER_LIMIT: usize = 50_000;

/// Transport selection environment variable.
pub const ENV_TRANSPORT: &str = "TRANSPORT";

/// Gate for Live Response tools.
pub const ENV_LIVE_RESPONSE_ENABLED: &str = "DEFENDER_ENABLE_LIVE_RESPONSE";

/// Optional allowlist of Live Response command types (comma-separated).
pub const ENV_LIVE_RESPONSE_ALLOWED_COMMANDS: &str = "DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS";

/// Default look-back hours for IP/domain/file statistics.
pub const DEFAULT_LOOK_BACK_HOURS: i32 = 720;

/// Maximum look-back hours.
pub const MAX_LOOK_BACK_HOURS: i32 = 720;

/// Maximum Live Response commands array size.
pub const MAX_LIVE_RESPONSE_COMMANDS: usize = 20;

/// Minimum Live Response comment length.
pub const MIN_LIVE_RESPONSE_COMMENT_LEN: usize = 10;

/// Maximum library file upload size in bytes (20 MB).
pub const MAX_LIBRARY_FILE_SIZE: usize = 20 * 1024 * 1024;

/// API path for library file upload.
pub const LIBRARY_FILES_PATH: &str = "/api/libraryfiles";
