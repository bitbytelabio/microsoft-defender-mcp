//! Defender MCP server: tool router, tool implementations, and server handler.

use rmcp::{
    ErrorData as McpError, ServerHandler, handler::server::wrapper::Parameters, model::*, tool,
    tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::client::{EndpointClient, GraphClient, ODataParams};
use crate::constants::DEFAULT_TOP;
use crate::validation;

// ---------------------------------------------------------------------------
// Macro: define a named ID input struct with serde alias "id"
// ---------------------------------------------------------------------------
macro_rules! define_id_input {
    ($name:ident, $field:ident, $doc:literal) => {
        #[doc = concat!("Input containing a `", stringify!($field), "`.")]
        #[derive(Debug, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            #[doc = $doc]
            #[schemars(length(min = 1))]
            #[serde(alias = "id")]
            pub $field: String,
        }
    };
}

// ---------------------------------------------------------------------------
// Shared input types
// ---------------------------------------------------------------------------

/// Input for tools requiring only a hostname.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostnameInput {
    /// Domain name or IP literal copied from the indicator under investigation (for example, `contoso.com`).
    /// Supply one host value, not a URL; slashes, whitespace, dot segments, and control characters are rejected.
    #[schemars(length(min = 1, max = 253))]
    pub hostname: String,
}

/// Input for tools requiring a hostname + OData list parameters.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostnameODataInput {
    /// Domain name or IP literal copied from the indicator under investigation (for example, `contoso.com`); supply one host value, not a URL.
    #[schemars(length(min = 1, max = 253))]
    pub hostname: String,

    /// Maximum results to return (default: 50, max: 1000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 1000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,

    /// OData $filter expression (e.g., "firstSeenDateTime ge 2024-01-01").
    #[serde(default)]
    pub filter: Option<String>,

    /// Service-supported fields to return as an OData `$select` list.
    #[serde(default)]
    pub select: Option<String>,

    /// Service-supported relationships to include as an OData `$expand` list.
    #[serde(default)]
    pub expand: Option<String>,

    /// When true, include the total match count in the response ($count=true).
    /// Supported for count-capable endpoints such as host SSL certificates.
    #[serde(default)]
    pub count: Option<bool>,
}

/// Input for OData list endpoints (no hostname required).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ODataListInput {
    /// Maximum results to return (default: 50, max: 1000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 1000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,

    /// Service-specific OData `$filter` expression; supported fields and operators vary by endpoint.
    #[serde(default)]
    pub filter: Option<String>,

    /// Service-supported fields to return as an OData `$select` list.
    #[serde(default)]
    pub select: Option<String>,

    /// Service-supported relationships to include as an OData `$expand` list.
    #[serde(default)]
    pub expand: Option<String>,

    /// Single OData `$search` term; this is supported for threat-intelligence articles, not every endpoint.
    #[serde(default)]
    pub search: Option<String>,

    /// When true, request the total match count ($count=true).
    /// Supported by XDR alerts, XDR incidents, and other count-capable Graph endpoints.
    #[serde(default)]
    pub count: Option<bool>,
}

// ---- Named ID inputs (replacing the generic IdInput) ----

define_id_input!(
    IntelProfileIdInput,
    intel_profile_id,
    "Threat-intelligence profile ID copied unchanged from a profile collection (for example, 9b01de37bf66d1760954a16dc2b52fed2a7bd4e093dfc8a4905e108e4843da80). Do not manually base64-encode opaque IDs."
);

define_id_input!(
    IntelProfileIndicatorIdInput,
    indicator_id,
    "Opaque indicator ID copied unchanged from an intelligence-profile indicator collection; do not decode or manually base64-encode it."
);

define_id_input!(
    ArticleIdInput,
    article_id,
    "Threat-intelligence article ID copied unchanged from an article collection (for example, a272d5ab)."
);

define_id_input!(
    ArticleIndicatorIdInput,
    indicator_id,
    "Opaque indicator ID copied unchanged from an article-indicator collection; do not decode or manually base64-encode it."
);

define_id_input!(
    HostComponentIdInput,
    component_id,
    "Opaque component ID copied unchanged from a host component collection; do not manually base64-encode it."
);

define_id_input!(
    HostCookieIdInput,
    cookie_id,
    "Opaque cookie ID copied unchanged from a host cookie collection; do not manually base64-encode it."
);

define_id_input!(
    HostPortIdInput,
    port_id,
    "Opaque port record ID copied unchanged from a host port collection; do not manually base64-encode it."
);

define_id_input!(
    HostTrackerIdInput,
    tracker_id,
    "Opaque tracker ID copied unchanged from a host tracker collection; do not manually base64-encode it."
);

define_id_input!(
    HostPairIdInput,
    pair_id,
    "Opaque host-pair ID copied unchanged from a host-pair collection; do not manually base64-encode it."
);

define_id_input!(
    SslCertIdInput,
    certificate_id,
    "Opaque certificate ID copied unchanged from an SSL-certificate collection (often base64 text such as MDJjODMz...); do not decode or encode it again."
);

define_id_input!(
    WhoisRecordIdInput,
    record_id,
    "Opaque WHOIS record ID copied unchanged from a WHOIS collection (often base64 text); do not decode or encode it again."
);

define_id_input!(
    PassiveDnsRecordIdInput,
    record_id,
    "Opaque passive-DNS record ID copied unchanged from a passive-DNS collection; do not manually base64-encode it."
);

// ---- Named ID+OData inputs (replacing the generic IdODataInput) ----

/// Input for listing intel profile indicators by profile ID + OData params.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntelProfileIdODataInput {
    /// Profile ID copied unchanged from an intel-profile collection; opaque IDs must not be manually encoded.
    #[schemars(length(min = 1))]
    #[serde(alias = "id")]
    pub intel_profile_id: String,

    /// Maximum results to return (default: 50, max: 1000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 1000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,

    /// Service-specific OData `$filter` expression; supported fields and operators vary by endpoint.
    #[serde(default)]
    pub filter: Option<String>,

    /// Service-supported fields to return as an OData `$select` list.
    #[serde(default)]
    pub select: Option<String>,

    /// Service-supported relationships to include as an OData `$expand` list.
    #[serde(default)]
    pub expand: Option<String>,
}

/// Input for listing article indicators by article ID + OData params.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArticleIdODataInput {
    /// Article ID copied unchanged from an articles collection (for example, `a272d5ab`).
    #[schemars(length(min = 1))]
    #[serde(alias = "id")]
    pub article_id: String,

    /// Maximum results to return (default: 50, max: 1000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 1000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,

    /// Service-supported fields to return as an OData `$select` list.
    #[serde(default)]
    pub select: Option<String>,
}

/// Input for listing SSL certificate related hosts + OData params.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertRelatedHostsInput {
    /// Opaque certificate ID copied unchanged from an SSL-certificate collection; do not re-encode base64 text.
    #[schemars(length(min = 1))]
    #[serde(alias = "id")]
    pub certificate_id: String,

    /// Maximum results to return (default: 50, max: 1000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 1000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,

    /// When true, include the total match count in the response ($count=true).
    #[serde(default)]
    pub count: Option<bool>,
}

// ---- Vulnerability-specific inputs ----

/// Input for CVE vulnerability tools.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityIdInput {
    /// CVE identifier in format CVE-YYYY-NNNN+ (e.g., CVE-2021-44228).
    #[schemars(length(min = 10))]
    pub vulnerability_id: String,
}

/// Input for vulnerability components (CVE + OData params).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityODataInput {
    /// CVE identifier in format CVE-YYYY-NNNN+ (e.g., CVE-2021-44228).
    #[schemars(length(min = 10))]
    pub vulnerability_id: String,

    /// Maximum results to return (default: 50, max: 1000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 1000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,

    /// Service-supported fields to return as an OData `$select` list.
    #[serde(default)]
    pub select: Option<String>,
}

/// Input for vulnerability component get (CVE + component ID).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VulnComponentGetInput {
    /// CVE identifier (e.g., CVE-2021-44228).
    #[schemars(length(min = 10))]
    pub vulnerability_id: String,

    /// Opaque component ID copied unchanged from the vulnerability component collection; do not re-encode it.
    #[schemars(length(min = 1))]
    pub component_id: String,
}

/// Input for the Advanced Hunting tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HuntingQueryInput {
    /// Read-only KQL query against the current Microsoft Defender XDR advanced-hunting schema.
    /// Example: `DeviceProcessEvents | where InitiatingProcessFileName =~ 'powershell.exe' | limit 10`
    #[schemars(length(min = 1, max = 128000))]
    pub query: String,

    /// ISO 8601 time range. Examples: P30D, P7D,
    /// 2024-01-01T00:00:00Z/2024-01-07T00:00:00Z.
    /// Default: `P30D`. Available history depends on upstream data and workspace retention.
    #[serde(default = "default_timespan")]
    pub timespan: String,
}

fn default_top_value() -> i32 {
    DEFAULT_TOP
}

fn default_timespan() -> String {
    "P30D".to_string()
}

// ---------------------------------------------------------------------------
// Live Response types
// ---------------------------------------------------------------------------

/// Supported Defender for Endpoint Live Response command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum LiveResponseCommandType {
    PutFile,
    RunScript,
    GetFile,
}

impl LiveResponseCommandType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PutFile => "PutFile",
            Self::RunScript => "RunScript",
            Self::GetFile => "GetFile",
        }
    }
}

/// A single command in a Live Response sequence.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveResponseCommand {
    /// Command type. PutFile copies a library file to the device; RunScript executes a
    /// library script; GetFile retrieves a device file. These operations affect a live endpoint.
    #[serde(rename = "type")]
    pub cmd_type: LiveResponseCommandType,

    /// Command parameters using the Microsoft API's lowercase `key`/`value` shape.
    /// Examples: `ScriptName=collect.ps1` and `Args=-Verbose` for RunScript,
    /// `FileName=tool.exe` for PutFile, or `Path=C:\temp\artifact.zip` for GetFile.
    pub params: Vec<LiveResponseParam>,
}

/// A key-value parameter for a Live Response command.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveResponseParam {
    /// Microsoft command parameter key, such as FileName, ScriptName, Path, or Args.
    pub key: String,
    /// Parameter value. This can be a library name, script argument string, or remote path;
    /// it is sent to Defender for Endpoint and may cause changes on the target device.
    pub value: String,
}

// ---- Endpoint API input types ----

/// OData input for Defender for Endpoint collection tools (maximum `top` 10000).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointODataInput {
    /// Service-specific OData `$filter` expression; supported fields and operators vary by endpoint.
    #[serde(default)]
    pub filter: Option<String>,

    /// Maximum results to return (default: 50, max: 10000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 10000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,
}

define_id_input!(
    MachineIdInput,
    machine_id,
    "Microsoft Defender for Endpoint machine ID copied from machine inventory; usually a 40-character hexadecimal Defender device ID, not a UUID or Microsoft Entra deviceId."
);

define_id_input!(
    SoftwareIdInput,
    software_id,
    "Software inventory ID copied from a Defender software collection (for example, microsoft-_-internet_explorer)."
);

/// Input for software machines/vulnerabilities/missing KBs/distribution with OData.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SoftwareODataInput {
    /// Software inventory ID copied from a software collection (for example, `microsoft-_-internet_explorer`).
    #[schemars(length(min = 1))]
    #[serde(alias = "id")]
    pub software_id: String,

    /// Service-specific OData `$filter` expression; supported fields and operators vary by endpoint.
    #[serde(default)]
    pub filter: Option<String>,

    /// Maximum results to return (default: 50, max: 10000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 10000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,
}

/// Find machines by tag.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindByTagInput {
    /// Free-form Defender machine tag value. It is sent as a query value, so values containing `/` or dots are preserved.
    #[schemars(length(min = 1))]
    pub tag_name: String,

    /// If true, matches tags beginning with tag_name; else exact match.
    #[serde(default)]
    pub use_starts_with: bool,
}

define_id_input!(CveIdInput, cve_id, "CVE identifier (e.g., CVE-2021-44228).");

/// CVE + OData params for vulnerability machine references.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CveODataInput {
    /// CVE identifier in `CVE-YYYY-NNNN+` form (for example, `CVE-2021-44228`).
    #[schemars(length(min = 10))]
    pub cve_id: String,

    /// Service-specific OData `$filter` expression; supported fields and operators vary by endpoint.
    #[serde(default)]
    pub filter: Option<String>,

    /// Maximum results to return (default: 50, max: 10000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 10000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,
}

define_id_input!(
    RecommendationIdInput,
    recommendation_id,
    "Recommendation identifier (e.g., va-_-google-_-chrome)."
);

define_id_input!(
    RemediationIdInput,
    remediation_id,
    "Opaque remediation task ID copied unchanged from a remediation-task collection."
);

/// Remediation ID + OData params for exposed devices.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemediationODataInput {
    /// Remediation task ID copied unchanged from a remediation-task collection.
    #[schemars(length(min = 1))]
    #[serde(alias = "id")]
    pub remediation_id: String,

    /// Service-specific OData `$filter` expression; supported fields and operators vary by endpoint.
    #[serde(default)]
    pub filter: Option<String>,

    /// Maximum results to return (default: 50, max: 10000).
    #[serde(default = "default_top_value")]
    #[schemars(range(min = 1, max = 10000))]
    pub top: i32,

    /// Number of results to skip for this one-page request (default: 0, range: 0–100000).
    #[serde(default)]
    #[schemars(range(min = 0, max = 100000))]
    pub skip: i32,
}

/// IP address input.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpInput {
    /// Valid IPv4 or IPv6 literal (for example, `203.0.113.9` or `2001:db8::1`).
    #[schemars(length(min = 1))]
    pub ip_address: String,
}

/// IP address + look-back hours for statistics.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpStatsInput {
    /// Valid IPv4 or IPv6 literal (for example, `203.0.113.9` or `2001:db8::1`).
    #[schemars(length(min = 1))]
    pub ip_address: String,

    /// Statistics lookback in hours (default: 720; accepted range: 1–720).
    #[serde(default)]
    #[schemars(range(min = 1, max = 720))]
    pub look_back_hours: Option<i32>,
}

/// Domain name input.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DomainInput {
    /// Domain name (e.g., example.com).
    #[schemars(length(min = 1, max = 253))]
    pub domain_name: String,
}

/// Domain name + look-back hours for statistics.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DomainStatsInput {
    /// Domain name (e.g., example.com).
    #[schemars(length(min = 1, max = 253))]
    pub domain_name: String,

    /// Statistics lookback in hours (default: 720; accepted range: 1–720).
    #[serde(default)]
    #[schemars(range(min = 1, max = 720))]
    pub look_back_hours: Option<i32>,
}

/// File hash input (MD5/SHA1/SHA256).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileIdInput {
    /// File hash: MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex).
    #[schemars(length(min = 32, max = 64))]
    pub file_id: String,
}

/// File SHA1 input.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileSha1Input {
    /// File SHA1 hash: exactly 40 hexadecimal characters; MD5 and SHA256 are not accepted here.
    #[schemars(length(min = 40, max = 40))]
    pub file_sha1: String,
}

/// File SHA1 + look-back hours for statistics.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileStatsInput {
    /// File SHA1 hash: exactly 40 hexadecimal characters; MD5 and SHA256 are not accepted here.
    #[schemars(length(min = 40, max = 40))]
    pub file_sha1: String,

    /// Statistics lookback in hours (default: 720; accepted range: 1–720).
    #[serde(default)]
    #[schemars(range(min = 1, max = 720))]
    pub look_back_hours: Option<i32>,
}

/// Defender for Endpoint username input.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserIdInput {
    /// Account username recognized by Defender for Endpoint (for example, `user1`); do not pass a full UPN, SID, or Entra object ID.
    #[schemars(length(min = 1))]
    pub user_id: String,
}

define_id_input!(
    AlertIdInput,
    alert_id,
    "Defender for Endpoint alert ID copied unchanged from an alert collection."
);

define_id_input!(
    ActionIdInput,
    action_id,
    "Machine-action ID copied unchanged from a machine-action response or collection (typically a GUID)."
);

define_id_input!(
    XdrAlertIdInput,
    alert_id,
    "Defender XDR Alert v2 ID copied unchanged from an alerts_v2 collection (for example, da637578995287051192_756343937)."
);

/// XDR incident ID with optional expand.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XdrIncidentIdInput {
    /// Defender XDR incident ID copied unchanged from an incident collection.
    #[schemars(length(min = 1))]
    #[serde(alias = "id")]
    pub incident_id: String,

    /// Comma-separated relationships to expand (e.g., "alerts").
    #[serde(default)]
    pub expand: Option<String>,
}

// ---- Live Response input types ----

/// Input for running a live response session.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveResponseRunInput {
    /// Defender for Endpoint machine ID, usually the 40-hex Defender device ID returned by machine inventory; not an Entra device ID.
    #[schemars(length(min = 1))]
    pub machine_id: String,

    /// Ordered commands to execute on the live device (maximum 20). Use exact `PutFile`, `RunScript`, or `GetFile` types with command-specific `params`.
    #[schemars(length(min = 1, max = 20))]
    pub commands: Vec<LiveResponseCommand>,

    /// Human-readable operational justification (at least 10 trimmed Unicode characters); stored in the audit trail.
    #[schemars(length(min = 10))]
    pub comment: String,
}

/// Input for getting live response command result.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveResponseResultInput {
    /// Machine-action ID returned by `defender_endpoint_live_response_run`.
    #[schemars(length(min = 1))]
    pub action_id: String,

    /// Zero-based command index from the original action (default: 0). Negative indices are rejected locally.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub command_index: i32,
}

/// Input for uploading a file to the live response library.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveResponseLibraryUploadInput {
    /// Destination library basename (for example, `collect.ps1`); paths, `.` and `..` are rejected.
    #[schemars(length(min = 1))]
    pub file_name: String,

    /// Non-empty UTF-8 file content, limited to 20 MiB by encoded byte length.
    #[schemars(length(min = 1))]
    pub file_content: String,

    /// Non-empty operational description. Slashes, ordinary punctuation, tabs, and newlines are preserved.
    #[schemars(length(min = 1))]
    pub description: String,

    /// Optional human-readable guidance for script parameters.
    #[serde(default)]
    pub parameters_description: Option<String>,

    /// Whether to replace an existing library file with the same name; `true` is destructive.
    #[serde(default)]
    pub override_if_exists: Option<bool>,
}

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DefenderServer {
    client: GraphClient,
    endpoint: EndpointClient,
    live_response_enabled: bool,
}

impl DefenderServer {
    pub fn new(client: GraphClient, endpoint: EndpointClient) -> Self {
        let live_response_enabled = std::env::var(crate::constants::ENV_LIVE_RESPONSE_ENABLED)
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        Self {
            client,
            endpoint,
            live_response_enabled,
        }
    }

    // ---- Shared helpers ----

    /// Build ODataParams from an ODataListInput.
    fn from_odata_list(i: &ODataListInput) -> ODataParams {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            filter: i.filter.clone(),
            select: i.select.clone(),
            expand: i.expand.clone(),
            search: i.search.clone(),
            count: i.count,
        }
    }

    /// Build ODataParams from a HostnameODataInput.
    fn from_hostname_odata(i: &HostnameODataInput) -> ODataParams {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            filter: i.filter.clone(),
            select: i.select.clone(),
            expand: i.expand.clone(),
            search: None,
            count: i.count,
        }
    }

    /// Build ODataParams from an IntelProfileIdODataInput.
    fn from_intel_profile_odata(i: &IntelProfileIdODataInput) -> ODataParams {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            filter: i.filter.clone(),
            select: i.select.clone(),
            expand: i.expand.clone(),
            search: None,
            count: None,
        }
    }

    /// Build ODataParams from an ArticleIdODataInput.
    fn from_article_odata(i: &ArticleIdODataInput) -> ODataParams {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            select: i.select.clone(),
            filter: None,
            expand: None,
            search: None,
            count: None,
        }
    }

    /// Build ODataParams from a CertRelatedHostsInput.
    fn from_cert_related_odata(i: &CertRelatedHostsInput) -> ODataParams {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            count: i.count,
            filter: None,
            select: None,
            expand: None,
            search: None,
        }
    }

    /// Convenience: perform a simple GET and return the raw JSON as structured content.
    async fn simple_get(&self, path: &str) -> Result<CallToolResult, McpError> {
        match self.client.graph_get(path, &[]).await {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Ok(e),
        }
    }

    /// Convenience: GET with OData params, return raw JSON as structured content.
    async fn odata_get(&self, path: &str, odata: &ODataParams) -> Result<CallToolResult, McpError> {
        match self.client.graph_get_with_odata(path, odata).await {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Ok(e),
        }
    }

    // ---- Endpoint helpers ----

    async fn ep_simple_get(&self, path: &str) -> Result<CallToolResult, McpError> {
        match self.endpoint.endpoint_get(path, &[]).await {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Ok(e),
        }
    }

    async fn ep_odata_get(
        &self,
        path: &str,
        odata: &ODataParams,
    ) -> Result<CallToolResult, McpError> {
        match self.endpoint.endpoint_get_with_odata(path, odata).await {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Ok(e),
        }
    }

    /// Build ODataParams with endpoint max top.
    fn ep_odata(filter: Option<String>, top: i32, skip: i32) -> ODataParams {
        ODataParams {
            top: Some(top),
            skip: Some(skip),
            filter,
            select: None,
            expand: None,
            search: None,
            count: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool_router]
impl DefenderServer {
    // ============================================================
    // 3.1 Advanced Hunting
    // ============================================================

    /// Execute a KQL query against Microsoft Defender XDR's advanced hunting schema.
    ///
    /// Local validation rejects empty, oversized, and leading-dot management commands;
    /// Microsoft Graph remains the query-language authority. The upstream service limits
    /// results to 100,000 rows and 50 MB with an approximately three-minute timeout.
    /// `P30D` is the default timespan; available history depends on tenant retention.
    #[tool(
        name = "defender_advanced_hunting_run",
        description = "Execute a read-only KQL query across Microsoft Defender XDR advanced hunting event \
                       tables (DeviceProcessEvents, DeviceNetworkEvents, EmailEvents, IdentityLogonEvents, \
                       etc.). Returns matching event rows and column schema. Timespan defaults to P30D (last \
                       30 days) and accepts all ISO 8601 duration/interval formats (e.g., P7D, P90D, or \
                       explicit start/end timestamps); available history depends on upstream data and \
                       workspace retention policies. Execution is limited to 100,000 rows, 50 MB response \
                       payload, and approximately 3-minute timeout per query, subject to tenant-dependent \
                       rate and CPU resource quotas. Requires ThreatHunting.Read.All application permission.",
        annotations(
            title = "Advanced Hunting Run",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_advanced_hunting_run(
        &self,
        Parameters(params): Parameters<HuntingQueryInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_kql_query(&params.query)?;

        let body = json!({
            "Query": params.query,
            "Timespan": params.timespan,
        });

        match self
            .client
            .graph_post("/security/runHuntingQuery", &body)
            .await
        {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Ok(e),
        }
    }

    // ============================================================
    // 3.2 TI Intel Profiles
    // ============================================================

    /// List all threat intelligence intel profiles (actor profiles).
    #[tool(
        name = "defender_ti_intel_profiles_list",
        description = "List threat actor intelligence profiles from Microsoft Defender Threat Intelligence, \
                       including nation-state groups, cybercrime syndicates, and tracked activity groups. \
                       Returns an OData collection of actor profiles with names, aliases, targets, and \
                       description summaries. Supports OData query parameters: $top (default 50, max 1000), \
                       $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Intel Profiles",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_intel_profiles_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/threatIntelligence/intelProfiles", &odata)
            .await
    }

    /// Get details of a specific intel profile by ID.
    #[tool(
        name = "defender_ti_intel_profile_get",
        description = "Retrieve detailed information for a specific threat actor profile by its unique \
                       identifier. Returns full profile metadata including known aliases, active targets, \
                       targeted industries and geographic regions, threat descriptions, and first/last seen \
                       dates. Pass the opaque intel_profile_id copied directly from profile listing or query \
                       results; do not manually base64-encode. Requires ThreatIntelligence.Read.All \
                       application permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Intel Profile",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_intel_profile_get(
        &self,
        Parameters(params): Parameters<IntelProfileIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let intel_profile_id =
            validation::validate_required_id(&params.intel_profile_id, "intel_profile_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/intelProfiles/{}",
            validation::encode_path_segment(intel_profile_id)
        ))
        .await
    }

    /// List indicators of compromise (IoCs) associated with a specific intel profile.
    #[tool(
        name = "defender_ti_intel_profile_indicators_list",
        description = "List indicators of compromise (IoCs) associated with a specific threat actor \
                       profile, such as command-and-control IP addresses, malicious domains, and file \
                       hashes. Returns an OData collection of indicator entities. Pass the opaque \
                       intel_profile_id. Supports OData query parameters: $top (default 50, max 1000), $skip \
                       for offset pagination, $filter, $select, and $expand. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Intel Profile Indicators",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_intel_profile_indicators_list(
        &self,
        Parameters(params): Parameters<IntelProfileIdODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let intel_profile_id =
            validation::validate_required_id(&params.intel_profile_id, "intel_profile_id")?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_intel_profile_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/intelProfiles/{}/indicators",
                validation::encode_path_segment(intel_profile_id)
            ),
            &odata,
        )
        .await
    }

    /// Get a specific intel profile indicator by its own ID.
    #[tool(
        name = "defender_ti_intel_profile_indicator_get",
        description = "Retrieve details for a specific threat actor profile indicator by its indicator \
                       identifier. Returns indicator type, observed value, confidence level, first/last seen \
                       timestamps, and associated threat context. Pass the opaque indicator_id copied \
                       verbatim from indicator listing; do not manually base64-encode. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "Get Intel Profile Indicator",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_intel_profile_indicator_get(
        &self,
        Parameters(params): Parameters<IntelProfileIndicatorIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let indicator_id = validation::validate_required_id(&params.indicator_id, "indicator_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/intelProfileIndicators/{}",
            validation::encode_path_segment(indicator_id)
        ))
        .await
    }

    /// List all intel profile indicators globally across all profiles.
    #[tool(
        name = "defender_ti_intel_profile_indicators_global_list",
        description = "List threat intelligence indicators across all actor profiles globally. Returns an \
                       OData collection of threat indicators aggregated across tracked adversaries. Supports \
                       OData query parameters: $top (default 50, max 1000), $skip for offset pagination, \
                       $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved \
                       for subsequent queries. Requires ThreatIntelligence.Read.All application permission \
                       and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Global Intel Profile Indicators",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_intel_profile_indicators_global_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get(
            "/security/threatIntelligence/intelProfileIndicators",
            &odata,
        )
        .await
    }

    // ============================================================
    // 3.3 TI Articles
    // ============================================================

    /// List threat intelligence articles (narrative reports about threats, actors, vulnerabilities).
    #[tool(
        name = "defender_ti_articles_list",
        description = "List threat intelligence articles and research reports published by Microsoft \
                       security researchers covering emerging threats, campaigns, and vulnerabilities. \
                       Returns an OData collection of article summaries. Supports OData query parameters: \
                       $top (default 50, max 1000), $skip for offset pagination, $filter, $select, $expand, \
                       and $search for full-text keyword querying. Single page returned; raw @odata.nextLink \
                       is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application \
                       permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List TI Articles",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_articles_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/threatIntelligence/articles", &odata)
            .await
    }

    /// Get a specific article by ID.
    #[tool(
        name = "defender_ti_article_get",
        description = "Retrieve the full content of a specific threat intelligence article by its article \
                       identifier. Returns comprehensive narrative report details, executive summary, threat \
                       analysis, and publication metadata. Pass the article_id (e.g., a272d5ab) copied \
                       verbatim from article listing. Requires ThreatIntelligence.Read.All application \
                       permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get TI Article",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_article_get(
        &self,
        Parameters(params): Parameters<ArticleIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let article_id = validation::validate_required_id(&params.article_id, "article_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/articles/{}",
            validation::encode_path_segment(article_id)
        ))
        .await
    }

    /// List IoCs associated with a specific article.
    #[tool(
        name = "defender_ti_article_indicators_list",
        description = "List indicators of compromise (IoCs) published within a specific threat intelligence \
                       article. Returns an OData collection of indicator entities associated with the \
                       research report. Pass the article_id. Supports OData query parameters: $top (default \
                       50, max 1000), $skip for offset pagination, and $select. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Article Indicators",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_article_indicators_list(
        &self,
        Parameters(params): Parameters<ArticleIdODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let article_id = validation::validate_required_id(&params.article_id, "article_id")?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_article_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/articles/{}/indicators",
                validation::encode_path_segment(article_id)
            ),
            &odata,
        )
        .await
    }

    /// Get a specific article indicator by its own ID.
    #[tool(
        name = "defender_ti_article_indicator_get",
        description = "Retrieve details of a specific article indicator by its indicator identifier. \
                       Returns indicator attributes, observed values, and threat context published in the \
                       parent research report. Pass the opaque indicator_id copied verbatim from listing \
                       results; do not manually base64-encode. Requires ThreatIntelligence.Read.All \
                       application permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Article Indicator",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_article_indicator_get(
        &self,
        Parameters(params): Parameters<ArticleIndicatorIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let indicator_id = validation::validate_required_id(&params.indicator_id, "indicator_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/articleIndicators/{}",
            validation::encode_path_segment(indicator_id)
        ))
        .await
    }

    /// List all article indicators globally across all articles.
    #[tool(
        name = "defender_ti_article_indicators_global_list",
        description = "List indicators of compromise published across all threat intelligence articles \
                       globally. Returns an OData collection of indicators aggregated from all research \
                       reports. Supports OData query parameters: $top (default 50, max 1000), $skip for \
                       offset pagination, $filter, $select, and $expand. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Global Article Indicators",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_article_indicators_global_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/threatIntelligence/articleIndicators", &odata)
            .await
    }

    // ============================================================
    // 3.4 TI Hosts - Core
    // ============================================================

    /// Get information about an internet host (domain or IP address).
    #[tool(
        name = "defender_ti_host_get",
        description = "Retrieve telemetry and infrastructure metadata for an internet host (domain name or \
                       IP address literal). Returns first and last observed timestamps, hosting provider \
                       details, autonomous system information, and network attributes. Input hostname must \
                       be a plain domain or IP; do not pass full URLs with protocols or paths. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "Get Host",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_get(
        &self,
        Parameters(params): Parameters<HostnameInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hosts/{}",
            validation::encode_path_segment(hostname)
        ))
        .await
    }

    /// Get reputation scoring for a host (classification, score, rules).
    #[tool(
        name = "defender_ti_host_reputation_get",
        description = "Retrieve reputation scoring and risk classification for an internet host (domain \
                       name or IP address literal). Returns classification status (malicious, suspicious, \
                       neutral, or unknown), computed numeric score (0-100), and triggering heuristic \
                       detection rules. Input hostname must be a plain domain or IP literal. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "Get Host Reputation",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_reputation_get(
        &self,
        Parameters(params): Parameters<HostnameInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hosts/{}/reputation",
            validation::encode_path_segment(hostname)
        ))
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Components
    // ============================================================

    /// List web components observed on a host (frameworks, CMS, server software).
    #[tool(
        name = "defender_ti_host_components_list",
        description = "List web components, application frameworks, content management systems, and server \
                       software observed running on an internet host. Returns an OData collection of \
                       component records. Input hostname must be a plain domain or IP literal. Supports \
                       OData query parameters: $top (default 50, max 1000), $skip for offset pagination, \
                       $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved \
                       for subsequent queries. Requires ThreatIntelligence.Read.All application permission \
                       and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Host Components",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_components_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/components",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    /// Get details of a specific host component by its ID.
    #[tool(
        name = "defender_ti_host_component_get",
        description = "Retrieve details for a specific host web component by its unique component \
                       identifier. Returns component category, detected product name, version details, and \
                       observation timestamps. Pass the opaque component_id copied verbatim from host \
                       component listing; do not manually base64-encode. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "Get Host Component",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_component_get(
        &self,
        Parameters(params): Parameters<HostComponentIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let component_id = validation::validate_required_id(&params.component_id, "component_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hostComponents/{}",
            validation::encode_path_segment(component_id)
        ))
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Cookies
    // ============================================================

    /// List cookies observed on a host.
    #[tool(
        name = "defender_ti_host_cookies_list",
        description = "List HTTP cookies observed on an internet host during web crawling and \
                       infrastructure scanning. Returns an OData collection of cookie records including \
                       cookie names, domains, and observation timestamps. Input hostname must be a plain \
                       domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), \
                       $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Host Cookies",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_cookies_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/cookies",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    /// Get details of a specific host cookie by its ID.
    #[tool(
        name = "defender_ti_host_cookie_get",
        description = "Retrieve details for a specific host HTTP cookie record by its unique cookie \
                       identifier. Returns cookie name, domain attribute, first and last seen timestamps, \
                       and associated host context. Pass the opaque cookie_id copied verbatim from host \
                       cookie listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All \
                       application permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Host Cookie",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_cookie_get(
        &self,
        Parameters(params): Parameters<HostCookieIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let cookie_id = validation::validate_required_id(&params.cookie_id, "cookie_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hostCookies/{}",
            validation::encode_path_segment(cookie_id)
        ))
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Ports
    // ============================================================

    /// List open ports observed on a host.
    #[tool(
        name = "defender_ti_host_ports_list",
        description = "List open network ports and running services observed on an internet host. Returns \
                       an OData collection of port records including port numbers, transport protocols, \
                       service banners, and scan timestamps. Input hostname must be a plain domain or IP \
                       literal. Supports OData query parameters: $top (default 50, max 1000), $skip for \
                       offset pagination, $filter, $select, and $expand. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Host Ports",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_ports_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/ports",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    /// Get details of a specific host port by its ID.
    #[tool(
        name = "defender_ti_host_port_get",
        description = "Retrieve details for a specific open port observation on a host by its unique port \
                       identifier. Returns port number, protocol, service banner strings, and detection \
                       timestamps. Pass the opaque port_id copied verbatim from host port listing; do not \
                       manually base64-encode. Requires ThreatIntelligence.Read.All application permission \
                       and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Host Port",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_port_get(
        &self,
        Parameters(params): Parameters<HostPortIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let port_id = validation::validate_required_id(&params.port_id, "port_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hostPorts/{}",
            validation::encode_path_segment(port_id)
        ))
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Trackers
    // ============================================================

    /// List tracking codes/scripts observed on a host (analytics, ad trackers).
    #[tool(
        name = "defender_ti_host_trackers_list",
        description = "List web tracking identifiers, ad codes, and analytics scripts (e.g., Google \
                       Analytics IDs, New Relic tags, social widgets) observed on an internet host. Returns \
                       an OData collection of tracker records useful for infrastructure correlation. Input \
                       hostname must be a plain domain or IP literal. Supports OData query parameters: $top \
                       (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. \
                       Single page returned; raw @odata.nextLink is preserved for subsequent queries. \
                       Requires ThreatIntelligence.Read.All application permission and an active Microsoft \
                       Defender Threat Intelligence license.",
        annotations(
            title = "List Host Trackers",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_trackers_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/trackers",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    /// Get details of a specific host tracker by its ID.
    #[tool(
        name = "defender_ti_host_tracker_get",
        description = "Retrieve details for a specific web tracker observation on a host by its unique \
                       tracker identifier. Returns tracker type, tracking identifier value, and observation \
                       window. Pass the opaque tracker_id copied verbatim from host tracker listing; do not \
                       manually base64-encode. Requires ThreatIntelligence.Read.All application permission \
                       and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Host Tracker",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_tracker_get(
        &self,
        Parameters(params): Parameters<HostTrackerIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let tracker_id = validation::validate_required_id(&params.tracker_id, "tracker_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hostTrackers/{}",
            validation::encode_path_segment(tracker_id)
        ))
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Subdomains
    // ============================================================

    /// List subdomains observed for a host.
    #[tool(
        name = "defender_ti_host_subdomains_list",
        description = "List known subdomains observed for a specific domain name. Returns an OData \
                       collection of subdomain host records discovered across passive DNS and web crawling. \
                       Input hostname must be a valid domain name (e.g., contoso.com). Supports OData query \
                       parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, \
                       $select, and $expand. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires ThreatIntelligence.Read.All application permission and \
                       an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Host Subdomains",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_subdomains_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/subdomains",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - SSL Certificates
    // ============================================================

    /// List SSL certificates observed on a host.
    #[tool(
        name = "defender_ti_host_ssl_certs_list",
        description = "List X.509 SSL/TLS certificates observed on an internet host. Returns an OData \
                       collection of certificate records with thumbprints, subject alternative names, \
                       validity dates, and issuer details. Input hostname must be a plain domain or IP \
                       literal. Supports OData query parameters: $top (default 50, max 1000), $skip for \
                       offset pagination, $filter, $select, $expand, and $count. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Host SSL Certificates",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_ssl_certs_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/sslCertificates",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Whois
    // ============================================================

    /// Get the current WHOIS record for a host.
    #[tool(
        name = "defender_ti_host_whois_get",
        description = "Retrieve the current active WHOIS domain registration record for a specific host. \
                       Returns registrar name, registrant contact details, administrative contacts, \
                       authoritative name servers, and expiration dates. Input hostname must be a plain \
                       domain name (e.g., contoso.com). Requires ThreatIntelligence.Read.All application \
                       permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Host Whois",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_whois_get(
        &self,
        Parameters(params): Parameters<HostnameInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hosts/{}/whois",
            validation::encode_path_segment(hostname)
        ))
        .await
    }

    /// List historical WHOIS records for a host.
    #[tool(
        name = "defender_ti_host_whois_history_list",
        description = "List historical WHOIS registration snapshots for an internet domain host. Returns an \
                       OData collection of historical WHOIS records reflecting past ownership, contact \
                       changes, and registrar transfers. Input hostname must be a plain domain name. \
                       Supports OData query parameters: $top (default 50, max 1000), $skip for offset \
                       pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink \
                       is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application \
                       permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Host Whois History",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_whois_history_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/whoisHistoryRecords",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Host Pairs
    // ============================================================

    /// List host pairs (connections) where this host is either parent or child.
    #[tool(
        name = "defender_ti_host_pairs_list",
        description = "List host pairing relationships where the specified host acts as either the parent \
                       (initiating connection/referral) or child (target resource) in web infrastructure \
                       mappings. Returns an OData collection of host pair entities. Input hostname must be a \
                       plain domain or IP literal. Supports OData query parameters: $top (default 50, max \
                       1000), $skip for offset pagination, $filter, $select, and $expand. Single page \
                       returned; raw @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Host Pairs",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_pairs_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/hostPairs",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    /// Get a specific host pair relationship by its ID.
    #[tool(
        name = "defender_ti_host_pair_get",
        description = "Retrieve details of a specific host pair connection by its unique relationship \
                       identifier. Returns parent host, child host, link type (e.g., script, link, iframe), \
                       and observation timestamps. Pass the opaque pair_id copied verbatim from host pair \
                       listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All \
                       application permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Host Pair",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_pair_get(
        &self,
        Parameters(params): Parameters<HostPairIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let pair_id = validation::validate_required_id(&params.pair_id, "pair_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/hostPairs/{}",
            validation::encode_path_segment(pair_id)
        ))
        .await
    }

    /// List host pairs where this host is the parent.
    #[tool(
        name = "defender_ti_host_child_pairs_list",
        description = "List child host connections where the specified host is the parent initiating or \
                       referencing external resources. Returns an OData collection of child host pair \
                       records. Input hostname must be a plain domain or IP literal. Supports OData query \
                       parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, \
                       $select, and $expand. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires ThreatIntelligence.Read.All application permission and \
                       an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Child Host Pairs",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_child_pairs_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/childHostPairs",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    /// List host pairs where this host is the child.
    #[tool(
        name = "defender_ti_host_parent_pairs_list",
        description = "List parent host connections where the specified host is referenced or targeted by \
                       external parent resources. Returns an OData collection of parent host pair records. \
                       Input hostname must be a plain domain or IP literal. Supports OData query parameters: \
                       $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and \
                       $expand. Single page returned; raw @odata.nextLink is preserved for subsequent \
                       queries. Requires ThreatIntelligence.Read.All application permission and an active \
                       Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Parent Host Pairs",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_parent_pairs_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/parentHostPairs",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 3.4 TI Hosts - Passive DNS
    // ============================================================

    /// List passive DNS records for a host (forward lookup).
    #[tool(
        name = "defender_ti_host_passive_dns_list",
        description = "List forward passive DNS resolution history for a domain host, mapping the domain to \
                       observed IP addresses over time. Returns an OData collection of resolution records \
                       with first/last seen timestamps and record types (A, AAAA, CNAME). Input hostname \
                       must be a valid domain name. Supports OData query parameters: $top (default 50, max \
                       1000), $skip for offset pagination, $filter, $select, and $expand. Single page \
                       returned; raw @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List Host Passive DNS",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_passive_dns_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/passiveDns",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    /// List reverse passive DNS records for a host (IP-to-domain mapping).
    #[tool(
        name = "defender_ti_host_passive_dns_reverse_list",
        description = "List reverse passive DNS resolution history for an IP address host, mapping the IP \
                       address to domains historically resolved to it. Returns an OData collection of \
                       resolution records. Input hostname must be a valid IP address literal. Supports OData \
                       query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, \
                       $select, and $expand. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires ThreatIntelligence.Read.All application permission and \
                       an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Host Reverse Passive DNS",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_host_passive_dns_reverse_list(
        &self,
        Parameters(params): Parameters<HostnameODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let hostname = validation::validate_hostname(&params.hostname)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_hostname_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/hosts/{}/passiveDnsReverse",
                validation::encode_path_segment(hostname)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 3.5 TI SSL Certificates
    // ============================================================

    /// List SSL certificates in the threat intelligence database.
    #[tool(
        name = "defender_ti_ssl_certs_list",
        description = "List SSL/TLS certificates cataloged in the Microsoft Defender Threat Intelligence \
                       database. Returns an OData collection of certificate metadata objects including \
                       serial numbers, SHA1/SHA256 thumbprints, subject/issuer distinguished names, and \
                       validity dates. Supports OData query parameters: $top (default 50, max 1000), $skip \
                       for offset pagination, $filter, $select, and $expand. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List SSL Certificates",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_ssl_certs_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/threatIntelligence/sslCertificates", &odata)
            .await
    }

    /// Get a specific SSL certificate by its ID.
    #[tool(
        name = "defender_ti_ssl_cert_get",
        description = "Retrieve full details of a specific SSL/TLS certificate by its certificate \
                       identifier. Returns complete X.509 certificate attributes, public key algorithms, \
                       subject alternative names, and certificate transparency metadata. Pass the \
                       certificate_id (opaque base64 string, e.g., MDJjODMz...) copied verbatim from \
                       certificate listing; do not decode or re-encode. Requires ThreatIntelligence.Read.All \
                       application permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get SSL Certificate",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_ssl_cert_get(
        &self,
        Parameters(params): Parameters<SslCertIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let certificate_id =
            validation::validate_required_id(&params.certificate_id, "certificate_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/sslCertificates/{}",
            validation::encode_path_segment(certificate_id)
        ))
        .await
    }

    /// List hosts associated with a given SSL certificate.
    #[tool(
        name = "defender_ti_ssl_cert_related_hosts_list",
        description = "List internet hosts and domains observed presenting a specific SSL/TLS certificate. \
                       Returns an OData collection of related host entities. Pass the certificate_id (opaque \
                       base64 string copied verbatim). Supports OData query parameters: $top (default 50, \
                       max 1000), $skip for offset pagination, and $count. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires \
                       ThreatIntelligence.Read.All application permission and an active Microsoft Defender \
                       Threat Intelligence license.",
        annotations(
            title = "List SSL Certificate Related Hosts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_ssl_cert_related_hosts_list(
        &self,
        Parameters(params): Parameters<CertRelatedHostsInput>,
    ) -> Result<CallToolResult, McpError> {
        let certificate_id =
            validation::validate_required_id(&params.certificate_id, "certificate_id")?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_cert_related_odata(&params);
        self.odata_get(
            &format!(
                "/security/threatIntelligence/sslCertificates/{}/relatedHosts",
                validation::encode_path_segment(certificate_id)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 3.6 TI Whois Records
    // ============================================================

    /// List WHOIS records in the threat intelligence database.
    #[tool(
        name = "defender_ti_whois_records_list",
        description = "List domain WHOIS registration records cataloged across Microsoft Defender Threat \
                       Intelligence. Returns an OData collection of WHOIS record summaries. Supports OData \
                       query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, \
                       $select, and $expand. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires ThreatIntelligence.Read.All application permission and \
                       an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Whois Records",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_whois_records_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/threatIntelligence/whoisRecords", &odata)
            .await
    }

    /// Get a specific WHOIS record by its ID.
    #[tool(
        name = "defender_ti_whois_record_get",
        description = "Retrieve a specific domain WHOIS registration record by its record identifier. \
                       Returns comprehensive registration details, contact blocks, raw registrar responses, \
                       and nameservers. Pass the opaque record_id (typically a base64 string copied verbatim \
                       from listing results); do not decode or re-encode. For active domain lookups by \
                       hostname, use defender_ti_host_whois_get. Requires ThreatIntelligence.Read.All \
                       application permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Whois Record",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_whois_record_get(
        &self,
        Parameters(params): Parameters<WhoisRecordIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let record_id = validation::validate_required_id(&params.record_id, "record_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/whoisRecords/{}",
            validation::encode_path_segment(record_id)
        ))
        .await
    }

    // ============================================================
    // 3.7 TI Passive DNS
    // ============================================================

    /// Get a specific passive DNS record by its ID.
    #[tool(
        name = "defender_ti_passive_dns_get",
        description = "Retrieve a specific passive DNS record by its unique record identifier. Returns \
                       domain, IP address mapping, record type, and first/last observed resolution \
                       timestamps. Pass the opaque record_id copied verbatim from listing results; do not \
                       manually base64-encode. For host-based resolution queries, use \
                       defender_ti_host_passive_dns_list. Requires ThreatIntelligence.Read.All application \
                       permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Passive DNS Record",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_passive_dns_get(
        &self,
        Parameters(params): Parameters<PassiveDnsRecordIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let record_id = validation::validate_required_id(&params.record_id, "record_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/passiveDnsRecords/{}",
            validation::encode_path_segment(record_id)
        ))
        .await
    }

    // ============================================================
    // 3.8 TI Vulnerabilities
    // ============================================================

    /// Get details of a specific vulnerability/CVE.
    #[tool(
        name = "defender_ti_vulnerability_get",
        description = "Retrieve threat intelligence details for a specific Common Vulnerabilities and \
                       Exposures (CVE) identifier. Returns vulnerability description, CVSS base score, \
                       severity rating, active exploit status in the wild, remediation guidance, related \
                       intelligence articles, and dark web discussion chatter. CVE ID must follow standard \
                       format CVE-YYYY-NNNN+ (e.g., CVE-2021-44228). Requires ThreatIntelligence.Read.All \
                       application permission and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Vulnerability",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_vulnerability_get(
        &self,
        Parameters(params): Parameters<VulnerabilityIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let vulnerability_id = validation::validate_cve_id(&params.vulnerability_id)?;
        self.simple_get(&format!(
            "/security/threatIntelligence/vulnerabilities/{}",
            validation::encode_path_segment(vulnerability_id)
        ))
        .await
    }

    /// List software/hardware components affected by a specific vulnerability/CVE.
    #[tool(
        name = "defender_ti_vulnerability_components_list",
        description = "List software and hardware components affected by a specific CVE identifier \
                       according to Microsoft Defender Threat Intelligence. Returns an OData collection of \
                       affected component objects. Pass a valid CVE ID (e.g., CVE-2021-44228). Supports \
                       OData query parameters: $top (default 50, max 1000), $skip for offset pagination, and \
                       $select. Single page returned; raw @odata.nextLink is preserved for subsequent \
                       queries. Requires ThreatIntelligence.Read.All application permission and an active \
                       Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "List Vulnerability Components",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_vulnerability_components_list(
        &self,
        Parameters(params): Parameters<VulnerabilityODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let vulnerability_id = validation::validate_cve_id(&params.vulnerability_id)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = ODataParams {
            top: Some(params.top),
            skip: Some(params.skip),
            select: params.select.clone(),
            filter: None,
            expand: None,
            search: None,
            count: None,
        };
        self.odata_get(
            &format!(
                "/security/threatIntelligence/vulnerabilities/{}/components",
                validation::encode_path_segment(vulnerability_id)
            ),
            &odata,
        )
        .await
    }

    /// Get a specific vulnerability component by CVE and component ID.
    #[tool(
        name = "defender_ti_vulnerability_component_get",
        description = "Retrieve details for a specific component affected by a CVE vulnerability. Returns \
                       component identification, vendor, product version ranges, and platform context. Pass \
                       a valid CVE ID (e.g., CVE-2021-44228) and the opaque component_id copied verbatim \
                       from component listing. Requires ThreatIntelligence.Read.All application permission \
                       and an active Microsoft Defender Threat Intelligence license.",
        annotations(
            title = "Get Vulnerability Component",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_ti_vulnerability_component_get(
        &self,
        Parameters(params): Parameters<VulnComponentGetInput>,
    ) -> Result<CallToolResult, McpError> {
        let vulnerability_id = validation::validate_cve_id(&params.vulnerability_id)?;
        let component_id = validation::validate_required_id(&params.component_id, "component_id")?;
        self.simple_get(&format!(
            "/security/threatIntelligence/vulnerabilities/{}/components/{}",
            validation::encode_path_segment(vulnerability_id),
            validation::encode_path_segment(component_id),
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Machine/Device Inventory (6 tools)
    // ============================================================

    /// List all machines/devices in the organization with OData filtering.
    #[tool(
        name = "defender_endpoint_machine_list",
        description = "List onboarded endpoint machines and devices enrolled in Microsoft Defender for \
                       Endpoint. Returns an OData collection of machine entities with health status, risk \
                       levels, OS platforms, IP addresses, and device tags. Supports OData query parameters: \
                       $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page \
                       returned; raw @odata.nextLink is preserved for subsequent queries. Requires \
                       Machine.Read.All application permission.",
        annotations(
            title = "List Endpoint Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/machines", &odata).await
    }

    /// Get detailed information about a specific machine by ID.
    #[tool(
        name = "defender_endpoint_machine_get",
        description = "Retrieve detailed hardware, OS, network, and security configuration for a specific \
                       device by its Defender machine ID. Returns computer name, domain, OS version, agent \
                       health, risk score, exposure level, and first/last seen timestamps. Pass the \
                       machine_id (usually a 40-character hexadecimal Defender device ID; not an Azure AD \
                       device ID or UUID). Requires Machine.Read.All application permission.",
        annotations(
            title = "Get Endpoint Machine",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_get(
        &self,
        Parameters(params): Parameters<MachineIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let machine_id = validation::validate_required_id(&params.machine_id, "machine_id")?;
        self.ep_simple_get(&format!(
            "/api/machines/{}",
            validation::encode_path_segment(machine_id)
        ))
        .await
    }

    /// Get the list of users logged on to a specific machine.
    #[tool(
        name = "defender_endpoint_machine_logged_on_users",
        description = "List user accounts observed logged on to a specific endpoint device. Returns an \
                       OData object with a value array of user records, including accountName, accountDomain, \
                       firstSeen, lastSeen, and logonTypes; these are not individual logon sessions. Pass the \
                       Defender machine_id. Requires User.Read.All application permission.",
        annotations(
            title = "Get Machine Logged On Users",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_logged_on_users(
        &self,
        Parameters(params): Parameters<MachineIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let machine_id = validation::validate_required_id(&params.machine_id, "machine_id")?;
        self.ep_simple_get(&format!(
            "/api/machines/{}/logonusers",
            validation::encode_path_segment(machine_id)
        ))
        .await
    }

    /// Find machines by tag name with optional prefix matching.
    #[tool(
        name = "defender_endpoint_machine_find_by_tag",
        description = "Search for endpoint devices by administrative device tag. Returns an OData object \
                       with a value array of matching machines. Pass the tag_name (case-insensitive string; slashes and \
                       dots are preserved in the query) and optional use_starts_with boolean (true for \
                       prefix matching, false for exact match). Requires Machine.Read.All application \
                       permission.",
        annotations(
            title = "Find Endpoint Machines by Tag",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_find_by_tag(
        &self,
        Parameters(params): Parameters<FindByTagInput>,
    ) -> Result<CallToolResult, McpError> {
        let tag_name = validation::validate_tag_name(&params.tag_name)?;
        let usw = if params.use_starts_with {
            "true"
        } else {
            "false"
        };
        let q = vec![
            ("tag", tag_name.to_owned()),
            ("useStartsWithFilter", usw.to_string()),
        ];
        match self
            .endpoint
            .endpoint_get("/api/machines/findByTag", &q)
            .await
        {
            Ok(v) => Ok(CallToolResult::structured(v)),
            Err(e) => Ok(e),
        }
    }

    /// List all installed software on a specific machine.
    #[tool(
        name = "defender_endpoint_machine_list_software",
        description = "List software applications, versions, and vendors installed on a specific endpoint \
                       device. Returns an OData object with a value array of installed software entities for vulnerability and \
                       compliance analysis. Pass the 40-hex Defender machine_id. Requires Software.Read.All \
                       application permission.",
        annotations(
            title = "List Machine Software",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_list_software(
        &self,
        Parameters(params): Parameters<MachineIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let machine_id = validation::validate_required_id(&params.machine_id, "machine_id")?;
        self.ep_simple_get(&format!(
            "/api/machines/{}/software",
            validation::encode_path_segment(machine_id)
        ))
        .await
    }

    /// Get security recommendations for a specific machine.
    #[tool(
        name = "defender_endpoint_machine_security_recommendations",
        description = "List security recommendations and configuration improvement actions applicable to a \
                       specific endpoint device. Returns an OData object with a value array of recommendations including \
                       remediation steps, threat context, and risk impact. Pass the 40-hex Defender \
                       machine_id. Requires SecurityRecommendation.Read.All application permission.",
        annotations(
            title = "Get Machine Security Recommendations",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_security_recommendations(
        &self,
        Parameters(params): Parameters<MachineIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let machine_id = validation::validate_required_id(&params.machine_id, "machine_id")?;
        self.ep_simple_get(&format!(
            "/api/machines/{}/recommendations",
            validation::encode_path_segment(machine_id)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Software Inventory (6 tools)
    // ============================================================

    /// List all software inventory across the organization.
    #[tool(
        name = "defender_endpoint_software_list",
        description = "List software inventory items discovered across all onboarded devices in the \
                       organization. Returns an OData collection of software products with vendor names, \
                       product identifiers, and weakness counts. Supports OData query parameters: $filter, \
                       $top (default 50, max 10000), and $skip for offset pagination. Single page returned; \
                       raw @odata.nextLink is preserved for subsequent queries. Requires Software.Read.All \
                       application permission.",
        annotations(
            title = "List Endpoint Software",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_software_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/Software", &odata).await
    }

    /// Get detailed information about a specific software by ID.
    #[tool(
        name = "defender_endpoint_software_get",
        description = "Retrieve detailed inventory and vulnerability summary for a specific software \
                       product. Returns product name, vendor, installed device count, and overall exposure \
                       metrics. Pass the software_id (e.g., microsoft-_-internet_explorer). Requires \
                       Software.Read.All application permission.",
        annotations(
            title = "Get Endpoint Software",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_software_get(
        &self,
        Parameters(params): Parameters<SoftwareIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let software_id = validation::validate_required_id(&params.software_id, "software_id")?;
        self.ep_simple_get(&format!(
            "/api/Software/{}",
            validation::encode_path_segment(software_id)
        ))
        .await
    }

    /// List all machines that have a specific software installed.
    #[tool(
        name = "defender_endpoint_software_machines",
        description = "List endpoint devices that currently have a specific software product installed. \
                       Returns an OData collection of machine reference entities. Pass the software_id. \
                       Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for \
                       offset pagination. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires Machine.Read.All or Software.Read.All application \
                       permission.",
        annotations(
            title = "List Software Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_software_machines(
        &self,
        Parameters(params): Parameters<SoftwareODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let software_id = validation::validate_required_id(&params.software_id, "software_id")?;
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get(
            &format!(
                "/api/Software/{}/machineReferences",
                validation::encode_path_segment(software_id)
            ),
            &odata,
        )
        .await
    }

    /// List all vulnerabilities associated with a specific software.
    #[tool(
        name = "defender_endpoint_software_vulnerabilities",
        description = "List known Common Vulnerabilities and Exposures (CVEs) associated with a specific \
                       software product across the organization. Returns an OData object with a value array of vulnerability summary \
                       entities with severity and CVSS scores. Pass the software_id. Requires \
                       Vulnerability.Read.All application permission.",
        annotations(
            title = "List Software Vulnerabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_software_vulnerabilities(
        &self,
        Parameters(params): Parameters<SoftwareIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let software_id = validation::validate_required_id(&params.software_id, "software_id")?;
        self.ep_simple_get(&format!(
            "/api/Software/{}/vulnerabilities",
            validation::encode_path_segment(software_id)
        ))
        .await
    }

    /// List missing security updates (KBs) for a specific software.
    #[tool(
        name = "defender_endpoint_software_missing_kbs",
        description = "List missing Microsoft security updates (KB patches) required for a specific \
                       software product installed on organizational endpoints. Returns an OData object with a value array of missing \
                       update entities. Pass the software_id. Requires Software.Read.All application \
                       permission.",
        annotations(
            title = "List Software Missing KBs",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_software_missing_kbs(
        &self,
        Parameters(params): Parameters<SoftwareIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let software_id = validation::validate_required_id(&params.software_id, "software_id")?;
        self.ep_simple_get(&format!(
            "/api/Software/{}/getmissingkbs",
            validation::encode_path_segment(software_id)
        ))
        .await
    }

    /// Get version distribution statistics for a specific software.
    #[tool(
        name = "defender_endpoint_software_distribution",
        description = "Retrieve version distribution statistics for a specific software product across the \
                       organizational device fleet. Returns raw JSON containing software version records with \
                       deployed machine counts. Pass the software_id. Requires Software.Read.All application \
                       permission.",
        annotations(
            title = "Get Software Distribution",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_software_distribution(
        &self,
        Parameters(params): Parameters<SoftwareIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let software_id = validation::validate_required_id(&params.software_id, "software_id")?;
        self.ep_simple_get(&format!(
            "/api/Software/{}/distributions",
            validation::encode_path_segment(software_id)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Vulnerability Management (4 tools)
    // ============================================================

    /// List all vulnerabilities affecting the organization.
    #[tool(
        name = "defender_endpoint_vulnerability_list",
        description = "List all vulnerabilities affecting software installed across the organization \
                       according to Defender Vulnerability Management. Returns an OData collection of CVE \
                       vulnerability entities with CVSS scores, exploitability tags, and severity ratings. \
                       Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for \
                       offset pagination. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires Vulnerability.Read.All application permission.",
        annotations(
            title = "List Endpoint Vulnerabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_vulnerability_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/vulnerabilities", &odata).await
    }

    /// Get a specific vulnerability by CVE identifier.
    #[tool(
        name = "defender_endpoint_vulnerability_get_by_cve",
        description = "Retrieve details for a specific vulnerability in organizational software by its CVE \
                       identifier. Returns vulnerability severity, CVSS scores, published dates, \
                       exploitability types, and affected software list. Pass a valid CVE ID (e.g., \
                       CVE-2021-44228). Requires Vulnerability.Read.All application permission.",
        annotations(
            title = "Get Endpoint Vulnerability by CVE",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_vulnerability_get_by_cve(
        &self,
        Parameters(params): Parameters<CveIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let cve_id = validation::validate_cve_id(&params.cve_id)?;
        self.ep_simple_get(&format!(
            "/api/vulnerabilities/{}",
            validation::encode_path_segment(cve_id)
        ))
        .await
    }

    /// List all machines exposed to a specific vulnerability.
    #[tool(
        name = "defender_endpoint_vulnerability_get_machines",
        description = "List endpoint devices exposed to a specific CVE vulnerability due to vulnerable \
                       software installations. Returns an OData collection of machine references. Pass a \
                       valid CVE ID (e.g., CVE-2021-44228). Supports OData query parameters: $filter, $top \
                       (default 50, max 10000), and $skip for offset pagination. Single page returned; raw \
                       @odata.nextLink is preserved for subsequent queries. Requires Machine.Read.All or \
                       Vulnerability.Read.All application permission.",
        annotations(
            title = "List Vulnerability Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_vulnerability_get_machines(
        &self,
        Parameters(params): Parameters<CveODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let cve_id = validation::validate_cve_id(&params.cve_id)?;
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get(
            &format!(
                "/api/vulnerabilities/{}/machineReferences",
                validation::encode_path_segment(cve_id)
            ),
            &odata,
        )
        .await
    }

    /// List all vulnerability-to-machine-to-software mappings.
    #[tool(
        name = "defender_endpoint_vulnerability_get_by_machine_software",
        description = "List all tripartite mappings between vulnerable software, specific CVEs, and exposed \
                       devices across the organization. Returns an OData collection of \
                       vulnerability-machine-software association records. Supports OData query parameters: \
                       $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page \
                       returned; raw @odata.nextLink is preserved for subsequent queries. Requires \
                       Vulnerability.Read.All application permission.",
        annotations(
            title = "List Vulnerabilities by Machine and Software",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_vulnerability_get_by_machine_software(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/vulnerabilities/machinesVulnerabilities", &odata)
            .await
    }

    // ============================================================
    // 4.x Endpoint — Security Recommendations (5 tools)
    // ============================================================

    /// List all security recommendations.
    #[tool(
        name = "defender_endpoint_recommendation_list",
        description = "List security recommendations from Microsoft Defender Vulnerability Management \
                       prioritizing risk reduction across endpoints. Returns an OData collection of security \
                       recommendation objects with remediation type, threat context, and exposure impact. \
                       Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for \
                       offset pagination. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires SecurityRecommendation.Read.All application permission.",
        annotations(
            title = "List Security Recommendations",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_recommendation_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/recommendations", &odata).await
    }

    /// Get a specific security recommendation by ID.
    #[tool(
        name = "defender_endpoint_recommendation_get",
        description = "Retrieve details of a specific security recommendation by its recommendation \
                       identifier. Returns full recommendation metadata, remediation instructions, affected \
                       product information, and risk score impact. Pass the recommendation_id (e.g., \
                       va-_-google-_-chrome). Requires SecurityRecommendation.Read.All application \
                       permission.",
        annotations(
            title = "Get Security Recommendation",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_recommendation_get(
        &self,
        Parameters(params): Parameters<RecommendationIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let recommendation_id =
            validation::validate_required_id(&params.recommendation_id, "recommendation_id")?;
        self.ep_simple_get(&format!(
            "/api/recommendations/{}",
            validation::encode_path_segment(recommendation_id)
        ))
        .await
    }

    /// List all machines associated with a specific security recommendation.
    #[tool(
        name = "defender_endpoint_recommendation_machines",
        description = "List endpoint devices where a specific security recommendation is currently \
                       applicable and unresolved. Returns an OData object with a value array of machine references. Pass the \
                       recommendation_id. Requires SecurityRecommendation.Read.All \
                       application permission.",
        annotations(
            title = "List Recommendation Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_recommendation_machines(
        &self,
        Parameters(params): Parameters<RecommendationIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let recommendation_id =
            validation::validate_required_id(&params.recommendation_id, "recommendation_id")?;
        self.ep_simple_get(&format!(
            "/api/recommendations/{}/machineReferences",
            validation::encode_path_segment(recommendation_id)
        ))
        .await
    }

    /// List vulnerabilities associated with a specific recommendation.
    #[tool(
        name = "defender_endpoint_recommendation_vulnerabilities",
        description = "List CVE vulnerabilities addressed and remediated by implementing a specific \
                       security recommendation. Returns an OData object with a value array of related CVE records. Pass the \
                       recommendation_id. Requires Vulnerability.Read.All \
                       application permission.",
        annotations(
            title = "List Recommendation Vulnerabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_recommendation_vulnerabilities(
        &self,
        Parameters(params): Parameters<RecommendationIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let recommendation_id =
            validation::validate_required_id(&params.recommendation_id, "recommendation_id")?;
        self.ep_simple_get(&format!(
            "/api/recommendations/{}/vulnerabilities",
            validation::encode_path_segment(recommendation_id)
        ))
        .await
    }

    /// List software inventory entries associated with a specific recommendation.
    #[tool(
        name = "defender_endpoint_recommendation_by_software",
        description = "List software applications associated with a specific security recommendation. \
                       Returns an OData object with a value array of related software products. Pass the recommendation_id. \
                       Requires Software.Read.All application permission.",
        annotations(
            title = "List Recommendation Software",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_recommendation_by_software(
        &self,
        Parameters(params): Parameters<RecommendationIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let recommendation_id =
            validation::validate_required_id(&params.recommendation_id, "recommendation_id")?;
        self.ep_simple_get(&format!(
            "/api/recommendations/{}/software",
            validation::encode_path_segment(recommendation_id)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Remediation Tasks (3 tools)
    // ============================================================

    /// List all remediation tasks (read-only).
    #[tool(
        name = "defender_endpoint_remediation_list",
        description = "List remediation tasks and security mitigation activities created in Defender \
                       Vulnerability Management or integrated via Microsoft Intune. Returns an OData \
                       collection of remediation task summaries with status, priority, and progress metrics. \
                       Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for \
                       offset pagination. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires RemediationTasks.Read.All application permission.",
        annotations(
            title = "List Remediation Tasks",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_remediation_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/remediationTasks", &odata).await
    }

    /// Get a specific remediation task by ID.
    #[tool(
        name = "defender_endpoint_remediation_get",
        description = "Retrieve details and execution status for a specific remediation task by its task \
                       identifier. Returns task title, description, assigned technician/team, target \
                       completion date, and current lifecycle state. Pass the remediation_id (GUID string). \
                       Requires RemediationTasks.Read.All application permission.",
        annotations(
            title = "Get Remediation Task",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_remediation_get(
        &self,
        Parameters(params): Parameters<RemediationIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let remediation_id =
            validation::validate_required_id(&params.remediation_id, "remediation_id")?;
        self.ep_simple_get(&format!(
            "/api/remediationTasks/{}",
            validation::encode_path_segment(remediation_id)
        ))
        .await
    }

    /// List devices exposed to a specific remediation task.
    #[tool(
        name = "defender_endpoint_remediation_exposed_devices",
        description = "List endpoint devices targeted by or exposed to a specific remediation task. Returns \
                       an OData collection of machine references. Pass the remediation_id (GUID string). \
                       Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for \
                       offset pagination. Single page returned; raw @odata.nextLink is preserved for \
                       subsequent queries. Requires Machine.Read.All or RemediationTasks.Read.All \
                       application permission.",
        annotations(
            title = "List Remediation Exposed Devices",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_remediation_exposed_devices(
        &self,
        Parameters(params): Parameters<RemediationODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let remediation_id =
            validation::validate_required_id(&params.remediation_id, "remediation_id")?;
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get(
            &format!(
                "/api/remediationTasks/{}/machinereferences",
                validation::encode_path_segment(remediation_id)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 4.x Endpoint — Exposure Score (2 tools)
    // ============================================================

    /// Get the organization's overall exposure score.
    #[tool(
        name = "defender_endpoint_exposure_score",
        description = "Retrieve the organization's overall device exposure score from Microsoft Defender \
                       Vulnerability Management. Returns calculated exposure score reflecting cumulative \
                       organizational risk based on unresolved vulnerabilities, misconfigurations, and \
                       device criticality. Requires Score.Read.All application permission.",
        annotations(
            title = "Get Exposure Score",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_exposure_score(&self) -> Result<CallToolResult, McpError> {
        self.ep_simple_get("/api/exposureScore").await
    }

    /// Get exposure score broken down by machine group.
    #[tool(
        name = "defender_endpoint_exposure_score_by_machine_groups",
        description = "Retrieve exposure scores broken down across defined device groups (e.g., Tier 0 \
                       domain controllers, developer workstations, production servers). Returns raw JSON containing \
                       group exposure objects with group IDs, group names, and individual group exposure \
                       scores. Requires Score.Read.All application permission.",
        annotations(
            title = "Get Exposure Score by Machine Groups",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_exposure_score_by_machine_groups(
        &self,
    ) -> Result<CallToolResult, McpError> {
        self.ep_simple_get("/api/exposureScore/ByMachineGroups")
            .await
    }

    // ============================================================
    // 4.x Endpoint — Entity Enrichment: IP (2 tools)
    // ============================================================

    /// Get prevalence and first/last seen statistics for an IP address.
    #[tool(
        name = "defender_endpoint_ip_statistics",
        description = "Retrieve organizational prevalence and communication statistics for an external or \
                       internal IP address across all managed endpoints. Returns first and last observed \
                       communication timestamps, communicating device counts, and traffic summaries. Pass an \
                       IPv4 or IPv6 address and optional look_back_hours (default 720, representing 30 days; \
                       range 1–720). Requires Ip.Read.All application permission.",
        annotations(
            title = "Get IP Statistics",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_ip_statistics(
        &self,
        Parameters(params): Parameters<IpStatsInput>,
    ) -> Result<CallToolResult, McpError> {
        let ip_address = validation::validate_ip_address(&params.ip_address)?;
        validation::validate_look_back_hours(params.look_back_hours)?;
        let lh = params
            .look_back_hours
            .unwrap_or(crate::constants::DEFAULT_LOOK_BACK_HOURS);
        let q = vec![("lookBackHours", lh.to_string())];
        match self
            .endpoint
            .endpoint_get(
                &format!(
                    "/api/ips/{}/stats",
                    validation::encode_path_segment(ip_address)
                ),
                &q,
            )
            .await
        {
            Ok(v) => Ok(CallToolResult::structured(v)),
            Err(e) => Ok(e),
        }
    }

    /// Get alerts related to a specific IP address.
    #[tool(
        name = "defender_endpoint_ip_related_alerts",
        description = "List security alerts associated with network traffic to or from a specific IP \
                       address across all endpoints. Returns an OData object with a value array of related alerts. Pass an \
                       IPv4 or IPv6 address literal. Requires Alert.Read.All or Alert.ReadWrite.All \
                       application permission.",
        annotations(
            title = "Get IP Related Alerts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_ip_related_alerts(
        &self,
        Parameters(params): Parameters<IpInput>,
    ) -> Result<CallToolResult, McpError> {
        let ip_address = validation::validate_ip_address(&params.ip_address)?;
        self.ep_simple_get(&format!(
            "/api/ips/{}/alerts",
            validation::encode_path_segment(ip_address)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Entity Enrichment: Domain (3 tools)
    // ============================================================

    /// Get prevalence and first/last seen statistics for a domain.
    #[tool(
        name = "defender_endpoint_domain_statistics",
        description = "Retrieve organizational prevalence and communication statistics for a domain name \
                       across all managed endpoints. Returns first and last observed access timestamps and \
                       accessing device counts. Pass a domain name (e.g., example.com) and optional \
                       look_back_hours (default 720; range 1–720). Requires URL.Read.All application \
                       permission.",
        annotations(
            title = "Get Domain Statistics",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_domain_statistics(
        &self,
        Parameters(params): Parameters<DomainStatsInput>,
    ) -> Result<CallToolResult, McpError> {
        let domain_name = validation::validate_hostname(&params.domain_name)?;
        validation::validate_look_back_hours(params.look_back_hours)?;
        let lh = params
            .look_back_hours
            .unwrap_or(crate::constants::DEFAULT_LOOK_BACK_HOURS);
        let q = vec![("lookBackHours", lh.to_string())];
        match self
            .endpoint
            .endpoint_get(
                &format!(
                    "/api/domains/{}/stats",
                    validation::encode_path_segment(domain_name)
                ),
                &q,
            )
            .await
        {
            Ok(v) => Ok(CallToolResult::structured(v)),
            Err(e) => Ok(e),
        }
    }

    /// List machines that have communicated with a specific domain.
    #[tool(
        name = "defender_endpoint_domain_related_machines",
        description = "List endpoint devices that have communicated with or resolved a specific domain \
                       name. Returns an OData object with a value array of machines (capped at 500 devices per \
                       upstream API limits). Pass a domain name. Requires Machine.ReadWrite.All application \
                       permission.",
        annotations(
            title = "Get Domain Related Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_domain_related_machines(
        &self,
        Parameters(params): Parameters<DomainInput>,
    ) -> Result<CallToolResult, McpError> {
        let domain_name = validation::validate_hostname(&params.domain_name)?;
        self.ep_simple_get(&format!(
            "/api/domains/{}/machines",
            validation::encode_path_segment(domain_name)
        ))
        .await
    }

    /// Get alerts related to a specific domain.
    #[tool(
        name = "defender_endpoint_domain_related_alerts",
        description = "List security alerts associated with network traffic or browser navigation to a \
                       specific domain name. Returns an OData object with a value array of related alerts. Pass a domain name. \
                       Requires Alert.ReadWrite.All application permission.",
        annotations(
            title = "Get Domain Related Alerts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_domain_related_alerts(
        &self,
        Parameters(params): Parameters<DomainInput>,
    ) -> Result<CallToolResult, McpError> {
        let domain_name = validation::validate_hostname(&params.domain_name)?;
        self.ep_simple_get(&format!(
            "/api/domains/{}/alerts",
            validation::encode_path_segment(domain_name)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Entity Enrichment: File (4 tools)
    // ============================================================

    /// Get file information by file identifier (SHA1, SHA256, or MD5).
    #[tool(
        name = "defender_endpoint_file_get",
        description = "Retrieve file metadata and global reputation for a specific file hash from Defender \
                       for Endpoint intelligence. Returns file size, file names, signing details, publisher, \
                       and global prevalence. Pass a valid MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex) \
                       hash. Requires File.Read.All application permission.",
        annotations(
            title = "Get File Information",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_file_get(
        &self,
        Parameters(params): Parameters<FileIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let file_id = validation::validate_file_hash(&params.file_id)?;
        self.ep_simple_get(&format!(
            "/api/files/{}",
            validation::encode_path_segment(file_id)
        ))
        .await
    }

    /// Get organizational prevalence statistics for a file (by SHA1).
    #[tool(
        name = "defender_endpoint_file_statistics",
        description = "Retrieve organizational prevalence statistics for a file by its SHA1 hash across all \
                       endpoints. Returns first and last seen timestamps, executing device counts, and file \
                       open counts. Pass exactly a 40-character hexadecimal SHA1 hash and optional \
                       look_back_hours (default 720; range 1–720). Requires File.Read.All application \
                       permission.",
        annotations(
            title = "Get File Statistics",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_file_statistics(
        &self,
        Parameters(params): Parameters<FileStatsInput>,
    ) -> Result<CallToolResult, McpError> {
        let file_sha1 = validation::validate_sha1(&params.file_sha1)?;
        validation::validate_look_back_hours(params.look_back_hours)?;
        let lh = params
            .look_back_hours
            .unwrap_or(crate::constants::DEFAULT_LOOK_BACK_HOURS);
        let q = vec![("lookBackHours", lh.to_string())];
        match self
            .endpoint
            .endpoint_get(
                &format!(
                    "/api/files/{}/stats",
                    validation::encode_path_segment(file_sha1)
                ),
                &q,
            )
            .await
        {
            Ok(v) => Ok(CallToolResult::structured(v)),
            Err(e) => Ok(e),
        }
    }

    /// List machines where a specific file (by SHA1) has been observed.
    #[tool(
        name = "defender_endpoint_file_related_machines",
        description = "List endpoint devices where a specific file has been observed or executed. Returns \
                       an OData object with a value array of machine records. Pass exactly a 40-character hexadecimal SHA1 \
                       hash. Requires Machine.ReadWrite.All application permission.",
        annotations(
            title = "Get File Related Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_file_related_machines(
        &self,
        Parameters(params): Parameters<FileSha1Input>,
    ) -> Result<CallToolResult, McpError> {
        let file_sha1 = validation::validate_sha1(&params.file_sha1)?;
        self.ep_simple_get(&format!(
            "/api/files/{}/machines",
            validation::encode_path_segment(file_sha1)
        ))
        .await
    }

    /// Get alerts related to a specific file (by SHA1).
    #[tool(
        name = "defender_endpoint_file_related_alerts",
        description = "List security alerts triggered by or involving a specific file across the \
                       organization. Returns an OData object with a value array of related alerts. Pass exactly a 40-character \
                       hexadecimal SHA1 hash. Requires Alert.ReadWrite.All application permission.",
        annotations(
            title = "Get File Related Alerts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_file_related_alerts(
        &self,
        Parameters(params): Parameters<FileSha1Input>,
    ) -> Result<CallToolResult, McpError> {
        let file_sha1 = validation::validate_sha1(&params.file_sha1)?;
        self.ep_simple_get(&format!(
            "/api/files/{}/alerts",
            validation::encode_path_segment(file_sha1)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Entity Enrichment: User (2 tools)
    // ============================================================

    /// Get alerts related to a specific user.
    #[tool(
        name = "defender_endpoint_user_related_alerts",
        description = "List security alerts involving a specific user account on endpoint devices. Returns \
                       an OData object with a value array of related alerts. Pass the account username recognized by Defender \
                       for Endpoint (e.g., user1; do not pass a full UPN like user1@contoso.com, SID, or AAD \
                       GUID). Requires Alert.Read.All or Alert.ReadWrite.All application permission.",
        annotations(
            title = "Get User Related Alerts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_user_related_alerts(
        &self,
        Parameters(params): Parameters<UserIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let user_id = validation::validate_required_id(&params.user_id, "user_id")?;
        self.ep_simple_get(&format!(
            "/api/users/{}/alerts",
            validation::encode_path_segment(user_id)
        ))
        .await
    }

    /// List machines associated with a specific user.
    #[tool(
        name = "defender_endpoint_user_related_machines",
        description = "List endpoint devices where a specific user account has logged on. Returns an OData \
                       object with a value array of machines. Pass the account username (e.g., user1). Requires \
                       Machine.ReadWrite.All application permission.",
        annotations(
            title = "Get User Related Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_user_related_machines(
        &self,
        Parameters(params): Parameters<UserIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let user_id = validation::validate_required_id(&params.user_id, "user_id")?;
        self.ep_simple_get(&format!(
            "/api/users/{}/machines",
            validation::encode_path_segment(user_id)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Alerts (2 tools)
    // ============================================================

    /// List alerts from Defender for Endpoint.
    #[tool(
        name = "defender_endpoint_alert_list",
        description = "List security alerts generated by Defender for Endpoint detection engines (process \
                       injection, ransomware behavior, credential dumping, etc.). Returns an OData \
                       collection of alert entities with title, severity, category, status, and affected \
                       machine ID. Supports OData query parameters: $filter, $top (default 50, max 10000), \
                       and $skip for offset pagination. Single page returned; raw @odata.nextLink is \
                       preserved for subsequent queries. Requires Alert.Read.All application permission.",
        annotations(
            title = "List Endpoint Alerts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_alert_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/alerts", &odata).await
    }

    /// Get a specific endpoint alert by ID.
    #[tool(
        name = "defender_endpoint_alert_get",
        description = "Retrieve full details of a specific Defender for Endpoint alert by its alert \
                       identifier. Returns comprehensive alert properties, process execution trees, related \
                       file hashes, network connections, and remediation history. Pass the alert_id. \
                       Requires Alert.Read.All application permission.",
        annotations(
            title = "Get Endpoint Alert",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_alert_get(
        &self,
        Parameters(params): Parameters<AlertIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let alert_id = validation::validate_required_id(&params.alert_id, "alert_id")?;
        self.ep_simple_get(&format!(
            "/api/alerts/{}",
            validation::encode_path_segment(alert_id)
        ))
        .await
    }

    // ============================================================
    // 4.x Endpoint — Machine Actions (2 tools)
    // ============================================================

    /// List all machine actions (read-only status view).
    #[tool(
        name = "defender_endpoint_machine_action_list",
        description = "List remote response actions executed on endpoint machines (e.g., isolate machine, \
                       collect investigation package, run antivirus scan, initiate live response). Returns \
                       an OData collection of machine action status entities. Supports OData query \
                       parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. \
                       Single page returned; raw @odata.nextLink is preserved for subsequent queries. \
                       Requires Machine.Read.All application permission.",
        annotations(
            title = "List Machine Actions",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_action_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter, params.top, params.skip);
        self.ep_odata_get("/api/machineactions", &odata).await
    }

    /// Get the status of a specific machine action by ID.
    #[tool(
        name = "defender_endpoint_machine_action_get_status",
        description = "Retrieve the current execution status and result metadata for a specific remote \
                       machine action. Returns action status (Pending, InProgress, Succeeded, Failed, \
                       Cancelled), creation time, completion time, and error codes if applicable. Pass the \
                       action_id (GUID string). Requires Machine.Read.All application permission.",
        annotations(
            title = "Get Machine Action Status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_machine_action_get_status(
        &self,
        Parameters(params): Parameters<ActionIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let action_id = validation::validate_required_id(&params.action_id, "action_id")?;
        self.ep_simple_get(&format!(
            "/api/machineactions/{}",
            validation::encode_path_segment(action_id)
        ))
        .await
    }

    // ============================================================
    // 5.x XDR Alerts & Incidents (4 tools) — Graph
    // ============================================================

    /// List cross-product security alerts from Microsoft 365 Defender via Graph.
    #[tool(
        name = "defender_xdr_alert_list",
        description = "List cross-workload security alerts from Microsoft Defender XDR via Microsoft Graph \
                       API (/security/alerts_v2), aggregating signals across Endpoint, Office 365, Identity, \
                       and Cloud Apps. Returns an OData collection of Alert v2 objects with provider \
                       detection source, MITRE ATT&CK techniques, and evidence entities. Supports OData \
                       query parameters: $filter, $top (default 50, max 1000), $skip for offset pagination, \
                       and $count. Single page returned; raw @odata.nextLink is preserved for subsequent \
                       queries. Requires SecurityAlert.Read.All application permission.",
        annotations(
            title = "List XDR Alerts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_xdr_alert_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/alerts_v2", &odata).await
    }

    /// Get a specific XDR alert by ID.
    #[tool(
        name = "defender_xdr_alert_get",
        description = "Retrieve full details of a specific Microsoft Defender XDR Alert v2 by its alert \
                       identifier. Returns comprehensive multi-stage detection details, involved user \
                       accounts, affected devices, cloud assets, and full evidence arrays. Pass the alert_id \
                       (e.g., da637578995287051192_756343937). Requires SecurityAlert.Read.All application \
                       permission.",
        annotations(
            title = "Get XDR Alert",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_xdr_alert_get(
        &self,
        Parameters(params): Parameters<XdrAlertIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let alert_id = validation::validate_required_id(&params.alert_id, "alert_id")?;
        self.simple_get(&format!(
            "/security/alerts_v2/{}",
            validation::encode_path_segment(alert_id)
        ))
        .await
    }

    /// List security incidents from Microsoft 365 Defender via Graph.
    #[tool(
        name = "defender_xdr_incident_list",
        description = "List consolidated security incidents from Microsoft Defender XDR via Microsoft Graph \
                       API (/security/incidents), correlating related alerts and evidence across attack \
                       chains. Returns an OData collection of incident objects with incident names, \
                       severity, classification, assigned owners, and summary metrics. Supports OData query \
                       parameters: $filter, $top (default 50, max 1000), $skip for offset pagination, \
                       $expand (e.g., $expand=alerts), and $count. Single page returned; raw @odata.nextLink \
                       is preserved for subsequent queries. Requires SecurityIncident.Read.All application \
                       permission.",
        annotations(
            title = "List XDR Incidents",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_xdr_incident_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/incidents", &odata).await
    }

    /// Get a specific XDR incident by ID.
    #[tool(
        name = "defender_xdr_incident_get",
        description = "Retrieve full details of a specific Microsoft Defender XDR incident by its incident \
                       identifier. Returns full incident timeline, affected assets, determinations, tags, \
                       and optional expanded relationships. Pass the incident_id and optional expand \
                       parameter (e.g., expand='alerts' to include member alert objects). Requires \
                       SecurityIncident.Read.All application permission.",
        annotations(
            title = "Get XDR Incident",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_xdr_incident_get(
        &self,
        Parameters(params): Parameters<XdrIncidentIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let incident_id = validation::validate_required_id(&params.incident_id, "incident_id")?;
        let q: Vec<(&str, String)> = if let Some(ref expand) = params.expand {
            if !expand.is_empty() {
                vec![("$expand", expand.clone())]
            } else {
                vec![]
            }
        } else {
            vec![]
        };
        match self
            .client
            .graph_get(
                &format!(
                    "/security/incidents/{}",
                    validation::encode_path_segment(incident_id)
                ),
                &q,
            )
            .await
        {
            Ok(v) => Ok(CallToolResult::structured(v)),
            Err(e) => Ok(e),
        }
    }

    // ============================================================
    // 6.x Live Response (3 tools) — Gated
    // ============================================================

    /// Upload a file to the live response library.
    /// **Gated:** requires DEFENDER_ENABLE_LIVE_RESPONSE=true at server startup.
    #[tool(
        name = "defender_library_file_upload",
        description = "Upload a remediation script or binary tool to the Defender for Endpoint Live \
                       Response library via multipart/form-data. Uploaded files can subsequently be copied \
                       to or executed on live managed endpoints. Supports PowerShell (.ps1) on Windows and \
                       Shell (.sh) scripts on Linux/macOS. File content must be non-empty UTF-8 text up to \
                       20 MB (20,971,520 bytes). Setting override_if_exists=true is an irreversible \
                       destructive mutation that overwrites any existing file with the same name. Gated \
                       operation: requires server configuration DEFENDER_ENABLE_LIVE_RESPONSE=true and \
                       explicit human authorization. Requires Library.Manage application permission.",
        annotations(
            title = "Upload Live Response Library File",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn defender_library_file_upload(
        &self,
        Parameters(params): Parameters<LiveResponseLibraryUploadInput>,
    ) -> Result<CallToolResult, McpError> {
        if !self.live_response_enabled {
            return Ok(crate::error::tool_error(
                "Live Response is disabled. Set DEFENDER_ENABLE_LIVE_RESPONSE=true to enable.",
            ));
        }

        let file_name = validation::validate_file_name(&params.file_name)?;
        let description = validation::validate_description(&params.description)?;

        let content_bytes = params.file_content.as_bytes();
        if content_bytes.is_empty() {
            return Ok(crate::error::tool_error("file_content cannot be empty"));
        }
        if content_bytes.len() > crate::constants::MAX_LIBRARY_FILE_SIZE {
            return Ok(crate::error::tool_error(format!(
                "File size {} bytes exceeds maximum of {} bytes (20 MB)",
                content_bytes.len(),
                crate::constants::MAX_LIBRARY_FILE_SIZE
            )));
        }

        tracing::info!(
            file_name = %file_name,
            size = content_bytes.len(),
            "Library file upload initiated"
        );

        match self
            .endpoint
            .endpoint_multipart_upload(
                crate::constants::LIBRARY_FILES_PATH,
                file_name,
                content_bytes,
                description,
                params.parameters_description.as_deref(),
                params.override_if_exists,
            )
            .await
        {
            Ok(v) => Ok(CallToolResult::structured(v)),
            Err(e) => Ok(e),
        }
    }

    /// Run a sequence of live response commands on a specific machine.
    /// **Gated:** requires DEFENDER_ENABLE_LIVE_RESPONSE=true at server startup.
    #[tool(
        name = "defender_endpoint_live_response_run",
        description = "Initiate and execute a sequence of Live Response commands directly on a live managed \
                       endpoint device. Supported command types: PutFile (copies a library file to the \
                       device), RunScript (executes a library script with arguments), and GetFile (retrieves \
                       a file from the device). Up to 20 commands per session. comment is mandatory (minimum \
                       10 non-whitespace characters) for audit trail compliance. If the target machine is \
                       offline, the action will queue for up to 2 hours. Gated mutating operation: directly \
                       affects running systems; requires server configuration \
                       DEFENDER_ENABLE_LIVE_RESPONSE=true, optional DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS \
                       restriction, and explicit human authorization. Requires Machine.LiveResponse \
                       application permission.",
        annotations(
            title = "Run Live Response Session",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_live_response_run(
        &self,
        Parameters(params): Parameters<LiveResponseRunInput>,
    ) -> Result<CallToolResult, McpError> {
        if !self.live_response_enabled {
            return Ok(crate::error::tool_error(
                "Live Response is disabled. Set DEFENDER_ENABLE_LIVE_RESPONSE=true to enable.",
            ));
        }

        let machine_id = validation::validate_required_id(&params.machine_id, "machine_id")?;
        let comment = validation::validate_live_response_comment(&params.comment)?;
        validation::validate_live_response_commands(&params.commands)?;

        tracing::info!(
            machine_id = %machine_id,
            comment = %comment,
            command_count = params.commands.len(),
            "Live Response run initiated"
        );

        let body = json!({
            "Commands": params.commands,
            "Comment": comment,
        });

        match self
            .endpoint
            .endpoint_post(
                &format!(
                    "/api/machines/{}/runliveresponse",
                    validation::encode_path_segment(machine_id)
                ),
                &body,
            )
            .await
        {
            Ok(v) => Ok(CallToolResult::structured(v)),
            Err(e) => Ok(e),
        }
    }

    /// Retrieve the downloadable result link for a specific live response command.
    #[tool(
        name = "defender_endpoint_live_response_get_result",
        description = "Retrieve the temporary Shared Access Signature (SAS) download URL for the output or \
                       retrieved file generated by a specific Live Response command. Applicable to RunScript \
                       output logs and GetFile payload downloads (PutFile does not produce a download \
                       result). Pass the action_id returned from defender_endpoint_live_response_run and the \
                       zero-based command_index within the original session commands array (must be >= 0; \
                       negative indices are rejected locally). Gated operation: requires \
                       DEFENDER_ENABLE_LIVE_RESPONSE=true. Requires Machine.ReadWrite.All or \
                       Machine.LiveResponse application permission.",
        annotations(
            title = "Live Response Get Result",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn defender_endpoint_live_response_get_result(
        &self,
        Parameters(params): Parameters<LiveResponseResultInput>,
    ) -> Result<CallToolResult, McpError> {
        if !self.live_response_enabled {
            return Ok(crate::error::tool_error(
                "Live Response is disabled. Set DEFENDER_ENABLE_LIVE_RESPONSE=true to enable.",
            ));
        }

        let action_id = validation::validate_required_id(&params.action_id, "action_id")?;
        let idx = params.command_index;
        if idx < 0 {
            return Err(crate::error::invalid_params(format!(
                "command_index must be zero or greater, got {idx}"
            )));
        }

        self.ep_simple_get(&format!(
            "/api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})",
            validation::encode_path_segment(action_id),
            idx
        ))
        .await
    }
}

// ---------------------------------------------------------------------------
// Server handler
// ---------------------------------------------------------------------------

#[tool_handler(
    name = "microsoft-defender-mcp",
    version = "0.2.0",
    instructions = "Investigate Microsoft Defender through Microsoft Graph Security and Defender for Endpoint APIs. \
                    86 tools are read-only. defender_library_file_upload and defender_endpoint_live_response_run \
                    can change cloud library files or endpoint state: clients must obtain explicit human approval \
                    before invoking them. All three Live Response tools require DEFENDER_ENABLE_LIVE_RESPONSE=true \
                    at startup. DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS restricts commands in live_response_run \
                    only; it does not restrict library uploads or result-link retrieval. Tool results preserve \
                    upstream JSON; OData collections are objects with a value array and optional metadata, not \
                    flattened arrays. Pagination is not followed automatically. Grant only the application \
                    permissions documented for the chosen tool; some read-only APIs require legacy write-named \
                    scopes. HTTP transport has no bundled client authentication: use an authenticated, trusted \
                    boundary for remote access."
)]
impl ServerHandler for DefenderServer {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::{
        Json, Router,
        extract::{Query, Request},
        http::{StatusCode, header::CONTENT_TYPE},
        response::IntoResponse,
        routing::{get, post},
    };
    use serde_json::{Value, json};

    use crate::auth::TokenManager;
    use crate::client::{EndpointClient, GraphClient};

    struct TestServerGuard {
        pub base_url: String,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestServerGuard {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_test_server(app: Router) -> TestServerGuard {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback port");
        let addr = listener.local_addr().expect("local addr");
        let base_url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        TestServerGuard { base_url, handle }
    }

    fn create_test_server(base_url: &str, live_response_enabled: bool) -> DefenderServer {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("loopback reqwest client");
        let tm = TokenManager::for_test(http);
        let graph = GraphClient::for_test(tm.clone(), base_url.to_string());
        let endpoint = EndpointClient::for_test(tm, base_url.to_string());
        DefenderServer {
            client: graph,
            endpoint,
            live_response_enabled,
        }
    }

    #[tokio::test]
    async fn test_opaque_ssl_cert_id_percent_encoded_single_segment_prevents_injection() {
        const EXPECTED_SEGMENT: &str = "a%2Fb%2Bc%3D%3F%23%25%C3%A9";

        let app = Router::new().fallback(|req: Request| async move {
            let expected_path =
                format!("/security/threatIntelligence/sslCertificates/{EXPECTED_SEGMENT}");
            if req.uri().path() == expected_path && req.uri().query().is_none() {
                (StatusCode::OK, Json(json!({"id": "a/b+c=?#%é"})))
            } else {
                (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
            }
        });

        let guard = spawn_test_server(app).await;
        let server = create_test_server(&guard.base_url, false);

        let res = server
            .defender_ti_ssl_cert_get(Parameters(SslCertIdInput {
                certificate_id: "   a/b+c=?#%é   ".to_string(),
            }))
            .await
            .expect("ssl cert get succeeded");

        let val = res.structured_content.as_ref().expect("structured content");
        assert_eq!(val["id"], "a/b+c=?#%é");
    }

    #[tokio::test]
    async fn test_odata_list_count_parameter_deserialization_and_propagation() {
        async fn count_list_handler(
            Query(query): Query<HashMap<String, String>>,
            req: Request,
        ) -> impl IntoResponse {
            let has_count = query.get("$count").map(|v| v.as_str()) == Some("true");
            let is_alert = req.uri().path().contains("alerts_v2");
            let mut body = json!({
                "value": [if is_alert { json!({"id": "alert-1"}) } else { json!({"id": "incident-1"}) }]
            });
            if has_count {
                body["@odata.count"] = json!(42);
                body["@odata.nextLink"] = json!("http://127.0.0.1/next.invalid");
            }
            (StatusCode::OK, Json(body))
        }

        let app = Router::new()
            .route("/security/alerts_v2", get(count_list_handler))
            .route("/security/incidents", get(count_list_handler));
        let guard = spawn_test_server(app).await;
        let server = create_test_server(&guard.base_url, false);

        let raw = json!({ "top": 10, "skip": 0, "count": true });
        let alert_input: ODataListInput =
            serde_json::from_value(raw.clone()).expect("deserialize ODataListInput");
        let alert_res = server
            .defender_xdr_alert_list(Parameters(alert_input))
            .await
            .expect("alert list call");
        let alert_val = alert_res
            .structured_content
            .as_ref()
            .expect("structured content");
        assert_eq!(alert_val["@odata.count"], 42);
        assert_eq!(
            alert_val["@odata.nextLink"],
            "http://127.0.0.1/next.invalid"
        );
        assert_eq!(alert_val["value"][0]["id"], "alert-1");

        let inc_input: ODataListInput =
            serde_json::from_value(raw).expect("deserialize ODataListInput");
        let inc_res = server
            .defender_xdr_incident_list(Parameters(inc_input))
            .await
            .expect("incident list call");
        let inc_val = inc_res
            .structured_content
            .as_ref()
            .expect("structured content");
        assert_eq!(inc_val["@odata.count"], 42);
        assert_eq!(inc_val["@odata.nextLink"], "http://127.0.0.1/next.invalid");
        assert_eq!(inc_val["value"][0]["id"], "incident-1");
    }

    #[tokio::test]
    async fn test_library_upload_preserves_slashes_and_newlines_in_description() {
        let app = Router::new().route(
            "/api/libraryfiles",
            post(|headers: axum::http::HeaderMap| async move {
                let ct = headers
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if ct.starts_with("multipart/form-data") {
                    (
                        StatusCode::OK,
                        Json(json!({"id": "lib-1", "name": "remediation.ps1"})),
                    )
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "invalid content type"})),
                    )
                }
            }),
        );
        let guard = spawn_test_server(app).await;
        let server = create_test_server(&guard.base_url, true);

        let res = server
            .defender_library_file_upload(Parameters(LiveResponseLibraryUploadInput {
                file_name: "remediation.ps1".to_string(),
                file_content: "Write-Output 'Scan'".to_string(),
                description: "Scan C:/Logs\nand /var/log".to_string(),
                parameters_description: None,
                override_if_exists: Some(true),
            }))
            .await
            .expect("upload call succeeded");
        let val = res.structured_content.as_ref().expect("structured content");
        assert_eq!(val["id"], "lib-1");
        assert_eq!(val["name"], "remediation.ps1");

        let empty_res = server
            .defender_library_file_upload(Parameters(LiveResponseLibraryUploadInput {
                file_name: "empty.ps1".to_string(),
                file_content: "".to_string(),
                description: "Valid description".to_string(),
                parameters_description: None,
                override_if_exists: None,
            }))
            .await
            .expect("handled empty content");
        assert_eq!(empty_res.is_error, Some(true));

        let bad_name = server
            .defender_library_file_upload(Parameters(LiveResponseLibraryUploadInput {
                file_name: "../escaped.ps1".to_string(),
                file_content: "Write-Output 'test'".to_string(),
                description: "Valid description".to_string(),
                parameters_description: None,
                override_if_exists: None,
            }))
            .await;
        assert_eq!(
            bad_name.unwrap_err().code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
    }

    #[tokio::test]
    async fn test_live_response_run_serializes_typed_enum_and_accepts_pending_action() {
        let app = Router::new().route(
            "/api/machines/dev-machine-01/runliveresponse",
            post(|Json(body): Json<Value>| async move {
                let expected = json!({
                    "Commands": [
                        {
                            "type": "RunScript",
                            "params": [
                                {"key": "ScriptName", "value": "triage.ps1"},
                                {"key": "Args", "value": "-Detailed"}
                            ]
                        }
                    ],
                    "Comment": "Live response triage for investigation"
                });
                if body == expected {
                    (
                        StatusCode::CREATED,
                        Json(json!({"id": "action-1", "status": "Pending"})),
                    )
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "wire shape mismatch"})),
                    )
                }
            }),
        );
        let guard = spawn_test_server(app).await;
        let server = create_test_server(&guard.base_url, true);

        let res = server
            .defender_endpoint_live_response_run(Parameters(LiveResponseRunInput {
                machine_id: "dev-machine-01".to_string(),
                commands: vec![LiveResponseCommand {
                    cmd_type: LiveResponseCommandType::RunScript,
                    params: vec![
                        LiveResponseParam {
                            key: "ScriptName".to_string(),
                            value: "triage.ps1".to_string(),
                        },
                        LiveResponseParam {
                            key: "Args".to_string(),
                            value: "-Detailed".to_string(),
                        },
                    ],
                }],
                comment: "Live response triage for investigation".to_string(),
            }))
            .await
            .expect("run call succeeded");

        let val = res.structured_content.as_ref().expect("structured content");
        assert_eq!(val["id"], "action-1");
        assert_eq!(val["status"], "Pending");
    }

    #[tokio::test]
    async fn test_live_response_negative_command_index_rejected_with_gate_precedence() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = call_count.clone();

        let app = Router::new().fallback(move || {
            let count = count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::OK,
                    Json(json!({"downloadUrl": "http://127.0.0.1/download.invalid"})),
                )
            }
        });
        let guard = spawn_test_server(app).await;

        // Gated precedence: disabled server returns tool error before validation
        let disabled_server = create_test_server(&guard.base_url, false);
        let disabled_res = disabled_server
            .defender_endpoint_live_response_get_result(Parameters(LiveResponseResultInput {
                action_id: "action-1".to_string(),
                command_index: -1,
            }))
            .await
            .expect("handled as tool error");
        assert_eq!(disabled_res.is_error, Some(true));
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // Enabled server: negative index rejected locally as invalid_params without upstream contact
        let enabled_server = create_test_server(&guard.base_url, true);
        let err = enabled_server
            .defender_endpoint_live_response_get_result(Parameters(LiveResponseResultInput {
                action_id: "action-1".to_string(),
                command_index: -1,
            }))
            .await
            .expect_err("negative index must error");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // Boundary: valid index 0 contacts upstream
        let valid_res = enabled_server
            .defender_endpoint_live_response_get_result(Parameters(LiveResponseResultInput {
                action_id: "action-1".to_string(),
                command_index: 0,
            }))
            .await
            .expect("valid index succeeds");
        let val = valid_res
            .structured_content
            .as_ref()
            .expect("structured content");
        assert_eq!(val["downloadUrl"], "http://127.0.0.1/download.invalid");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
