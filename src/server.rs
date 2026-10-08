//! Defender MCP server: tool router, tool implementations, and server handler.

use rmcp::{
    ErrorData as McpError, ServerHandler, handler::server::wrapper::Parameters, model::*, tool,
    tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::audit::{
    AuditPhase, AuditRecord, AuditResult, AuditSink, AuditTarget, ConfirmationOutcome,
    RejectReason, new_attempt_id,
};
use crate::auth::{IdentitySnapshot, PermissionCategory};
use crate::cli::MutatingTool;
use crate::client::{EndpointClient, GraphClient, MutationResponse, ODataParams};
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
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
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
// Domain dispatchers: action catalogs and inputs
// ---------------------------------------------------------------------------

pub const HUNTING_ACTIONS: &[&str] = &["run"];

pub const TI_ACTIONS: &[&str] = &[
    "intel_profiles_list",
    "intel_profile_get",
    "intel_profile_indicators_list",
    "intel_profile_indicator_get",
    "intel_profile_indicators_global_list",
    "articles_list",
    "article_get",
    "article_indicators_list",
    "article_indicator_get",
    "article_indicators_global_list",
    "host_get",
    "host_reputation_get",
    "host_components_list",
    "host_component_get",
    "host_cookies_list",
    "host_cookie_get",
    "host_ports_list",
    "host_port_get",
    "host_trackers_list",
    "host_tracker_get",
    "host_subdomains_list",
    "host_ssl_certs_list",
    "host_whois_get",
    "host_whois_history_list",
    "host_pairs_list",
    "host_pair_get",
    "host_child_pairs_list",
    "host_parent_pairs_list",
    "host_passive_dns_list",
    "host_passive_dns_reverse_list",
    "ssl_certs_list",
    "ssl_cert_get",
    "ssl_cert_related_hosts_list",
    "whois_records_list",
    "whois_record_get",
    "passive_dns_get",
    "vulnerability_get",
    "vulnerability_components_list",
    "vulnerability_component_get",
    "custom_indicator_list",
];

pub const INCIDENTS_ALERTS_ACTIONS: &[&str] = &[
    "xdr_alert_list",
    "xdr_alert_get",
    "xdr_incident_list",
    "xdr_incident_get",
    "endpoint_alert_list",
    "endpoint_alert_get",
    "ip_related_alerts",
    "domain_related_alerts",
    "file_related_alerts",
    "user_related_alerts",
];

pub const MACHINES_ACTIONS: &[&str] = &[
    "machine_list",
    "machine_get",
    "logged_on_users",
    "find_by_tag",
    "installed_software",
    "security_recommendations",
    "ip_statistics",
    "domain_statistics",
    "domain_related_machines",
    "file_get",
    "file_statistics",
    "file_related_machines",
    "user_related_machines",
    "find_by_ip",
    "machine_alerts",
    "machine_vulnerabilities",
    "machine_missing_kbs",
];

pub const VULNERABILITIES_ACTIONS: &[&str] = &[
    "software_list",
    "software_get",
    "software_machines",
    "software_vulnerabilities",
    "software_missing_kbs",
    "software_distribution",
    "vulnerability_list",
    "vulnerability_get_by_cve",
    "vulnerability_get_machines",
    "vulnerability_get_by_machine_software",
    "recommendation_list",
    "recommendation_get",
    "recommendation_machines",
    "recommendation_vulnerabilities",
    "recommendation_by_software",
    "remediation_list",
    "remediation_get",
    "remediation_exposed_devices",
    "exposure_score",
    "exposure_score_by_machine_groups",
];

pub const FORENSICS_ACTIONS: &[&str] = &[
    "machine_action_list",
    "machine_action_get_status",
    "get_investigation_package_sas_url",
    "download_investigation_package",
    "download_quarantined_file",
    "live_response_get_result",
    "investigation_list",
    "investigation_get",
    "library_file_list",
];

pub const RESPONSE_ACTIONS: &[&str] = &[
    "collect_investigation_package",
    "live_response_run",
    "upload_library_file",
    "stop_and_quarantine_file",
    "library_file_delete",
];

pub const DEVICE_RESPONSE_ACTIONS: &[&str] = &[
    "isolate",
    "unisolate",
    "restrict_app_execution",
    "unrestrict_app_execution",
    "run_av_scan",
    "start_investigation",
    "cancel_machine_action",
    "tag_add",
    "tag_remove",
    "set_device_value",
    "offboard",
];

pub const DEVICE_RESPONSE_ACTIONS_WITHOUT_OFFBOARD: &[&str] = &[
    "isolate",
    "unisolate",
    "restrict_app_execution",
    "unrestrict_app_execution",
    "run_av_scan",
    "start_investigation",
    "cancel_machine_action",
    "tag_add",
    "tag_remove",
    "set_device_value",
];

pub const INDICATORS_ACTIONS: &[&str] = &["submit", "delete", "batch_delete"];

pub const TRIAGE_ACTIONS: &[&str] = &[
    "endpoint_alert_update",
    "endpoint_alert_batch_update",
    "endpoint_alert_comment",
    "xdr_alert_update",
    "xdr_alert_comment",
    "xdr_incident_update",
    "xdr_incident_comment",
];

pub const DEVICE_RESPONSE_DESCRIPTION_WITH_OFFBOARD: &str = "\
Device containment, remediation, and lifecycle actions on managed endpoints. Actions: \
isolate (machine_id, isolation_type: Full|Selective|UnManagedDevice default Full, comment), \
unisolate (machine_id, comment), restrict_app_execution (machine_id, comment), \
unrestrict_app_execution (machine_id, comment), run_av_scan (machine_id, scan_type: Quick|Full, comment), \
start_investigation (machine_id, comment), cancel_machine_action (action_id, comment), \
tag_add (machine_id, tag, comment), tag_remove (machine_id, tag, comment), \
set_device_value (machine_id, device_value: Low|Normal|High, comment), \
offboard (machine_id, comment; irreversible). comment is mandatory (minimum 10 characters) \
for audit trail compliance. Gated mutating operation: requires human confirmation unless disabled.";

pub const DEVICE_RESPONSE_DESCRIPTION_WITHOUT_OFFBOARD: &str = "\
Device containment, remediation, and lifecycle actions on managed endpoints. Actions: \
isolate (machine_id, isolation_type: Full|Selective|UnManagedDevice default Full, comment), \
unisolate (machine_id, comment), restrict_app_execution (machine_id, comment), \
unrestrict_app_execution (machine_id, comment), run_av_scan (machine_id, scan_type: Quick|Full, comment), \
start_investigation (machine_id, comment), cancel_machine_action (action_id, comment), \
tag_add (machine_id, tag, comment), tag_remove (machine_id, tag, comment), \
set_device_value (machine_id, device_value: Low|Normal|High, comment). \
comment is mandatory (minimum 10 characters) for audit trail compliance. \
Gated mutating operation: requires human confirmation unless disabled.";

pub const INDICATORS_DESCRIPTION: &str = "\
Manage tenant-wide custom indicators of compromise (IoCs) to block, allow, or audit artifacts. \
Actions: submit (indicator_value, indicator_type: FileSha1|FileSha256|FileMd5|CertificateThumbprint|IpAddress|DomainName|Url, \
indicator_action: Allowed|Audit|Warn|Block|BlockAndRemediate, title, description, comment, \
severity: Informational|Low|Medium|High, expiration_time: RFC3339, rbac_group_names, recommended_actions, \
generate_alert), delete (indicator_id, comment), batch_delete (indicator_ids: 1-500 IDs, comment). \
comment is mandatory (minimum 10 characters) for audit trail compliance. Listing is available on \
defender_ti custom_indicator_list. Gated mutating operation: requires human confirmation unless disabled.";

pub const TRIAGE_DESCRIPTION: &str = "\
Triage and update alerts and incidents across Microsoft Defender Endpoint and Defender XDR. \
Actions: endpoint_alert_update (id, justification, status: new|inProgress|resolved, assigned_to, \
classification: truePositive|informationalExpectedActivity|falsePositive, determination, comment), \
endpoint_alert_batch_update (ids: 1-500 IDs, justification, status, assigned_to, classification, \
determination, comment), endpoint_alert_comment (id, comment, justification), \
xdr_alert_update (id, justification, status: new|inProgress|resolved, assigned_to, classification, determination), \
xdr_alert_comment (id, comment, justification), \
xdr_incident_update (id, justification, status: active|inProgress|resolved|redirected, assigned_to, \
classification, determination, tags: customTags), xdr_incident_comment (id, comment, justification). \
justification is mandatory (minimum 10 characters) for the audit log and is never sent upstream. \
Non-destructive: no human confirmation prompt.";

/// Deserialize a closed input enum from its exact input spelling (`name`). Errors name the
/// input `field` and list the valid values, because the parameter extractor reports serde
/// errors without a field path.
fn closed_enum<'de, D, T>(
    deserializer: D,
    field: &str,
    variants: &[T],
    name: fn(&T) -> &'static str,
) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Copy,
{
    let value = String::deserialize(deserializer)?;
    variants
        .iter()
        .find(|v| name(v) == value)
        .copied()
        .ok_or_else(|| {
            let valid: Vec<&str> = variants.iter().map(name).collect();
            serde::de::Error::custom(format!(
                "invalid {field} '{value}'; valid values: {}",
                valid.join(", ")
            ))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub enum IsolationType {
    Full,
    Selective,
    UnManagedDevice,
}

impl IsolationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Selective => "Selective",
            Self::UnManagedDevice => "UnManagedDevice",
        }
    }
}

impl<'de> Deserialize<'de> for IsolationType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "isolation_type",
            &[Self::Full, Self::Selective, Self::UnManagedDevice],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub enum ScanType {
    Quick,
    Full,
}

impl ScanType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quick => "Quick",
            Self::Full => "Full",
        }
    }
}

impl<'de> Deserialize<'de> for ScanType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "scan_type",
            &[Self::Quick, Self::Full],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub enum DeviceValue {
    Low,
    Normal,
    High,
}

impl DeviceValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Normal => "Normal",
            Self::High => "High",
        }
    }
}

impl<'de> Deserialize<'de> for DeviceValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "device_value",
            &[Self::Low, Self::Normal, Self::High],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceResponseInput {
    pub action: String,
    #[serde(default)]
    pub machine_id: Option<String>,
    #[serde(default)]
    pub action_id: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub isolation_type: Option<IsolationType>,
    #[serde(default)]
    pub scan_type: Option<ScanType>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub device_value: Option<DeviceValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub enum IndicatorType {
    FileSha1,
    FileSha256,
    FileMd5,
    CertificateThumbprint,
    IpAddress,
    DomainName,
    Url,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FileSha1 => "FileSha1",
            Self::FileSha256 => "FileSha256",
            Self::FileMd5 => "FileMd5",
            Self::CertificateThumbprint => "CertificateThumbprint",
            Self::IpAddress => "IpAddress",
            Self::DomainName => "DomainName",
            Self::Url => "Url",
        }
    }
}

impl<'de> Deserialize<'de> for IndicatorType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "indicator_type",
            &[
                Self::FileSha1,
                Self::FileSha256,
                Self::FileMd5,
                Self::CertificateThumbprint,
                Self::IpAddress,
                Self::DomainName,
                Self::Url,
            ],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub enum IndicatorAction {
    Allowed,
    Audit,
    Warn,
    Block,
    BlockAndRemediate,
}

impl IndicatorAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "Allowed",
            Self::Audit => "Audit",
            Self::Warn => "Warn",
            Self::Block => "Block",
            Self::BlockAndRemediate => "BlockAndRemediate",
        }
    }
}

impl<'de> Deserialize<'de> for IndicatorAction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if matches!(value.as_str(), "Alert" | "AlertAndBlock") {
            return Err(serde::de::Error::custom(format!(
                "indicator_action '{value}' is legacy, unsupported since January 2022"
            )));
        }
        closed_enum(
            serde::de::value::StringDeserializer::<D::Error>::new(value),
            "indicator_action",
            &[
                Self::Allowed,
                Self::Audit,
                Self::Warn,
                Self::Block,
                Self::BlockAndRemediate,
            ],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub enum IndicatorSeverity {
    Informational,
    Low,
    Medium,
    High,
}

impl IndicatorSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "Informational",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }
}

impl<'de> Deserialize<'de> for IndicatorSeverity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "severity",
            &[Self::Informational, Self::Low, Self::Medium, Self::High],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndicatorsInput {
    pub action: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub indicator_value: Option<String>,
    #[serde(default)]
    pub indicator_type: Option<IndicatorType>,
    #[serde(default)]
    pub indicator_action: Option<IndicatorAction>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<IndicatorSeverity>,
    #[serde(default)]
    pub expiration_time: Option<String>,
    #[serde(default)]
    pub rbac_group_names: Option<Vec<String>>,
    #[serde(default)]
    pub recommended_actions: Option<String>,
    #[serde(default)]
    pub generate_alert: Option<bool>,
    #[serde(default)]
    pub indicator_id: Option<String>,
    #[serde(default)]
    pub indicator_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageTarget {
    MdeAlertPatch,
    MdeAlertBatch,
    XdrAlert,
    XdrIncident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum TriageStatus {
    New,
    InProgress,
    Resolved,
    Active,
    Redirected,
}

impl TriageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::InProgress => "inProgress",
            Self::Resolved => "resolved",
            Self::Active => "active",
            Self::Redirected => "redirected",
        }
    }

    pub fn wire(&self, target: TriageTarget) -> Result<&'static str, rmcp::ErrorData> {
        match target {
            TriageTarget::MdeAlertPatch | TriageTarget::MdeAlertBatch => match self {
                Self::New => Ok("New"),
                Self::InProgress => Ok("InProgress"),
                Self::Resolved => Ok("Resolved"),
                Self::Active | Self::Redirected => Err(crate::error::invalid_params(format!(
                    "status '{}' is not supported for endpoint alerts; valid: new, inProgress, resolved",
                    self.as_str()
                ))),
            },
            TriageTarget::XdrAlert => match self {
                Self::New => Ok("new"),
                Self::InProgress => Ok("inProgress"),
                Self::Resolved => Ok("resolved"),
                Self::Active | Self::Redirected => Err(crate::error::invalid_params(format!(
                    "status '{}' is not supported for XDR alerts; valid: new, inProgress, resolved",
                    self.as_str()
                ))),
            },
            TriageTarget::XdrIncident => match self {
                Self::Active => Ok("active"),
                Self::InProgress => Ok("inProgress"),
                Self::Resolved => Ok("resolved"),
                Self::Redirected => Ok("redirected"),
                Self::New => Err(crate::error::invalid_params(
                    "status 'new' is not supported for XDR incidents; valid: active, inProgress, resolved, redirected",
                )),
            },
        }
    }
}

impl<'de> Deserialize<'de> for TriageStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "status",
            &[
                Self::New,
                Self::InProgress,
                Self::Resolved,
                Self::Active,
                Self::Redirected,
            ],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Classification {
    TruePositive,
    InformationalExpectedActivity,
    FalsePositive,
}

impl Classification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TruePositive => "truePositive",
            Self::InformationalExpectedActivity => "informationalExpectedActivity",
            Self::FalsePositive => "falsePositive",
        }
    }

    pub fn wire(&self, target: TriageTarget) -> &'static str {
        match target {
            TriageTarget::MdeAlertPatch | TriageTarget::MdeAlertBatch => match self {
                Self::TruePositive => "TruePositive",
                Self::InformationalExpectedActivity => "InformationalExpectedActivity",
                Self::FalsePositive => "FalsePositive",
            },
            TriageTarget::XdrAlert | TriageTarget::XdrIncident => self.as_str(),
        }
    }
}

impl<'de> Deserialize<'de> for Classification {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "classification",
            &[
                Self::TruePositive,
                Self::InformationalExpectedActivity,
                Self::FalsePositive,
            ],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Determination {
    MultiStagedAttack,
    MaliciousUserActivity,
    CompromisedAccount,
    Malware,
    Phishing,
    UnwantedSoftware,
    SecurityTesting,
    LineOfBusinessApplication,
    ConfirmedActivity,
    NotMalicious,
    NotEnoughDataToValidate,
    Other,
}

impl Determination {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MultiStagedAttack => "multiStagedAttack",
            Self::MaliciousUserActivity => "maliciousUserActivity",
            Self::CompromisedAccount => "compromisedAccount",
            Self::Malware => "malware",
            Self::Phishing => "phishing",
            Self::UnwantedSoftware => "unwantedSoftware",
            Self::SecurityTesting => "securityTesting",
            Self::LineOfBusinessApplication => "lineOfBusinessApplication",
            Self::ConfirmedActivity => "confirmedActivity",
            Self::NotMalicious => "notMalicious",
            Self::NotEnoughDataToValidate => "notEnoughDataToValidate",
            Self::Other => "other",
        }
    }

    pub fn allowed_for(classification: Classification) -> &'static [Determination] {
        match classification {
            Classification::TruePositive => &[
                Self::MultiStagedAttack,
                Self::MaliciousUserActivity,
                Self::CompromisedAccount,
                Self::Malware,
                Self::Phishing,
                Self::UnwantedSoftware,
                Self::Other,
            ],
            Classification::InformationalExpectedActivity => &[
                Self::SecurityTesting,
                Self::LineOfBusinessApplication,
                Self::ConfirmedActivity,
                Self::Other,
            ],
            Classification::FalsePositive => &[
                Self::NotMalicious,
                Self::NotEnoughDataToValidate,
                Self::Other,
            ],
        }
    }

    pub fn wire(&self, target: TriageTarget) -> &'static str {
        match target {
            TriageTarget::MdeAlertPatch => match self {
                Self::MultiStagedAttack => "MultiStagedAttack",
                Self::MaliciousUserActivity => "MaliciousUserActivity",
                Self::CompromisedAccount => "CompromisedUser",
                Self::Malware => "Malware",
                Self::Phishing => "Phishing",
                Self::UnwantedSoftware => "UnwantedSoftware",
                Self::SecurityTesting => "SecurityTesting",
                Self::LineOfBusinessApplication => "LineOfBusinessApplication",
                Self::ConfirmedActivity => "ConfirmedActivity",
                Self::NotMalicious => "NotMalicious",
                Self::NotEnoughDataToValidate => "InsufficientData",
                Self::Other => "Other",
            },
            TriageTarget::MdeAlertBatch => match self {
                Self::MultiStagedAttack => "MultiStagedAttack",
                Self::MaliciousUserActivity => "MaliciousUserActivity",
                Self::CompromisedAccount => "CompromisedUser",
                Self::Malware => "Malware",
                Self::Phishing => "Phishing",
                Self::UnwantedSoftware => "UnwantedSoftware",
                Self::SecurityTesting => "SecurityTesting",
                Self::LineOfBusinessApplication => "LineOfBusinessApplication",
                Self::ConfirmedActivity => "ConfirmedUserActivity",
                Self::NotMalicious => "Clean",
                Self::NotEnoughDataToValidate => "InsufficientData",
                Self::Other => "Other",
            },
            TriageTarget::XdrAlert | TriageTarget::XdrIncident => self.as_str(),
        }
    }
}

impl<'de> Deserialize<'de> for Determination {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        closed_enum(
            deserializer,
            "determination",
            &[
                Self::MultiStagedAttack,
                Self::MaliciousUserActivity,
                Self::CompromisedAccount,
                Self::Malware,
                Self::Phishing,
                Self::UnwantedSoftware,
                Self::SecurityTesting,
                Self::LineOfBusinessApplication,
                Self::ConfirmedActivity,
                Self::NotMalicious,
                Self::NotEnoughDataToValidate,
                Self::Other,
            ],
            Self::as_str,
        )
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageInput {
    pub action: String,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<TriageStatus>,
    #[serde(default)]
    pub assigned_to: Option<String>,
    #[serde(default)]
    pub classification: Option<Classification>,
    #[serde(default)]
    pub determination: Option<Determination>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub comment: Option<String>,
}

fn default_hunting_action() -> String {
    "run".to_string()
}

/// Input for `defender_hunting`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HuntingInput {
    /// Hunting action (only `run`; default `run`).
    #[serde(default = "default_hunting_action")]
    pub action: String,
    /// Read-only KQL query against the Defender XDR advanced-hunting schema.
    #[schemars(length(min = 1, max = 128000))]
    pub query: String,
    /// ISO 8601 duration or interval (default `P30D`).
    #[serde(default)]
    pub timespan: Option<String>,
}

/// Input for `defender_ti`. Unused fields must be omitted; `id` stands in for the action's
/// identifier (profile, article, indicator, certificate, record, or CVE ID).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelInput {
    /// Threat-intelligence action name (see tool description).
    pub action: String,
    /// Entity identifier: profile/article/indicator/component/cookie/port/tracker/pair/certificate/record ID, or CVE ID for `vulnerability_*`.
    #[serde(default)]
    pub id: Option<String>,
    /// Domain name or IP literal for `host_*` actions.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Component ID for `vulnerability_component_get`.
    #[serde(default)]
    pub component_id: Option<String>,
    /// Page size (default 50, max 1000).
    #[serde(default)]
    pub top: Option<i32>,
    /// Number of results to skip.
    #[serde(default)]
    pub skip: Option<i32>,
    /// OData `$filter` expression.
    #[serde(default)]
    pub filter: Option<String>,
    /// OData `$select` list.
    #[serde(default)]
    pub select: Option<String>,
    /// OData `$expand` list.
    #[serde(default)]
    pub expand: Option<String>,
    /// OData `$search` term (articles).
    #[serde(default)]
    pub search: Option<String>,
    /// Request `$count=true`.
    #[serde(default)]
    pub count: Option<bool>,
}

/// Input for `defender_incidents_alerts`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncidentsAlertsInput {
    /// Incident/alert action name (see tool description).
    pub action: String,
    /// Alert ID, incident ID, or indicator (IP, domain, SHA-1, username) for `*_related_alerts`.
    #[serde(default)]
    pub id: Option<String>,
    /// Page size.
    #[serde(default)]
    pub top: Option<i32>,
    /// Number of results to skip.
    #[serde(default)]
    pub skip: Option<i32>,
    /// OData `$filter` expression.
    #[serde(default)]
    pub filter: Option<String>,
    /// OData `$select` list (XDR lists).
    #[serde(default)]
    pub select: Option<String>,
    /// OData `$expand` list (XDR lists, `xdr_incident_get`).
    #[serde(default)]
    pub expand: Option<String>,
    /// OData `$search` term (XDR lists).
    #[serde(default)]
    pub search: Option<String>,
    /// Request `$count=true` (XDR lists).
    #[serde(default)]
    pub count: Option<bool>,
}

/// Input for `defender_machines`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachinesInput {
    /// Machine action name (see tool description).
    pub action: String,
    /// 40-hex Defender machine ID for `machine_get`, `logged_on_users`, `installed_software`, `security_recommendations`.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Indicator for indicator actions: IP, domain, file hash, username, or tag name.
    #[serde(default)]
    pub id: Option<String>,
    /// Tag value for `find_by_tag`.
    #[serde(default)]
    pub tag_name: Option<String>,
    /// Prefix tag matching for `find_by_tag`.
    #[serde(default)]
    pub use_starts_with: Option<bool>,
    /// Statistics look-back hours (1–720).
    #[serde(default)]
    pub look_back_hours: Option<i32>,
    /// Page size (max 10000).
    #[serde(default)]
    pub top: Option<i32>,
    /// Number of results to skip.
    #[serde(default)]
    pub skip: Option<i32>,
    /// OData `$filter` expression.
    #[serde(default)]
    pub filter: Option<String>,
    /// Timestamp for `find_by_ip` (RFC 3339, within 30 days).
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// Input for `defender_vulnerabilities`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilitiesInput {
    /// Vulnerability/software action name (see tool description).
    pub action: String,
    /// Software ID, CVE ID, recommendation ID, or remediation ID.
    #[serde(default)]
    pub id: Option<String>,
    /// CVE identifier (alternative to `id` for `vulnerability_*`).
    #[serde(default)]
    pub cve_id: Option<String>,
    /// Software ID (alternative to `id` for `software_*`).
    #[serde(default)]
    pub software_id: Option<String>,
    /// Page size (max 10000).
    #[serde(default)]
    pub top: Option<i32>,
    /// Number of results to skip.
    #[serde(default)]
    pub skip: Option<i32>,
    /// OData `$filter` expression.
    #[serde(default)]
    pub filter: Option<String>,
}

/// Input for `defender_forensics` (read-only remotely; download actions write to local staging).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForensicsInput {
    /// Forensics action name (see tool description).
    pub action: String,
    /// Machine action ID (GUID or hex).
    #[serde(default)]
    pub action_id: Option<String>,
    /// SHA-1 of the retrieved file; names the staged archive `quarantine_{sha1}.zip`.
    #[serde(default)]
    pub sha1: Option<String>,
    /// Zero-based Live Response command index (default 0).
    #[serde(default)]
    pub command_index: Option<i32>,
    /// Relative subdirectory inside the configured quarantine directory; absolute paths and `..` are rejected.
    #[serde(default)]
    pub destination_dir: Option<String>,
    /// Page size for `machine_action_list` (max 10000).
    #[serde(default)]
    pub top: Option<i32>,
    /// Number of results to skip.
    #[serde(default)]
    pub skip: Option<i32>,
    /// OData `$filter` expression.
    #[serde(default)]
    pub filter: Option<String>,
    /// Investigation ID for `investigation_get`.
    #[serde(default)]
    pub investigation_id: Option<String>,
}

/// Input for `defender_response` (mutating, gated).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseInput {
    /// Response action name (see tool description).
    pub action: String,
    /// Target 40-hex Defender machine ID.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Audit justification (at least 10 characters).
    #[serde(default)]
    pub comment: Option<String>,
    /// Live Response commands for `live_response_run` (max 20).
    #[serde(default)]
    pub commands: Option<Vec<LiveResponseCommand>>,
    /// Library file basename for `upload_library_file`.
    #[serde(default)]
    pub file_name: Option<String>,
    /// Non-empty UTF-8 content for `upload_library_file`.
    #[serde(default)]
    pub file_content: Option<String>,
    /// Library file description for `upload_library_file`.
    #[serde(default)]
    pub description: Option<String>,
    /// Script parameter guidance for `upload_library_file`.
    #[serde(default)]
    pub parameters_description: Option<String>,
    /// Overwrite an existing library file (destructive).
    #[serde(default)]
    pub override_if_exists: Option<bool>,
    /// 40-hex SHA-1 for `stop_and_quarantine_file`.
    #[serde(default)]
    pub sha1: Option<String>,
}

/// Serialize a dispatcher input into per-action arguments: drop `action` and absent fields.
fn action_args<T: Serialize>(input: &T) -> serde_json::Map<String, serde_json::Value> {
    let mut args = match serde_json::to_value(input) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    args.remove("action");
    args.retain(|_, v| !v.is_null());
    args
}

/// Move `from` to `to` when the target per-action input has no `id` alias for that field.
fn rename_arg(args: &mut serde_json::Map<String, serde_json::Value>, from: &str, to: &str) {
    if !args.contains_key(to)
        && let Some(v) = args.remove(from)
    {
        args.insert(to.to_string(), v);
    }
}

/// Extract `httpStatus` from a structured tool error produced by `error::http_error`.
fn http_status_of(result: &CallToolResult) -> Option<u64> {
    result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("httpStatus"))
        .and_then(serde_json::Value::as_u64)
}

/// Upstream JSON as structured content; upstream failures are already tool errors.
fn tool_result(result: Result<serde_json::Value, CallToolResult>) -> CallToolResult {
    result.map_or_else(|e| e, CallToolResult::structured)
}

fn required<'a>(value: &'a Option<String>, name: &str, action: &str) -> Result<&'a str, McpError> {
    value
        .as_deref()
        .ok_or_else(|| crate::error::invalid_params(format!("action '{action}' requires '{name}'")))
}

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

type Router = rmcp::handler::server::router::tool::ToolRouter<DefenderServer>;

#[derive(Clone)]
pub struct DefenderServer {
    client: GraphClient,
    endpoint: EndpointClient,
    config: crate::cli::ServerConfig,
    audit_sink: Option<std::sync::Arc<AuditSink>>,
    /// Tool catalog for the configured mode, with mutating tools removed under `--read-only`.
    router: std::sync::Arc<Router>,
}

impl DefenderServer {
    pub fn new_with_config(
        client: GraphClient,
        endpoint: EndpointClient,
        config: crate::cli::ServerConfig,
        audit_sink: Option<std::sync::Arc<AuditSink>>,
    ) -> Self {
        let mut router = Self::consolidated_tool_router();
        for tool in [
            MutatingTool::Response,
            MutatingTool::DeviceResponse,
            MutatingTool::Indicators,
            MutatingTool::Triage,
        ] {
            if !config.categories.tool_enabled(tool) {
                router.remove_route(tool.name());
            }
        }
        if let Some(route) = router.map.get_mut("defender_device_response") {
            if config.categories.offboarding {
                route.attr.description = Some(std::borrow::Cow::Borrowed(
                    DEVICE_RESPONSE_DESCRIPTION_WITH_OFFBOARD,
                ));
            } else {
                route.attr.description = Some(std::borrow::Cow::Borrowed(
                    DEVICE_RESPONSE_DESCRIPTION_WITHOUT_OFFBOARD,
                ));
            }
        }
        Self {
            client,
            endpoint,
            config,
            audit_sink,
            router: std::sync::Arc::new(router),
        }
    }

    /// Return the active identity snapshot.
    pub fn identity(&self) -> IdentitySnapshot {
        self.endpoint.identity()
    }

    /// Tools exposed by `tools/list` for the active configuration.
    pub fn list_tools_for_config(&self) -> Vec<Tool> {
        self.router.list_all()
    }

    /// Resolve the staging directory for a download, confining `destination_dir` to a
    /// relative subdirectory of the configured quarantine directory.
    fn staging_dir(&self, destination_dir: Option<&str>) -> Result<std::path::PathBuf, McpError> {
        let Some(sub) = destination_dir.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(self.config.quarantine_dir.clone());
        };
        let sub_path = std::path::Path::new(sub);
        let confined = sub_path.components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        });
        if !confined {
            return Err(crate::error::invalid_params(
                "destination_dir must be a relative subdirectory of the quarantine directory (no absolute paths or '..')",
            ));
        }
        Ok(self.config.quarantine_dir.join(sub_path))
    }

    // ---- Shared helpers ----

    /// Build ODataParams from an ODataListInput.
    fn from_odata_list(i: &ODataListInput) -> ODataParams<'_> {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            filter: i.filter.as_deref(),
            select: i.select.as_deref(),
            expand: i.expand.as_deref(),
            search: i.search.as_deref(),
            count: i.count,
        }
    }

    /// Build ODataParams from a HostnameODataInput.
    fn from_hostname_odata(i: &HostnameODataInput) -> ODataParams<'_> {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            filter: i.filter.as_deref(),
            select: i.select.as_deref(),
            expand: i.expand.as_deref(),
            count: i.count,
            ..ODataParams::default()
        }
    }

    /// Build ODataParams from an IntelProfileIdODataInput.
    fn from_intel_profile_odata(i: &IntelProfileIdODataInput) -> ODataParams<'_> {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            filter: i.filter.as_deref(),
            select: i.select.as_deref(),
            expand: i.expand.as_deref(),
            ..ODataParams::default()
        }
    }

    /// Build ODataParams from an ArticleIdODataInput.
    fn from_article_odata(i: &ArticleIdODataInput) -> ODataParams<'_> {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            select: i.select.as_deref(),
            ..ODataParams::default()
        }
    }

    /// Build ODataParams from a CertRelatedHostsInput.
    fn from_cert_related_odata(i: &CertRelatedHostsInput) -> ODataParams<'_> {
        ODataParams {
            top: Some(i.top),
            skip: Some(i.skip),
            count: i.count,
            ..ODataParams::default()
        }
    }

    /// Convenience: perform a simple GET and return the raw JSON as structured content.
    async fn simple_get(&self, path: &str) -> Result<CallToolResult, McpError> {
        Ok(tool_result(self.client.graph_get(path, &[]).await))
    }

    /// Convenience: GET with OData params, return raw JSON as structured content.
    async fn odata_get(
        &self,
        path: &str,
        odata: &ODataParams<'_>,
    ) -> Result<CallToolResult, McpError> {
        Ok(tool_result(
            self.client.graph_get_with_odata(path, odata).await,
        ))
    }

    // ---- Endpoint helpers ----

    async fn ep_simple_get(&self, path: &str) -> Result<CallToolResult, McpError> {
        Ok(tool_result(self.endpoint.endpoint_get(path, &[]).await))
    }

    async fn ep_odata_get(
        &self,
        path: &str,
        odata: &ODataParams<'_>,
    ) -> Result<CallToolResult, McpError> {
        Ok(tool_result(
            self.endpoint.endpoint_get_with_odata(path, odata).await,
        ))
    }

    async fn ep_simple_get_as(
        &self,
        path: &str,
        category: PermissionCategory,
    ) -> Result<CallToolResult, McpError> {
        Ok(tool_result(
            self.endpoint.endpoint_get_as(path, &[], category).await,
        ))
    }

    async fn ep_odata_get_as(
        &self,
        path: &str,
        odata: &ODataParams<'_>,
        category: PermissionCategory,
    ) -> Result<CallToolResult, McpError> {
        Ok(tool_result(
            self.endpoint
                .endpoint_get_with_odata_as(path, odata, category)
                .await,
        ))
    }

    /// Check whether the action is a write-named read that was not requested under delegated --read-only.
    fn check_scope_not_requested(&self, action: &str) -> Option<CallToolResult> {
        if matches!(self.config.auth, crate::cli::AuthConfig::User { .. }) && self.config.read_only
        {
            let scope = match action {
                "domain_related_machines"
                | "file_related_machines"
                | "user_related_machines"
                | "find_by_ip"
                | "download_quarantined_file"
                | "download_live_response_result"
                | "live_response_get_result" => Some("Machine.ReadWrite"),
                "file_related_alerts"
                | "machine_alerts"
                | "get_investigation_package_sas_url"
                | "download_investigation_package"
                | "investigation_list"
                | "investigation_get" => Some("Alert.ReadWrite"),
                "custom_indicator_list" => Some("Ti.ReadWrite"),
                "library_file_list" => Some("Library.Manage"),
                _ => None,
            };
            if let Some(s) = scope {
                return Some(crate::error::scope_not_requested(action, s));
            }
        }
        None
    }

    /// Build ODataParams with endpoint max top.
    fn ep_odata(filter: Option<&str>, top: i32, skip: i32) -> ODataParams<'_> {
        ODataParams {
            top: Some(top),
            skip: Some(skip),
            filter,
            ..ODataParams::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

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
    /// Former tool `defender_advanced_hunting_run`.
    ///
    /// Execute a read-only KQL query across Microsoft Defender XDR advanced hunting event tables (DeviceProcessEvents, DeviceNetworkEvents, EmailEvents, IdentityLogonEvents, etc.). Returns matching event rows and column schema. Timespan defaults to P30D (last 30 days) and accepts all ISO 8601 duration/interval formats (e.g., P7D, P90D, or explicit start/end timestamps); available history depends on upstream data and workspace retention policies. Execution is limited to 100,000 rows, 50 MB response payload, and approximately 3-minute timeout per query, subject to tenant-dependent rate and CPU resource quotas. Requires ThreatHunting.Read.All application permission.
    async fn defender_advanced_hunting_run(
        &self,
        Parameters(params): Parameters<HuntingQueryInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_kql_query(&params.query)?;

        let body = json!({
            "Query": params.query,
            "Timespan": params.timespan,
        });

        Ok(tool_result(
            self.client
                .graph_post("/security/runHuntingQuery", &body)
                .await,
        ))
    }

    // ============================================================
    // 3.2 TI Intel Profiles
    // ============================================================

    /// List all threat intelligence intel profiles (actor profiles).
    /// Former tool `defender_ti_intel_profiles_list`.
    ///
    /// List threat actor intelligence profiles from Microsoft Defender Threat Intelligence, including nation-state groups, cybercrime syndicates, and tracked activity groups. Returns an OData collection of actor profiles with names, aliases, targets, and description summaries. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_intel_profile_get`.
    ///
    /// Retrieve detailed information for a specific threat actor profile by its unique identifier. Returns full profile metadata including known aliases, active targets, targeted industries and geographic regions, threat descriptions, and first/last seen dates. Pass the opaque intel_profile_id copied directly from profile listing or query results; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_intel_profile_indicators_list`.
    ///
    /// List indicators of compromise (IoCs) associated with a specific threat actor profile, such as command-and-control IP addresses, malicious domains, and file hashes. Returns an OData collection of indicator entities. Pass the opaque intel_profile_id. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_intel_profile_indicator_get`.
    ///
    /// Retrieve details for a specific threat actor profile indicator by its indicator identifier. Returns indicator type, observed value, confidence level, first/last seen timestamps, and associated threat context. Pass the opaque indicator_id copied verbatim from indicator listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_intel_profile_indicators_global_list`.
    ///
    /// List threat intelligence indicators across all actor profiles globally. Returns an OData collection of threat indicators aggregated across tracked adversaries. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_articles_list`.
    ///
    /// List threat intelligence articles and research reports published by Microsoft security researchers covering emerging threats, campaigns, and vulnerabilities. Returns an OData collection of article summaries. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, $expand, and $search for full-text keyword querying. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_article_get`.
    ///
    /// Retrieve the full content of a specific threat intelligence article by its article identifier. Returns comprehensive narrative report details, executive summary, threat analysis, and publication metadata. Pass the article_id (e.g., a272d5ab) copied verbatim from article listing. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_article_indicators_list`.
    ///
    /// List indicators of compromise (IoCs) published within a specific threat intelligence article. Returns an OData collection of indicator entities associated with the research report. Pass the article_id. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, and $select. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_article_indicator_get`.
    ///
    /// Retrieve details of a specific article indicator by its indicator identifier. Returns indicator attributes, observed values, and threat context published in the parent research report. Pass the opaque indicator_id copied verbatim from listing results; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_article_indicators_global_list`.
    ///
    /// List indicators of compromise published across all threat intelligence articles globally. Returns an OData collection of indicators aggregated from all research reports. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_get`.
    ///
    /// Retrieve telemetry and infrastructure metadata for an internet host (domain name or IP address literal). Returns first and last observed timestamps, hosting provider details, autonomous system information, and network attributes. Input hostname must be a plain domain or IP; do not pass full URLs with protocols or paths. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_reputation_get`.
    ///
    /// Retrieve reputation scoring and risk classification for an internet host (domain name or IP address literal). Returns classification status (malicious, suspicious, neutral, or unknown), computed numeric score (0-100), and triggering heuristic detection rules. Input hostname must be a plain domain or IP literal. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_components_list`.
    ///
    /// List web components, application frameworks, content management systems, and server software observed running on an internet host. Returns an OData collection of component records. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_component_get`.
    ///
    /// Retrieve details for a specific host web component by its unique component identifier. Returns component category, detected product name, version details, and observation timestamps. Pass the opaque component_id copied verbatim from host component listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_cookies_list`.
    ///
    /// List HTTP cookies observed on an internet host during web crawling and infrastructure scanning. Returns an OData collection of cookie records including cookie names, domains, and observation timestamps. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_cookie_get`.
    ///
    /// Retrieve details for a specific host HTTP cookie record by its unique cookie identifier. Returns cookie name, domain attribute, first and last seen timestamps, and associated host context. Pass the opaque cookie_id copied verbatim from host cookie listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_ports_list`.
    ///
    /// List open network ports and running services observed on an internet host. Returns an OData collection of port records including port numbers, transport protocols, service banners, and scan timestamps. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_port_get`.
    ///
    /// Retrieve details for a specific open port observation on a host by its unique port identifier. Returns port number, protocol, service banner strings, and detection timestamps. Pass the opaque port_id copied verbatim from host port listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_trackers_list`.
    ///
    /// List web tracking identifiers, ad codes, and analytics scripts (e.g., Google Analytics IDs, New Relic tags, social widgets) observed on an internet host. Returns an OData collection of tracker records useful for infrastructure correlation. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_tracker_get`.
    ///
    /// Retrieve details for a specific web tracker observation on a host by its unique tracker identifier. Returns tracker type, tracking identifier value, and observation window. Pass the opaque tracker_id copied verbatim from host tracker listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_subdomains_list`.
    ///
    /// List known subdomains observed for a specific domain name. Returns an OData collection of subdomain host records discovered across passive DNS and web crawling. Input hostname must be a valid domain name (e.g., contoso.com). Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_ssl_certs_list`.
    ///
    /// List X.509 SSL/TLS certificates observed on an internet host. Returns an OData collection of certificate records with thumbprints, subject alternative names, validity dates, and issuer details. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, $expand, and $count. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_whois_get`.
    ///
    /// Retrieve the current active WHOIS domain registration record for a specific host. Returns registrar name, registrant contact details, administrative contacts, authoritative name servers, and expiration dates. Input hostname must be a plain domain name (e.g., contoso.com). Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_whois_history_list`.
    ///
    /// List historical WHOIS registration snapshots for an internet domain host. Returns an OData collection of historical WHOIS records reflecting past ownership, contact changes, and registrar transfers. Input hostname must be a plain domain name. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_pairs_list`.
    ///
    /// List host pairing relationships where the specified host acts as either the parent (initiating connection/referral) or child (target resource) in web infrastructure mappings. Returns an OData collection of host pair entities. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_pair_get`.
    ///
    /// Retrieve details of a specific host pair connection by its unique relationship identifier. Returns parent host, child host, link type (e.g., script, link, iframe), and observation timestamps. Pass the opaque pair_id copied verbatim from host pair listing; do not manually base64-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_child_pairs_list`.
    ///
    /// List child host connections where the specified host is the parent initiating or referencing external resources. Returns an OData collection of child host pair records. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_parent_pairs_list`.
    ///
    /// List parent host connections where the specified host is referenced or targeted by external parent resources. Returns an OData collection of parent host pair records. Input hostname must be a plain domain or IP literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_passive_dns_list`.
    ///
    /// List forward passive DNS resolution history for a domain host, mapping the domain to observed IP addresses over time. Returns an OData collection of resolution records with first/last seen timestamps and record types (A, AAAA, CNAME). Input hostname must be a valid domain name. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_host_passive_dns_reverse_list`.
    ///
    /// List reverse passive DNS resolution history for an IP address host, mapping the IP address to domains historically resolved to it. Returns an OData collection of resolution records. Input hostname must be a valid IP address literal. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_ssl_certs_list`.
    ///
    /// List SSL/TLS certificates cataloged in the Microsoft Defender Threat Intelligence database. Returns an OData collection of certificate metadata objects including serial numbers, SHA1/SHA256 thumbprints, subject/issuer distinguished names, and validity dates. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_ssl_cert_get`.
    ///
    /// Retrieve full details of a specific SSL/TLS certificate by its certificate identifier. Returns complete X.509 certificate attributes, public key algorithms, subject alternative names, and certificate transparency metadata. Pass the certificate_id (opaque base64 string, e.g., MDJjODMz...) copied verbatim from certificate listing; do not decode or re-encode. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_ssl_cert_related_hosts_list`.
    ///
    /// List internet hosts and domains observed presenting a specific SSL/TLS certificate. Returns an OData collection of related host entities. Pass the certificate_id (opaque base64 string copied verbatim). Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, and $count. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_whois_records_list`.
    ///
    /// List domain WHOIS registration records cataloged across Microsoft Defender Threat Intelligence. Returns an OData collection of WHOIS record summaries. Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, $filter, $select, and $expand. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_whois_record_get`.
    ///
    /// Retrieve a specific domain WHOIS registration record by its record identifier. Returns comprehensive registration details, contact blocks, raw registrar responses, and nameservers. Pass the opaque record_id (typically a base64 string copied verbatim from listing results); do not decode or re-encode. For active domain lookups by hostname, use defender_ti_host_whois_get. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_passive_dns_get`.
    ///
    /// Retrieve a specific passive DNS record by its unique record identifier. Returns domain, IP address mapping, record type, and first/last observed resolution timestamps. Pass the opaque record_id copied verbatim from listing results; do not manually base64-encode. For host-based resolution queries, use defender_ti_host_passive_dns_list. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_vulnerability_get`.
    ///
    /// Retrieve threat intelligence details for a specific Common Vulnerabilities and Exposures (CVE) identifier. Returns vulnerability description, CVSS base score, severity rating, active exploit status in the wild, remediation guidance, related intelligence articles, and dark web discussion chatter. CVE ID must follow standard format CVE-YYYY-NNNN+ (e.g., CVE-2021-44228). Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_ti_vulnerability_components_list`.
    ///
    /// List software and hardware components affected by a specific CVE identifier according to Microsoft Defender Threat Intelligence. Returns an OData collection of affected component objects. Pass a valid CVE ID (e.g., CVE-2021-44228). Supports OData query parameters: $top (default 50, max 1000), $skip for offset pagination, and $select. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
    async fn defender_ti_vulnerability_components_list(
        &self,
        Parameters(params): Parameters<VulnerabilityODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let vulnerability_id = validation::validate_cve_id(&params.vulnerability_id)?;
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = ODataParams {
            top: Some(params.top),
            skip: Some(params.skip),
            select: params.select.as_deref(),
            ..ODataParams::default()
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
    /// Former tool `defender_ti_vulnerability_component_get`.
    ///
    /// Retrieve details for a specific component affected by a CVE vulnerability. Returns component identification, vendor, product version ranges, and platform context. Pass a valid CVE ID (e.g., CVE-2021-44228) and the opaque component_id copied verbatim from component listing. Requires ThreatIntelligence.Read.All application permission and an active Microsoft Defender Threat Intelligence license.
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
    /// Former tool `defender_endpoint_machine_list`.
    ///
    /// List onboarded endpoint machines and devices enrolled in Microsoft Defender for Endpoint. Returns an OData collection of machine entities with health status, risk levels, OS platforms, IP addresses, and device tags. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Machine.Read.All application permission.
    async fn defender_endpoint_machine_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/machines", &odata).await
    }

    /// Get detailed information about a specific machine by ID.
    /// Former tool `defender_endpoint_machine_get`.
    ///
    /// Retrieve detailed hardware, OS, network, and security configuration for a specific device by its Defender machine ID. Returns computer name, domain, OS version, agent health, risk score, exposure level, and first/last seen timestamps. Pass the machine_id (usually a 40-character hexadecimal Defender device ID; not an Azure AD device ID or UUID). Requires Machine.Read.All application permission.
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
    /// Former tool `defender_endpoint_machine_logged_on_users`.
    ///
    /// List user accounts observed logged on to a specific endpoint device. Returns an OData object with a value array of user records, including accountName, accountDomain, firstSeen, lastSeen, and logonTypes; these are not individual logon sessions. Pass the Defender machine_id. Requires User.Read.All application permission.
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
    /// Former tool `defender_endpoint_machine_find_by_tag`.
    ///
    /// Search for endpoint devices by administrative device tag. Returns an OData object with a value array of matching machines. Pass the tag_name (case-insensitive string; slashes and dots are preserved in the query) and optional use_starts_with boolean (true for prefix matching, false for exact match). Requires Machine.Read.All application permission.
    async fn defender_endpoint_machine_find_by_tag(
        &self,
        Parameters(params): Parameters<FindByTagInput>,
    ) -> Result<CallToolResult, McpError> {
        let tag_name = validation::validate_tag_name(&params.tag_name)?;
        let use_starts_with = if params.use_starts_with {
            "true"
        } else {
            "false"
        };
        let q = [("tag", tag_name), ("useStartsWithFilter", use_starts_with)];
        Ok(tool_result(
            self.endpoint
                .endpoint_get("/api/machines/findByTag", &q)
                .await,
        ))
    }

    /// List all installed software on a specific machine.
    /// Former tool `defender_endpoint_machine_list_software`.
    ///
    /// List software applications, versions, and vendors installed on a specific endpoint device. Returns an OData object with a value array of installed software entities for vulnerability and compliance analysis. Pass the 40-hex Defender machine_id. Requires Software.Read.All application permission.
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
    /// Former tool `defender_endpoint_machine_security_recommendations`.
    ///
    /// List security recommendations and configuration improvement actions applicable to a specific endpoint device. Returns an OData object with a value array of recommendations including remediation steps, threat context, and risk impact. Pass the 40-hex Defender machine_id. Requires SecurityRecommendation.Read.All application permission.
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
    /// Former tool `defender_endpoint_software_list`.
    ///
    /// List software inventory items discovered across all onboarded devices in the organization. Returns an OData collection of software products with vendor names, product identifiers, and weakness counts. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Software.Read.All application permission.
    async fn defender_endpoint_software_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/Software", &odata).await
    }

    /// Get detailed information about a specific software by ID.
    /// Former tool `defender_endpoint_software_get`.
    ///
    /// Retrieve detailed inventory and vulnerability summary for a specific software product. Returns product name, vendor, installed device count, and overall exposure metrics. Pass the software_id (e.g., microsoft-_-internet_explorer). Requires Software.Read.All application permission.
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
    /// Former tool `defender_endpoint_software_machines`.
    ///
    /// List endpoint devices that currently have a specific software product installed. Returns an OData collection of machine reference entities. Pass the software_id. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Machine.Read.All or Software.Read.All application permission.
    async fn defender_endpoint_software_machines(
        &self,
        Parameters(params): Parameters<SoftwareODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let software_id = validation::validate_required_id(&params.software_id, "software_id")?;
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
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
    /// Former tool `defender_endpoint_software_vulnerabilities`.
    ///
    /// List known Common Vulnerabilities and Exposures (CVEs) associated with a specific software product across the organization. Returns an OData object with a value array of vulnerability summary entities with severity and CVSS scores. Pass the software_id. Requires Vulnerability.Read.All application permission.
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
    /// Former tool `defender_endpoint_software_missing_kbs`.
    ///
    /// List missing Microsoft security updates (KB patches) required for a specific software product installed on organizational endpoints. Returns an OData object with a value array of missing update entities. Pass the software_id. Requires Software.Read.All application permission.
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
    /// Former tool `defender_endpoint_software_distribution`.
    ///
    /// Retrieve version distribution statistics for a specific software product across the organizational device fleet. Returns raw JSON containing software version records with deployed machine counts. Pass the software_id. Requires Software.Read.All application permission.
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
    /// Former tool `defender_endpoint_vulnerability_list`.
    ///
    /// List all vulnerabilities affecting software installed across the organization according to Defender Vulnerability Management. Returns an OData collection of CVE vulnerability entities with CVSS scores, exploitability tags, and severity ratings. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Vulnerability.Read.All application permission.
    async fn defender_endpoint_vulnerability_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/vulnerabilities", &odata).await
    }

    /// Get a specific vulnerability by CVE identifier.
    /// Former tool `defender_endpoint_vulnerability_get_by_cve`.
    ///
    /// Retrieve details for a specific vulnerability in organizational software by its CVE identifier. Returns vulnerability severity, CVSS scores, published dates, exploitability types, and affected software list. Pass a valid CVE ID (e.g., CVE-2021-44228). Requires Vulnerability.Read.All application permission.
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
    /// Former tool `defender_endpoint_vulnerability_get_machines`.
    ///
    /// List endpoint devices exposed to a specific CVE vulnerability due to vulnerable software installations. Returns an OData collection of machine references. Pass a valid CVE ID (e.g., CVE-2021-44228). Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Machine.Read.All or Vulnerability.Read.All application permission.
    async fn defender_endpoint_vulnerability_get_machines(
        &self,
        Parameters(params): Parameters<CveODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let cve_id = validation::validate_cve_id(&params.cve_id)?;
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
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
    /// Former tool `defender_endpoint_vulnerability_get_by_machine_software`.
    ///
    /// List all tripartite mappings between vulnerable software, specific CVEs, and exposed devices across the organization. Returns an OData collection of vulnerability-machine-software association records. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Vulnerability.Read.All application permission.
    async fn defender_endpoint_vulnerability_get_by_machine_software(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/vulnerabilities/machinesVulnerabilities", &odata)
            .await
    }

    // ============================================================
    // 4.x Endpoint — Security Recommendations (5 tools)
    // ============================================================

    /// List all security recommendations.
    /// Former tool `defender_endpoint_recommendation_list`.
    ///
    /// List security recommendations from Microsoft Defender Vulnerability Management prioritizing risk reduction across endpoints. Returns an OData collection of security recommendation objects with remediation type, threat context, and exposure impact. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires SecurityRecommendation.Read.All application permission.
    async fn defender_endpoint_recommendation_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/recommendations", &odata).await
    }

    /// Get a specific security recommendation by ID.
    /// Former tool `defender_endpoint_recommendation_get`.
    ///
    /// Retrieve details of a specific security recommendation by its recommendation identifier. Returns full recommendation metadata, remediation instructions, affected product information, and risk score impact. Pass the recommendation_id (e.g., va-_-google-_-chrome). Requires SecurityRecommendation.Read.All application permission.
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
    /// Former tool `defender_endpoint_recommendation_machines`.
    ///
    /// List endpoint devices where a specific security recommendation is currently applicable and unresolved. Returns an OData object with a value array of machine references. Pass the recommendation_id. Requires SecurityRecommendation.Read.All application permission.
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
    /// Former tool `defender_endpoint_recommendation_vulnerabilities`.
    ///
    /// List CVE vulnerabilities addressed and remediated by implementing a specific security recommendation. Returns an OData object with a value array of related CVE records. Pass the recommendation_id. Requires Vulnerability.Read.All application permission.
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
    /// Former tool `defender_endpoint_recommendation_by_software`.
    ///
    /// List software applications associated with a specific security recommendation. Returns an OData object with a value array of related software products. Pass the recommendation_id. Requires Software.Read.All application permission.
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
    /// Former tool `defender_endpoint_remediation_list`.
    ///
    /// List remediation tasks and security mitigation activities created in Defender Vulnerability Management or integrated via Microsoft Intune. Returns an OData collection of remediation task summaries with status, priority, and progress metrics. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires RemediationTasks.Read.All application permission.
    async fn defender_endpoint_remediation_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/remediationTasks", &odata).await
    }

    /// Get a specific remediation task by ID.
    /// Former tool `defender_endpoint_remediation_get`.
    ///
    /// Retrieve details and execution status for a specific remediation task by its task identifier. Returns task title, description, assigned technician/team, target completion date, and current lifecycle state. Pass the remediation_id (GUID string). Requires RemediationTasks.Read.All application permission.
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
    /// Former tool `defender_endpoint_remediation_exposed_devices`.
    ///
    /// List endpoint devices targeted by or exposed to a specific remediation task. Returns an OData collection of machine references. Pass the remediation_id (GUID string). Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Machine.Read.All or RemediationTasks.Read.All application permission.
    async fn defender_endpoint_remediation_exposed_devices(
        &self,
        Parameters(params): Parameters<RemediationODataInput>,
    ) -> Result<CallToolResult, McpError> {
        let remediation_id =
            validation::validate_required_id(&params.remediation_id, "remediation_id")?;
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
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
    /// Former tool `defender_endpoint_exposure_score`.
    ///
    /// Retrieve the organization's overall device exposure score from Microsoft Defender Vulnerability Management. Returns calculated exposure score reflecting cumulative organizational risk based on unresolved vulnerabilities, misconfigurations, and device criticality. Requires Score.Read.All application permission.
    async fn defender_endpoint_exposure_score(&self) -> Result<CallToolResult, McpError> {
        self.ep_simple_get("/api/exposureScore").await
    }

    /// Get exposure score broken down by machine group.
    /// Former tool `defender_endpoint_exposure_score_by_machine_groups`.
    ///
    /// Retrieve exposure scores broken down across defined device groups (e.g., Tier 0 domain controllers, developer workstations, production servers). Returns raw JSON containing group exposure objects with group IDs, group names, and individual group exposure scores. Requires Score.Read.All application permission.
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
    /// Former tool `defender_endpoint_ip_statistics`.
    ///
    /// Retrieve organizational prevalence and communication statistics for an external or internal IP address across all managed endpoints. Returns first and last observed communication timestamps, communicating device counts, and traffic summaries. Pass an IPv4 or IPv6 address and optional look_back_hours (default 720, representing 30 days; range 1–720). Requires Ip.Read.All application permission.
    async fn defender_endpoint_ip_statistics(
        &self,
        Parameters(params): Parameters<IpStatsInput>,
    ) -> Result<CallToolResult, McpError> {
        let ip_address = validation::validate_ip_address(&params.ip_address)?;
        validation::validate_look_back_hours(params.look_back_hours)?;
        let lh = params
            .look_back_hours
            .unwrap_or(crate::constants::DEFAULT_LOOK_BACK_HOURS)
            .to_string();
        Ok(tool_result(
            self.endpoint
                .endpoint_get(
                    &format!(
                        "/api/ips/{}/stats",
                        validation::encode_path_segment(ip_address)
                    ),
                    &[("lookBackHours", lh.as_str())],
                )
                .await,
        ))
    }

    /// Get alerts related to a specific IP address.
    /// Former tool `defender_endpoint_ip_related_alerts`.
    ///
    /// List security alerts associated with network traffic to or from a specific IP address across all endpoints. Returns an OData object with a value array of related alerts. Pass an IPv4 or IPv6 address literal. Requires Alert.Read.All or Alert.ReadWrite.All application permission.
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
    /// Former tool `defender_endpoint_domain_statistics`.
    ///
    /// Retrieve organizational prevalence and communication statistics for a domain name across all managed endpoints. Returns first and last observed access timestamps and accessing device counts. Pass a domain name (e.g., example.com) and optional look_back_hours (default 720; range 1–720). Requires URL.Read.All application permission.
    async fn defender_endpoint_domain_statistics(
        &self,
        Parameters(params): Parameters<DomainStatsInput>,
    ) -> Result<CallToolResult, McpError> {
        let domain_name = validation::validate_hostname(&params.domain_name)?;
        validation::validate_look_back_hours(params.look_back_hours)?;
        let lh = params
            .look_back_hours
            .unwrap_or(crate::constants::DEFAULT_LOOK_BACK_HOURS)
            .to_string();
        Ok(tool_result(
            self.endpoint
                .endpoint_get(
                    &format!(
                        "/api/domains/{}/stats",
                        validation::encode_path_segment(domain_name)
                    ),
                    &[("lookBackHours", lh.as_str())],
                )
                .await,
        ))
    }

    /// List machines that have communicated with a specific domain.
    /// Former tool `defender_endpoint_domain_related_machines`.
    ///
    /// List endpoint devices that have communicated with or resolved a specific domain name. Returns an OData object with a value array of machines (capped at 500 devices per upstream API limits). Pass a domain name. Requires Machine.ReadWrite.All application permission.
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
    /// Former tool `defender_endpoint_domain_related_alerts`.
    ///
    /// List security alerts associated with network traffic or browser navigation to a specific domain name. Returns an OData object with a value array of related alerts. Pass a domain name. Requires Alert.ReadWrite.All application permission.
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
    /// Former tool `defender_endpoint_file_get`.
    ///
    /// Retrieve file metadata and global reputation for a specific file hash from Defender for Endpoint intelligence. Returns file size, file names, signing details, publisher, and global prevalence. Pass a valid MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex) hash. Requires File.Read.All application permission.
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
    /// Former tool `defender_endpoint_file_statistics`.
    ///
    /// Retrieve organizational prevalence statistics for a file by its SHA1 hash across all endpoints. Returns first and last seen timestamps, executing device counts, and file open counts. Pass exactly a 40-character hexadecimal SHA1 hash and optional look_back_hours (default 720; range 1–720). Requires File.Read.All application permission.
    async fn defender_endpoint_file_statistics(
        &self,
        Parameters(params): Parameters<FileStatsInput>,
    ) -> Result<CallToolResult, McpError> {
        let file_sha1 = validation::validate_sha1(&params.file_sha1)?;
        validation::validate_look_back_hours(params.look_back_hours)?;
        let lh = params
            .look_back_hours
            .unwrap_or(crate::constants::DEFAULT_LOOK_BACK_HOURS)
            .to_string();
        Ok(tool_result(
            self.endpoint
                .endpoint_get(
                    &format!(
                        "/api/files/{}/stats",
                        validation::encode_path_segment(file_sha1)
                    ),
                    &[("lookBackHours", lh.as_str())],
                )
                .await,
        ))
    }

    /// List machines where a specific file (by SHA1) has been observed.
    /// Former tool `defender_endpoint_file_related_machines`.
    ///
    /// List endpoint devices where a specific file has been observed or executed. Returns an OData object with a value array of machine records. Pass exactly a 40-character hexadecimal SHA1 hash. Requires Machine.ReadWrite.All application permission.
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
    /// Former tool `defender_endpoint_file_related_alerts`.
    ///
    /// List security alerts triggered by or involving a specific file across the organization. Returns an OData object with a value array of related alerts. Pass exactly a 40-character hexadecimal SHA1 hash. Requires Alert.ReadWrite.All application permission.
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
    /// Former tool `defender_endpoint_user_related_alerts`.
    ///
    /// List security alerts involving a specific user account on endpoint devices. Returns an OData object with a value array of related alerts. Pass the account username recognized by Defender for Endpoint (e.g., user1; do not pass a full UPN like user1@contoso.com, SID, or AAD GUID). Requires Alert.Read.All or Alert.ReadWrite.All application permission.
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
    /// Former tool `defender_endpoint_user_related_machines`.
    ///
    /// List endpoint devices where a specific user account has logged on. Returns an OData object with a value array of machines. Pass the account username (e.g., user1). Requires Machine.ReadWrite.All application permission.
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
    /// Former tool `defender_endpoint_alert_list`.
    ///
    /// List security alerts generated by Defender for Endpoint detection engines (process injection, ransomware behavior, credential dumping, etc.). Returns an OData collection of alert entities with title, severity, category, status, and affected machine ID. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Alert.Read.All application permission.
    async fn defender_endpoint_alert_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/alerts", &odata).await
    }

    /// Get a specific endpoint alert by ID.
    /// Former tool `defender_endpoint_alert_get`.
    ///
    /// Retrieve full details of a specific Defender for Endpoint alert by its alert identifier. Returns comprehensive alert properties, process execution trees, related file hashes, network connections, and remediation history. Pass the alert_id. Requires Alert.Read.All application permission.
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
    /// Former tool `defender_endpoint_machine_action_list`.
    ///
    /// List remote response actions executed on endpoint machines (e.g., isolate machine, collect investigation package, run antivirus scan, initiate live response). Returns an OData collection of machine action status entities. Supports OData query parameters: $filter, $top (default 50, max 10000), and $skip for offset pagination. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires Machine.Read.All application permission.
    async fn defender_endpoint_machine_action_list(
        &self,
        Parameters(params): Parameters<EndpointODataInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_endpoint_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::ep_odata(params.filter.as_deref(), params.top, params.skip);
        self.ep_odata_get("/api/machineactions", &odata).await
    }

    /// Get the status of a specific machine action by ID.
    /// Former tool `defender_endpoint_machine_action_get_status`.
    ///
    /// Retrieve the current execution status and result metadata for a specific remote machine action. Returns action status (Pending, InProgress, Succeeded, Failed, Cancelled), creation time, completion time, and error codes if applicable. Pass the action_id (GUID string). Requires Machine.Read.All application permission.
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
    /// Former tool `defender_xdr_alert_list`.
    ///
    /// List cross-workload security alerts from Microsoft Defender XDR via Microsoft Graph API (/security/alerts_v2), aggregating signals across Endpoint, Office 365, Identity, and Cloud Apps. Returns an OData collection of Alert v2 objects with provider detection source, MITRE ATT&CK techniques, and evidence entities. Supports OData query parameters: $filter, $top (default 50, max 1000), $skip for offset pagination, and $count. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires SecurityAlert.Read.All application permission.
    async fn defender_xdr_alert_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/alerts_v2", &odata).await
    }

    /// Get a specific XDR alert by ID.
    /// Former tool `defender_xdr_alert_get`.
    ///
    /// Retrieve full details of a specific Microsoft Defender XDR Alert v2 by its alert identifier. Returns comprehensive multi-stage detection details, involved user accounts, affected devices, cloud assets, and full evidence arrays. Pass the alert_id (e.g., da637578995287051192_756343937). Requires SecurityAlert.Read.All application permission.
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
    /// Former tool `defender_xdr_incident_list`.
    ///
    /// List consolidated security incidents from Microsoft Defender XDR via Microsoft Graph API (/security/incidents), correlating related alerts and evidence across attack chains. Returns an OData collection of incident objects with incident names, severity, classification, assigned owners, and summary metrics. Supports OData query parameters: $filter, $top (default 50, max 1000), $skip for offset pagination, $expand (e.g., $expand=alerts), and $count. Single page returned; raw @odata.nextLink is preserved for subsequent queries. Requires SecurityIncident.Read.All application permission.
    async fn defender_xdr_incident_list(
        &self,
        Parameters(params): Parameters<ODataListInput>,
    ) -> Result<CallToolResult, McpError> {
        validation::validate_odata_params(Some(params.top), Some(params.skip))?;
        let odata = Self::from_odata_list(&params);
        self.odata_get("/security/incidents", &odata).await
    }

    /// Get a specific XDR incident by ID.
    /// Former tool `defender_xdr_incident_get`.
    ///
    /// Retrieve full details of a specific Microsoft Defender XDR incident by its incident identifier. Returns full incident timeline, affected assets, determinations, tags, and optional expanded relationships. Pass the incident_id and optional expand parameter (e.g., expand='alerts' to include member alert objects). Requires SecurityIncident.Read.All application permission.
    async fn defender_xdr_incident_get(
        &self,
        Parameters(params): Parameters<XdrIncidentIdInput>,
    ) -> Result<CallToolResult, McpError> {
        let incident_id = validation::validate_required_id(&params.incident_id, "incident_id")?;
        let odata = ODataParams {
            expand: params.expand.as_deref(),
            ..ODataParams::default()
        };
        self.odata_get(
            &format!(
                "/security/incidents/{}",
                validation::encode_path_segment(incident_id)
            ),
            &odata,
        )
        .await
    }

    // ============================================================
    // 6.x Live Response (3 tools) — Gated
    // ============================================================

    /// Retrieve the downloadable result link for a specific live response command.
    /// Former tool `defender_endpoint_live_response_get_result`.
    ///
    /// Retrieve the temporary Shared Access Signature (SAS) download URL for the output or retrieved file generated by a specific Live Response command. Applicable to RunScript output logs and GetFile payload downloads (PutFile does not produce a download result). Pass the action_id returned from defender_endpoint_live_response_run and the zero-based command_index within the original session commands array (must be >= 0; negative indices are rejected locally). Gated operation: requires DEFENDER_ENABLE_LIVE_RESPONSE=true. Requires Machine.ReadWrite.All or Machine.LiveResponse application permission.
    async fn defender_endpoint_live_response_get_result(
        &self,
        Parameters(params): Parameters<LiveResponseResultInput>,
    ) -> Result<CallToolResult, McpError> {
        if !self.config.categories.live_response {
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
// Domain dispatchers
// ---------------------------------------------------------------------------

/// Deserialize dispatcher arguments into the action's typed input and invoke its private
/// handler, so every action keeps its validation rules and endpoint mapping.
macro_rules! call_action {
    ($self:ident, $method:ident, $args:expr) => {{
        let params = serde_json::from_value(serde_json::Value::Object($args)).map_err(|e| {
            crate::error::invalid_params(format!("invalid arguments for this action: {e}"))
        })?;
        $self.$method(Parameters(params)).await
    }};
}

/// Extract the SAS download URL from a Defender `{ "value": "<url>" }` response.
fn sas_url(value: &serde_json::Value) -> Result<String, CallToolResult> {
    value
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            crate::error::tool_error("upstream response did not contain a download URL in 'value'")
        })
}

impl DefenderServer {
    /// Fetch the investigation package SAS URL; a 404 while the action exists is reported as
    /// "package not ready" with the action's current status.
    async fn investigation_package_url(&self, action_id: &str) -> Result<String, CallToolResult> {
        let encoded = validation::encode_path_segment(action_id);
        match self
            .endpoint
            .endpoint_get(&format!("/api/machineactions/{encoded}/getPackageUri"), &[])
            .await
        {
            Ok(v) => sas_url(&v),
            Err(not_found) if http_status_of(&not_found) == Some(404) => {
                match self
                    .endpoint
                    .endpoint_get(&format!("/api/machineactions/{encoded}"), &[])
                    .await
                {
                    Ok(action) => {
                        let status = action
                            .get("status")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("Unknown");
                        Err(crate::error::package_not_ready(status))
                    }
                    // The action itself is unknown: surface the original 404.
                    Err(_) => Err(not_found),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Download `url` into the staging directory and return the artifact record.
    async fn stage_artifact(
        &self,
        url: &str,
        dir: &std::path::Path,
        file_name: &str,
        action_id: &str,
        sha1: Option<&str>,
    ) -> CallToolResult {
        match self
            .endpoint
            .download_artifact(
                url,
                dir,
                file_name,
                Some(action_id.to_owned()),
                sha1.map(str::to_owned),
            )
            .await
        {
            Ok(artifact) => {
                tracing::info!(
                    file_path = %artifact.file_path,
                    sha256 = %artifact.sha256,
                    bytes = artifact.file_size_bytes,
                    "Forensic artifact staged"
                );
                match serde_json::to_value(&artifact) {
                    Ok(v) => CallToolResult::structured(v),
                    Err(e) => crate::error::tool_error(format!("failed to encode artifact: {e}")),
                }
            }
            Err(e) => e,
        }
    }
    fn wrap_machine_action(resp: MutationResponse, warning: Option<&str>) -> MutationResponse {
        let action_id = resp
            .body
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut map = serde_json::Map::new();
        map.insert("machineAction".to_string(), resp.body);
        map.insert(
            "poll_with".to_string(),
            json!({
                "tool": "defender_forensics",
                "action": "machine_action_get_status",
                "action_id": action_id
            }),
        );
        if let Some(w) = warning {
            map.insert("warning".to_string(), json!(w));
        }
        MutationResponse {
            http_status: resp.http_status,
            body: Value::Object(map),
        }
    }

    fn wrap_investigation(resp: MutationResponse) -> MutationResponse {
        let inv_id = resp
            .body
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut map = serde_json::Map::new();
        map.insert("investigation".to_string(), resp.body);
        map.insert(
            "poll_with".to_string(),
            json!({
                "tool": "defender_forensics",
                "action": "investigation_get",
                "investigation_id": inv_id
            }),
        );
        MutationResponse {
            http_status: resp.http_status,
            body: Value::Object(map),
        }
    }
}

/// Parameters for executing a mutating tool action through the shared mutation pipeline.
///
/// Order of execution:
/// 1. Read-only barrier: rejects if `--read-only` is active.
/// 2. Category check: verifies tool category (and offboarding if applicable) is enabled.
/// 3. Validation check: inspects `validation_result` and enforces `justification` >= 10 chars.
/// 4. Human confirmation: if tool is destructive and confirmation is enabled, prompts human via MCP Form elicitation.
/// 5. Audit intent record: writes pre-network intent record (fail-closed: on error, fails before network).
/// 6. Single upstream request: executes the provided upstream closure exactly once (no retries).
/// 7. Audit outcome record: writes post-network outcome record.
pub struct MutationRequest<'a, F, Fut, T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<MutationResponse, CallToolResult>>,
    T: FnOnce(&MutationResponse) -> (Option<String>, Option<String>),
{
    pub tool: MutatingTool,
    pub action: &'a str,
    pub category: PermissionCategory,
    pub targets: Vec<AuditTarget>,
    pub parameters: serde_json::Map<String, Value>,
    pub justification: Option<&'a str>,
    pub validation_result: Result<(), CallToolResult>,
    pub context: &'a rmcp::service::RequestContext<rmcp::RoleServer>,
    pub extract_tracking: T,
    pub upstream: F,
}

impl DefenderServer {
    /// Executes a mutating action through the shared 7-stage mutation pipeline.
    pub async fn execute_mutation<F, Fut, T>(
        &self,
        req: MutationRequest<'_, F, Fut, T>,
    ) -> Result<CallToolResult, McpError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<MutationResponse, CallToolResult>>,
        T: FnOnce(&MutationResponse) -> (Option<String>, Option<String>),
    {
        let attempt_id = new_attempt_id();
        let identity = self.identity();

        let record_final = |reason: RejectReason, confirmation: ConfirmationOutcome| AuditRecord {
            ts: chrono::Utc::now(),
            attempt_id: attempt_id.clone(),
            phase: AuditPhase::Final,
            tool: req.tool.name().to_string(),
            action: req.action.to_string(),
            targets: req.targets.clone(),
            parameters: req.parameters.clone(),
            justification: req.justification.map(str::to_owned),
            identity: identity.clone(),
            confirmation,
            result: AuditResult::Rejected { reason },
        };

        // 1. Read-only check
        if self.config.read_only {
            let rec = record_final(RejectReason::ReadOnly, ConfirmationOutcome::NotApplicable);
            self.write_audit_record_best_effort(&rec).await;
            return Ok(crate::error::read_only_violation(req.tool.name()));
        }

        // 2. Category check (including offboarding)
        let tool_enabled = self.config.categories.tool_enabled(req.tool);
        let offboarding_disabled = req.action == "offboard" && !self.config.categories.offboarding;
        if !tool_enabled || offboarding_disabled {
            let flag = if offboarding_disabled {
                "--enable-offboarding"
            } else {
                req.tool.enable_flag()
            };
            let rec = record_final(
                RejectReason::CategoryDisabled,
                ConfirmationOutcome::NotApplicable,
            );
            self.write_audit_record_best_effort(&rec).await;
            return Ok(crate::error::category_disabled(flag));
        }

        // 3. Validation check
        if let Err(val_err) = req.validation_result {
            let rec = record_final(RejectReason::Validation, ConfirmationOutcome::NotApplicable);
            self.write_audit_record_best_effort(&rec).await;
            return Ok(val_err);
        }

        let justification = match req.justification.map(str::trim) {
            Some(j) if j.chars().count() >= crate::constants::MIN_JUSTIFICATION_LEN => j,
            _ => {
                let rec =
                    record_final(RejectReason::Validation, ConfirmationOutcome::NotApplicable);
                self.write_audit_record_best_effort(&rec).await;
                let field_name = if req.tool == MutatingTool::Triage {
                    "justification"
                } else {
                    "comment"
                };
                return Ok(crate::error::tool_error(format!(
                    "{field_name} must be at least {} characters describing the purpose",
                    crate::constants::MIN_JUSTIFICATION_LEN
                )));
            }
        };

        // 4. Confirmation
        let confirmation_outcome = if req.tool.destructive() && self.config.confirm_destructive {
            let outcome = crate::confirm::request_confirmation(
                &req.context.peer,
                req.tool.name(),
                req.action,
                &req.parameters,
                &req.targets,
                justification,
                &identity,
            )
            .await;

            match outcome {
                ConfirmationOutcome::Accepted => ConfirmationOutcome::Accepted,
                ConfirmationOutcome::Unavailable => {
                    let rec = record_final(
                        RejectReason::ConfirmationUnavailable,
                        ConfirmationOutcome::Unavailable,
                    );
                    self.write_audit_record_best_effort(&rec).await;
                    return Ok(crate::error::confirmation_unavailable());
                }
                _ => {
                    let rec = AuditRecord {
                        ts: chrono::Utc::now(),
                        attempt_id: attempt_id.clone(),
                        phase: AuditPhase::Final,
                        tool: req.tool.name().to_string(),
                        action: req.action.to_string(),
                        targets: req.targets.clone(),
                        parameters: req.parameters.clone(),
                        justification: Some(justification.to_string()),
                        identity: identity.clone(),
                        confirmation: ConfirmationOutcome::Declined,
                        result: AuditResult::Declined,
                    };
                    self.write_audit_record_best_effort(&rec).await;
                    return Ok(crate::error::not_confirmed());
                }
            }
        } else if req.tool.destructive() {
            ConfirmationOutcome::TurnedOff
        } else {
            ConfirmationOutcome::NotApplicable
        };

        // 5. Intent record
        let intent_record = AuditRecord {
            ts: chrono::Utc::now(),
            attempt_id: attempt_id.clone(),
            phase: AuditPhase::Intent,
            tool: req.tool.name().to_string(),
            action: req.action.to_string(),
            targets: req.targets.clone(),
            parameters: req.parameters.clone(),
            justification: Some(justification.to_string()),
            identity: identity.clone(),
            confirmation: confirmation_outcome,
            result: AuditResult::Pending,
        };

        let Some(sink) = &self.audit_sink else {
            let rec = record_final(RejectReason::AuditUnavailable, confirmation_outcome);
            rec.print_stderr_summary();
            return Ok(crate::error::audit_unavailable());
        };

        if let Err(e) = sink.append(&intent_record).await {
            tracing::error!(error = %e, "Failed to write audit intent record");
            let rec = record_final(RejectReason::AuditUnavailable, confirmation_outcome);
            self.write_audit_record_best_effort(&rec).await;
            return Ok(crate::error::audit_unavailable());
        }

        // 6. Upstream request (exactly once, no retry)
        let upstream_res = (req.upstream)().await;

        // 7. Outcome record
        let (audit_result, tool_result) = match upstream_res {
            Ok(resp) => {
                let (tracking_id, upstream_status) = (req.extract_tracking)(&resp);
                let audit_res = AuditResult::Submitted {
                    http_status: resp.http_status,
                    tracking_id,
                    upstream_status,
                };
                let tool_res = CallToolResult::structured(resp.body);
                (audit_res, Ok(tool_res))
            }
            Err(err) => {
                let status_opt = http_status_of(&err);
                let msg = err
                    .content
                    .first()
                    .and_then(|c| c.as_text())
                    .map(|t| t.text.clone())
                    .unwrap_or_else(|| "upstream error".to_string());
                let audit_res = match status_opt {
                    Some(status) => AuditResult::UpstreamError {
                        http_status: status as u16,
                        message: msg,
                    },
                    None => AuditResult::TransportError { message: msg },
                };
                (audit_res, Ok(err))
            }
        };

        let outcome_record = AuditRecord {
            ts: chrono::Utc::now(),
            attempt_id: attempt_id.clone(),
            phase: AuditPhase::Outcome,
            tool: req.tool.name().to_string(),
            action: req.action.to_string(),
            targets: req.targets,
            parameters: req.parameters,
            justification: Some(justification.to_string()),
            identity: identity.clone(),
            confirmation: confirmation_outcome,
            result: audit_result,
        };

        if let Some(sink) = &self.audit_sink
            && let Err(e) = sink.append(&outcome_record).await
        {
            eprintln!(
                "AUDIT ERROR: failed to write outcome audit record for attempt {attempt_id}: {e}"
            );
        }

        tool_result
    }

    /// Best effort write of an audit record to the sink if present; logs to stderr if failed.
    async fn write_audit_record_best_effort(&self, record: &AuditRecord) {
        if let Some(sink) = &self.audit_sink
            && let Err(e) = sink.append(record).await
        {
            eprintln!("AUDIT ERROR: failed to append audit record: {e}");
        }
    }

    /// Audit a protocol-level error raised while validating a known mutating action (for
    /// example a missing required field) as a `final` validation rejection, and return it as a
    /// tool error. Every rejection of a known action thus leaves one audit record and makes no
    /// upstream request. Successful results pass through unchanged.
    async fn audit_validation_error(
        &self,
        tool: MutatingTool,
        action: &str,
        category: PermissionCategory,
        justification: Option<&str>,
        context: &rmcp::service::RequestContext<rmcp::RoleServer>,
        result: Result<CallToolResult, McpError>,
    ) -> Result<CallToolResult, McpError> {
        let Err(err) = result else {
            return result;
        };
        self.execute_mutation(MutationRequest {
            tool,
            action,
            category,
            targets: Vec::new(),
            parameters: serde_json::Map::new(),
            justification,
            validation_result: Err(crate::error::tool_error(err.message)),
            context,
            extract_tracking: |_| (None, None),
            upstream: || async {
                Err(crate::error::tool_error(
                    "internal error: upstream called after a validation failure",
                ))
            },
        })
        .await
    }
}

#[tool_router(router = consolidated_tool_router)]
impl DefenderServer {
    /// Consolidated Advanced Hunting dispatcher.
    #[tool(
        name = "defender_hunting",
        description = "Run a read-only KQL query across Microsoft Defender XDR advanced hunting tables \
                       (DeviceProcessEvents, DeviceNetworkEvents, EmailEvents, IdentityLogonEvents, etc.). \
                       action: 'run' (default). Params: query (required), timespan (ISO 8601, default P30D). \
                       Upstream limits: 100,000 rows, 50 MB, ~3-minute timeout. Requires \
                       ThreatHunting.Read.All.",
        annotations(
            title = "Defender Hunting",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn defender_hunting(
        &self,
        Parameters(input): Parameters<HuntingInput>,
    ) -> Result<CallToolResult, McpError> {
        if input.action != "run" {
            return Err(crate::error::unknown_action_error(
                "defender_hunting",
                &input.action,
                HUNTING_ACTIONS,
            ));
        }
        call_action!(self, defender_advanced_hunting_run, action_args(&input))
    }

    /// Consolidated threat-intelligence dispatcher.
    #[tool(
        name = "defender_ti",
        description = "Microsoft Defender Threat Intelligence lookups (read-only). Actions: \
                       intel_profiles_list, intel_profile_get, intel_profile_indicators_list, \
                       intel_profile_indicator_get, intel_profile_indicators_global_list, articles_list, \
                       article_get, article_indicators_list, article_indicator_get, \
                       article_indicators_global_list, host_get, host_reputation_get, host_components_list, \
                       host_component_get, host_cookies_list, host_cookie_get, host_ports_list, host_port_get, \
                       host_trackers_list, host_tracker_get, host_subdomains_list, host_ssl_certs_list, \
                       host_whois_get, host_whois_history_list, host_pairs_list, host_pair_get, \
                       host_child_pairs_list, host_parent_pairs_list, host_passive_dns_list, \
                       host_passive_dns_reverse_list, ssl_certs_list, ssl_cert_get, ssl_cert_related_hosts_list, \
                       whois_records_list, whois_record_get, passive_dns_get, vulnerability_get, \
                       vulnerability_components_list, vulnerability_component_get, custom_indicator_list. host_* list/get-by-host \
                       actions take hostname (domain or IP literal); *_get actions take id (opaque IDs copied \
                       verbatim; CVE ID for vulnerability_*); vulnerability_component_get also takes \
                       component_id. Lists accept top (max 1000; custom_indicator_list max 10000, default 50), skip, and, where the endpoint supports them, \
                       filter, select, expand, search, count. Unsupported fields are rejected. Requires \
                       ThreatIntelligence.Read.All and a Defender TI license (custom_indicator_list requires Ti.ReadWrite).",
        annotations(
            title = "Defender Threat Intelligence",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn defender_ti(
        &self,
        Parameters(input): Parameters<ThreatIntelInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        if let Some(blocked) = self.check_scope_not_requested(action) {
            return Ok(blocked);
        }
        let mut args = action_args(&input);
        let host_by_name = action.starts_with("host_")
            && !matches!(
                action,
                "host_component_get"
                    | "host_cookie_get"
                    | "host_port_get"
                    | "host_tracker_get"
                    | "host_pair_get"
            );
        if host_by_name {
            rename_arg(&mut args, "id", "hostname");
        }
        if action.starts_with("vulnerability_") {
            rename_arg(&mut args, "id", "vulnerability_id");
        }
        match action {
            "intel_profiles_list" => call_action!(self, defender_ti_intel_profiles_list, args),
            "intel_profile_get" => call_action!(self, defender_ti_intel_profile_get, args),
            "intel_profile_indicators_list" => {
                call_action!(self, defender_ti_intel_profile_indicators_list, args)
            }
            "intel_profile_indicator_get" => {
                call_action!(self, defender_ti_intel_profile_indicator_get, args)
            }
            "intel_profile_indicators_global_list" => {
                call_action!(self, defender_ti_intel_profile_indicators_global_list, args)
            }
            "articles_list" => call_action!(self, defender_ti_articles_list, args),
            "article_get" => call_action!(self, defender_ti_article_get, args),
            "article_indicators_list" => {
                call_action!(self, defender_ti_article_indicators_list, args)
            }
            "article_indicator_get" => {
                call_action!(self, defender_ti_article_indicator_get, args)
            }
            "article_indicators_global_list" => {
                call_action!(self, defender_ti_article_indicators_global_list, args)
            }
            "host_get" => call_action!(self, defender_ti_host_get, args),
            "host_reputation_get" => call_action!(self, defender_ti_host_reputation_get, args),
            "host_components_list" => call_action!(self, defender_ti_host_components_list, args),
            "host_component_get" => call_action!(self, defender_ti_host_component_get, args),
            "host_cookies_list" => call_action!(self, defender_ti_host_cookies_list, args),
            "host_cookie_get" => call_action!(self, defender_ti_host_cookie_get, args),
            "host_ports_list" => call_action!(self, defender_ti_host_ports_list, args),
            "host_port_get" => call_action!(self, defender_ti_host_port_get, args),
            "host_trackers_list" => call_action!(self, defender_ti_host_trackers_list, args),
            "host_tracker_get" => call_action!(self, defender_ti_host_tracker_get, args),
            "host_subdomains_list" => call_action!(self, defender_ti_host_subdomains_list, args),
            "host_ssl_certs_list" => call_action!(self, defender_ti_host_ssl_certs_list, args),
            "host_whois_get" => call_action!(self, defender_ti_host_whois_get, args),
            "host_whois_history_list" => {
                call_action!(self, defender_ti_host_whois_history_list, args)
            }
            "host_pairs_list" => call_action!(self, defender_ti_host_pairs_list, args),
            "host_pair_get" => call_action!(self, defender_ti_host_pair_get, args),
            "host_child_pairs_list" => {
                call_action!(self, defender_ti_host_child_pairs_list, args)
            }
            "host_parent_pairs_list" => {
                call_action!(self, defender_ti_host_parent_pairs_list, args)
            }
            "host_passive_dns_list" => {
                call_action!(self, defender_ti_host_passive_dns_list, args)
            }
            "host_passive_dns_reverse_list" => {
                call_action!(self, defender_ti_host_passive_dns_reverse_list, args)
            }
            "ssl_certs_list" => call_action!(self, defender_ti_ssl_certs_list, args),
            "ssl_cert_get" => call_action!(self, defender_ti_ssl_cert_get, args),
            "ssl_cert_related_hosts_list" => {
                call_action!(self, defender_ti_ssl_cert_related_hosts_list, args)
            }
            "whois_records_list" => call_action!(self, defender_ti_whois_records_list, args),
            "whois_record_get" => call_action!(self, defender_ti_whois_record_get, args),
            "passive_dns_get" => call_action!(self, defender_ti_passive_dns_get, args),
            "vulnerability_get" => call_action!(self, defender_ti_vulnerability_get, args),
            "vulnerability_components_list" => {
                call_action!(self, defender_ti_vulnerability_components_list, args)
            }
            "vulnerability_component_get" => {
                call_action!(self, defender_ti_vulnerability_component_get, args)
            }
            "custom_indicator_list" => {
                if input.id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'id' is not used by action 'custom_indicator_list'",
                    ));
                }
                if input.hostname.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'hostname' is not used by action 'custom_indicator_list'",
                    ));
                }
                if input.component_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'component_id' is not used by action 'custom_indicator_list'",
                    ));
                }
                if input.select.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'select' is not used by action 'custom_indicator_list'",
                    ));
                }
                if input.expand.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'expand' is not used by action 'custom_indicator_list'",
                    ));
                }
                if input.search.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'search' is not used by action 'custom_indicator_list'",
                    ));
                }
                if input.count.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'count' is not used by action 'custom_indicator_list'",
                    ));
                }
                validation::validate_endpoint_odata_params(input.top, input.skip)?;
                let odata = Self::ep_odata(
                    input.filter.as_deref(),
                    input.top.unwrap_or(DEFAULT_TOP),
                    input.skip.unwrap_or(0),
                );
                self.ep_odata_get_as("/api/indicators", &odata, PermissionCategory::Indicators)
                    .await
            }
            _ => Err(crate::error::unknown_action_error(
                "defender_ti",
                action,
                TI_ACTIONS,
            )),
        }
    }

    /// Consolidated incident and alert dispatcher.
    #[tool(
        name = "defender_incidents_alerts",
        description = "Defender XDR incidents/alerts and Defender for Endpoint alerts (read-only). Actions: \
                       xdr_alert_list, xdr_alert_get, xdr_incident_list, xdr_incident_get, endpoint_alert_list, \
                       endpoint_alert_get, ip_related_alerts, domain_related_alerts, file_related_alerts, \
                       user_related_alerts. *_get actions take id; *_related_alerts take id as the IP, domain, \
                       SHA-1, or username (not UPN/SID). XDR lists accept top (max 1000), skip, filter, select, \
                       expand, search, count (count=true sends $count=true); endpoint_alert_list accepts \
                       filter, top (max 10000), skip; xdr_incident_get accepts expand. Requires \
                       SecurityAlert.Read.All / SecurityIncident.Read.All (XDR) or Alert.Read.All (endpoint; \
                       file_related_alerts needs Alert.ReadWrite.All).",
        annotations(
            title = "Defender Incidents & Alerts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn defender_incidents_alerts(
        &self,
        Parameters(input): Parameters<IncidentsAlertsInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        if let Some(blocked) = self.check_scope_not_requested(action) {
            return Ok(blocked);
        }
        let mut args = action_args(&input);
        match action {
            "xdr_alert_list" => call_action!(self, defender_xdr_alert_list, args),
            "xdr_alert_get" => call_action!(self, defender_xdr_alert_get, args),
            "xdr_incident_list" => call_action!(self, defender_xdr_incident_list, args),
            "xdr_incident_get" => call_action!(self, defender_xdr_incident_get, args),
            "endpoint_alert_list" => call_action!(self, defender_endpoint_alert_list, args),
            "endpoint_alert_get" => call_action!(self, defender_endpoint_alert_get, args),
            "ip_related_alerts" => {
                rename_arg(&mut args, "id", "ip_address");
                call_action!(self, defender_endpoint_ip_related_alerts, args)
            }
            "domain_related_alerts" => {
                rename_arg(&mut args, "id", "domain_name");
                call_action!(self, defender_endpoint_domain_related_alerts, args)
            }
            "file_related_alerts" => {
                rename_arg(&mut args, "id", "file_sha1");
                call_action!(self, defender_endpoint_file_related_alerts, args)
            }
            "user_related_alerts" => {
                rename_arg(&mut args, "id", "user_id");
                call_action!(self, defender_endpoint_user_related_alerts, args)
            }
            _ => Err(crate::error::unknown_action_error(
                "defender_incidents_alerts",
                action,
                INCIDENTS_ALERTS_ACTIONS,
            )),
        }
    }

    /// Consolidated device inventory and indicator-correlation dispatcher.
    #[tool(
        name = "defender_machines",
        description = "Defender for Endpoint device inventory and indicator correlation (read-only). Actions: \
                       machine_list, machine_get, logged_on_users, find_by_tag, installed_software, \
                       security_recommendations, ip_statistics, domain_statistics, domain_related_machines, \
                       file_get, file_statistics, file_related_machines, user_related_machines, \
                       find_by_ip, machine_alerts, machine_vulnerabilities, machine_missing_kbs. Device actions \
                       take machine_id (40-hex Defender machine ID, not an Entra device ID). Indicator actions \
                       take id: IP (ip_statistics, find_by_ip with timestamp RFC 3339 <= 30 days old), domain (domain_*), MD5/SHA-1/SHA-256 (file_get), SHA-1 \
                       (file_statistics, file_related_machines), username (user_related_machines). find_by_tag \
                       takes tag_name (or id) and use_starts_with. *_statistics accept look_back_hours (1-720). \
                       machine_list, machine_alerts, machine_vulnerabilities accept filter, top (max 10000), skip. Requires Machine.Read.All (related \
                       machines, find_by_ip need Machine.ReadWrite.All; machine_alerts needs Alert.ReadWrite.All), Software.Read.All, SecurityRecommendation.Read.All, \
                       Ip.Read.All, Url.Read.All, File.Read.All as applicable.",
        annotations(
            title = "Defender Machines",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn defender_machines(
        &self,
        Parameters(input): Parameters<MachinesInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        if let Some(blocked) = self.check_scope_not_requested(action) {
            return Ok(blocked);
        }
        let mut args = action_args(&input);
        match action {
            "machine_list" => call_action!(self, defender_endpoint_machine_list, args),
            "machine_get" => call_action!(self, defender_endpoint_machine_get, args),
            "logged_on_users" => {
                call_action!(self, defender_endpoint_machine_logged_on_users, args)
            }
            "find_by_tag" => {
                rename_arg(&mut args, "id", "tag_name");
                call_action!(self, defender_endpoint_machine_find_by_tag, args)
            }
            "installed_software" => {
                call_action!(self, defender_endpoint_machine_list_software, args)
            }
            "security_recommendations" => {
                call_action!(
                    self,
                    defender_endpoint_machine_security_recommendations,
                    args
                )
            }
            "ip_statistics" => {
                rename_arg(&mut args, "id", "ip_address");
                call_action!(self, defender_endpoint_ip_statistics, args)
            }
            "domain_statistics" => {
                rename_arg(&mut args, "id", "domain_name");
                call_action!(self, defender_endpoint_domain_statistics, args)
            }
            "domain_related_machines" => {
                rename_arg(&mut args, "id", "domain_name");
                call_action!(self, defender_endpoint_domain_related_machines, args)
            }
            "file_get" => {
                rename_arg(&mut args, "id", "file_id");
                call_action!(self, defender_endpoint_file_get, args)
            }
            "file_statistics" => {
                rename_arg(&mut args, "id", "file_sha1");
                call_action!(self, defender_endpoint_file_statistics, args)
            }
            "file_related_machines" => {
                rename_arg(&mut args, "id", "file_sha1");
                call_action!(self, defender_endpoint_file_related_machines, args)
            }
            "user_related_machines" => {
                rename_arg(&mut args, "id", "user_id");
                call_action!(self, defender_endpoint_user_related_machines, args)
            }
            "find_by_ip" => {
                if input.machine_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'machine_id' is not used by action 'find_by_ip'",
                    ));
                }
                if input.tag_name.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'tag_name' is not used by action 'find_by_ip'",
                    ));
                }
                if input.use_starts_with.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'use_starts_with' is not used by action 'find_by_ip'",
                    ));
                }
                if input.look_back_hours.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'look_back_hours' is not used by action 'find_by_ip'",
                    ));
                }
                if input.top.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'top' is not used by action 'find_by_ip'",
                    ));
                }
                if input.skip.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'skip' is not used by action 'find_by_ip'",
                    ));
                }
                if input.filter.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'filter' is not used by action 'find_by_ip'",
                    ));
                }
                let ip = required(&input.id, "id", action)?;
                let validated_ip = validation::validate_ip_address(ip)?;
                let ts = required(&input.timestamp, "timestamp", action)?;
                let normalized_ts = validation::validate_recent_timestamp(
                    ts,
                    crate::constants::FIND_BY_IP_MAX_AGE_DAYS,
                )?;
                let path = format!(
                    "/api/machines/findbyip(ip='{validated_ip}',timestamp={normalized_ts})"
                );
                self.ep_simple_get_as(&path, PermissionCategory::ReadWriteNamed)
                    .await
            }
            "machine_alerts" => {
                if input.timestamp.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'timestamp' is not used by action 'machine_alerts'",
                    ));
                }
                if input.tag_name.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'tag_name' is not used by action 'machine_alerts'",
                    ));
                }
                if input.use_starts_with.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'use_starts_with' is not used by action 'machine_alerts'",
                    ));
                }
                if input.look_back_hours.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'look_back_hours' is not used by action 'machine_alerts'",
                    ));
                }
                let m_id = input
                    .machine_id
                    .as_deref()
                    .or(input.id.as_deref())
                    .ok_or_else(|| {
                        crate::error::invalid_params(
                            "action 'machine_alerts' requires 'machine_id'",
                        )
                    })?;
                let validated_m_id = validation::validate_machine_id(m_id)?;
                validation::validate_endpoint_odata_params(input.top, input.skip)?;
                let odata = Self::ep_odata(
                    input.filter.as_deref(),
                    input.top.unwrap_or(DEFAULT_TOP),
                    input.skip.unwrap_or(0),
                );
                let path = format!(
                    "/api/machines/{}/alerts",
                    validation::encode_path_segment(validated_m_id)
                );
                self.ep_odata_get_as(&path, &odata, PermissionCategory::ReadWriteNamed)
                    .await
            }
            "machine_vulnerabilities" => {
                if input.timestamp.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'timestamp' is not used by action 'machine_vulnerabilities'",
                    ));
                }
                if input.tag_name.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'tag_name' is not used by action 'machine_vulnerabilities'",
                    ));
                }
                if input.use_starts_with.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'use_starts_with' is not used by action 'machine_vulnerabilities'",
                    ));
                }
                if input.look_back_hours.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'look_back_hours' is not used by action 'machine_vulnerabilities'",
                    ));
                }
                let m_id = input
                    .machine_id
                    .as_deref()
                    .or(input.id.as_deref())
                    .ok_or_else(|| {
                        crate::error::invalid_params(
                            "action 'machine_vulnerabilities' requires 'machine_id'",
                        )
                    })?;
                let validated_m_id = validation::validate_machine_id(m_id)?;
                validation::validate_endpoint_odata_params(input.top, input.skip)?;
                let odata = Self::ep_odata(
                    input.filter.as_deref(),
                    input.top.unwrap_or(DEFAULT_TOP),
                    input.skip.unwrap_or(0),
                );
                let path = format!(
                    "/api/machines/{}/vulnerabilities",
                    validation::encode_path_segment(validated_m_id)
                );
                self.ep_odata_get_as(&path, &odata, PermissionCategory::ReadEndpoint)
                    .await
            }
            "machine_missing_kbs" => {
                if input.timestamp.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'timestamp' is not used by action 'machine_missing_kbs'",
                    ));
                }
                if input.tag_name.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'tag_name' is not used by action 'machine_missing_kbs'",
                    ));
                }
                if input.use_starts_with.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'use_starts_with' is not used by action 'machine_missing_kbs'",
                    ));
                }
                if input.look_back_hours.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'look_back_hours' is not used by action 'machine_missing_kbs'",
                    ));
                }
                if input.top.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'top' is not used by action 'machine_missing_kbs'",
                    ));
                }
                if input.skip.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'skip' is not used by action 'machine_missing_kbs'",
                    ));
                }
                if input.filter.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'filter' is not used by action 'machine_missing_kbs'",
                    ));
                }
                let m_id = input
                    .machine_id
                    .as_deref()
                    .or(input.id.as_deref())
                    .ok_or_else(|| {
                        crate::error::invalid_params(
                            "action 'machine_missing_kbs' requires 'machine_id'",
                        )
                    })?;
                let validated_m_id = validation::validate_machine_id(m_id)?;
                let path = format!(
                    "/api/machines/{}/getmissingkbs",
                    validation::encode_path_segment(validated_m_id)
                );
                self.ep_simple_get_as(&path, PermissionCategory::ReadEndpoint)
                    .await
            }
            _ => Err(crate::error::unknown_action_error(
                "defender_machines",
                action,
                MACHINES_ACTIONS,
            )),
        }
    }

    /// Consolidated vulnerability-management dispatcher.
    #[tool(
        name = "defender_vulnerabilities",
        description = "Defender Vulnerability Management (read-only). Actions: software_list, software_get, \
                       software_machines, software_vulnerabilities, software_missing_kbs, software_distribution, \
                       vulnerability_list, vulnerability_get_by_cve, vulnerability_get_machines, \
                       vulnerability_get_by_machine_software, recommendation_list, recommendation_get, \
                       recommendation_machines, recommendation_vulnerabilities, recommendation_by_software, \
                       remediation_list, remediation_get, remediation_exposed_devices, exposure_score, \
                       exposure_score_by_machine_groups. software_* take id or software_id; vulnerability_* take \
                       id or cve_id; recommendation_*/remediation_* take id. Lists accept filter, top (max \
                       10000), skip. Requires Software.Read.All, Vulnerability.Read.All, \
                       SecurityRecommendation.Read.All, RemediationTasks.Read.All, or Score.Read.All as \
                       applicable.",
        annotations(
            title = "Defender Vulnerabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn defender_vulnerabilities(
        &self,
        Parameters(input): Parameters<VulnerabilitiesInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        let mut args = action_args(&input);
        if action.starts_with("software_") {
            rename_arg(&mut args, "id", "software_id");
        }
        if action.starts_with("vulnerability_get") {
            rename_arg(&mut args, "id", "cve_id");
        }
        match action {
            "software_list" => call_action!(self, defender_endpoint_software_list, args),
            "software_get" => call_action!(self, defender_endpoint_software_get, args),
            "software_machines" => call_action!(self, defender_endpoint_software_machines, args),
            "software_vulnerabilities" => {
                call_action!(self, defender_endpoint_software_vulnerabilities, args)
            }
            "software_missing_kbs" => {
                call_action!(self, defender_endpoint_software_missing_kbs, args)
            }
            "software_distribution" => {
                call_action!(self, defender_endpoint_software_distribution, args)
            }
            "vulnerability_list" => {
                call_action!(self, defender_endpoint_vulnerability_list, args)
            }
            "vulnerability_get_by_cve" => {
                call_action!(self, defender_endpoint_vulnerability_get_by_cve, args)
            }
            "vulnerability_get_machines" => {
                call_action!(self, defender_endpoint_vulnerability_get_machines, args)
            }
            "vulnerability_get_by_machine_software" => {
                call_action!(
                    self,
                    defender_endpoint_vulnerability_get_by_machine_software,
                    args
                )
            }
            "recommendation_list" => {
                call_action!(self, defender_endpoint_recommendation_list, args)
            }
            "recommendation_get" => {
                call_action!(self, defender_endpoint_recommendation_get, args)
            }
            "recommendation_machines" => {
                call_action!(self, defender_endpoint_recommendation_machines, args)
            }
            "recommendation_vulnerabilities" => {
                call_action!(self, defender_endpoint_recommendation_vulnerabilities, args)
            }
            "recommendation_by_software" => {
                call_action!(self, defender_endpoint_recommendation_by_software, args)
            }
            "remediation_list" => call_action!(self, defender_endpoint_remediation_list, args),
            "remediation_get" => call_action!(self, defender_endpoint_remediation_get, args),
            "remediation_exposed_devices" => {
                call_action!(self, defender_endpoint_remediation_exposed_devices, args)
            }
            "exposure_score" | "exposure_score_by_machine_groups" => {
                if !args.is_empty() {
                    return Err(crate::error::invalid_params(format!(
                        "action '{action}' takes no parameters"
                    )));
                }
                if action == "exposure_score" {
                    self.defender_endpoint_exposure_score().await
                } else {
                    self.defender_endpoint_exposure_score_by_machine_groups()
                        .await
                }
            }
            _ => Err(crate::error::unknown_action_error(
                "defender_vulnerabilities",
                action,
                VULNERABILITIES_ACTIONS,
            )),
        }
    }

    /// Consolidated forensic retrieval dispatcher.
    #[tool(
        name = "defender_forensics",
        description = "Forensic artifact inspection and retrieval; never changes endpoint or tenant state. \
                       Actions: machine_action_list (filter, top, skip), machine_action_get_status (action_id), \
                       get_investigation_package_sas_url (action_id; short-lived SAS URL), \
                       download_investigation_package (action_id), download_quarantined_file (action_id of a \
                       completed Live Response GetFile action, command_index default 0, optional sha1 used to \
                       name the archive), live_response_get_result (action_id, command_index; requires Live \
                       Response enabled), investigation_list (filter, top, skip), investigation_get (investigation_id), \
                       library_file_list. Download actions stream the archive into the server's quarantine \
                       directory (or a relative destination_dir inside it) with 0600 file permissions and \
                       return file_path, file_size_bytes, and sha256; files are never executed. If a package \
                       is not ready, the current action status is returned; retry once it is Succeeded. \
                       getPackageUri is limited to 2 calls/minute. Requires Machine.Read.All for action \
                       status/listing and Machine.ReadWrite.All for package and Live Response result links \
                       (investigation_* need Alert.ReadWrite, library_file_list needs Library.Manage).",
        annotations(
            title = "Defender Forensics",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub async fn defender_forensics(
        &self,
        Parameters(input): Parameters<ForensicsInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        if let Some(blocked) = self.check_scope_not_requested(action) {
            return Ok(blocked);
        }
        match action {
            "machine_action_list" => {
                call_action!(
                    self,
                    defender_endpoint_machine_action_list,
                    action_args(&input)
                )
            }
            "machine_action_get_status" => {
                call_action!(
                    self,
                    defender_endpoint_machine_action_get_status,
                    action_args(&input)
                )
            }
            "live_response_get_result" => {
                call_action!(
                    self,
                    defender_endpoint_live_response_get_result,
                    action_args(&input)
                )
            }
            "get_investigation_package_sas_url" => {
                let action_id = validation::validate_action_id(required(
                    &input.action_id,
                    "action_id",
                    action,
                )?)?;
                Ok(match self.investigation_package_url(action_id).await {
                    Ok(url) => CallToolResult::structured(json!({
                        "action_id": action_id,
                        "value": url,
                    })),
                    Err(e) => e,
                })
            }
            "download_investigation_package" => {
                let action_id = validation::validate_action_id(required(
                    &input.action_id,
                    "action_id",
                    action,
                )?)?;
                let dir = self.staging_dir(input.destination_dir.as_deref())?;
                let url = match self.investigation_package_url(action_id).await {
                    Ok(url) => url,
                    Err(e) => return Ok(e),
                };
                let file_name = format!("investigation_package_{action_id}.zip");
                Ok(self
                    .stage_artifact(&url, &dir, &file_name, action_id, None)
                    .await)
            }
            "download_quarantined_file" => {
                let action_id = validation::validate_action_id(required(
                    &input.action_id,
                    "action_id",
                    action,
                )?)?;
                let index = input.command_index.unwrap_or(0);
                if index < 0 {
                    return Err(crate::error::invalid_params(format!(
                        "command_index must be zero or greater, got {index}"
                    )));
                }
                let sha1 = input
                    .sha1
                    .as_deref()
                    .map(validation::validate_sha1)
                    .transpose()?
                    .map(str::to_ascii_lowercase);
                let dir = self.staging_dir(input.destination_dir.as_deref())?;
                let link = match self
                    .endpoint
                    .endpoint_get(
                        &format!(
                            "/api/machineactions/{}/GetLiveResponseResultDownloadLink(index={index})",
                            validation::encode_path_segment(action_id)
                        ),
                        &[],
                    )
                    .await
                {
                    Ok(v) => v,
                    Err(e) => return Ok(e),
                };
                let url = match sas_url(&link) {
                    Ok(url) => url,
                    Err(e) => return Ok(e),
                };
                let file_name = match &sha1 {
                    Some(sha1) => format!("quarantine_{sha1}.zip"),
                    None => format!("quarantine_{action_id}_{index}.zip"),
                };
                Ok(self
                    .stage_artifact(&url, &dir, &file_name, action_id, sha1.as_deref())
                    .await)
            }
            "investigation_list" => {
                if input.action_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'action_id' is not used by action 'investigation_list'",
                    ));
                }
                if input.sha1.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'sha1' is not used by action 'investigation_list'",
                    ));
                }
                if input.command_index.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'command_index' is not used by action 'investigation_list'",
                    ));
                }
                if input.destination_dir.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'destination_dir' is not used by action 'investigation_list'",
                    ));
                }
                if input.investigation_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'investigation_id' is not used by action 'investigation_list'",
                    ));
                }
                validation::validate_endpoint_odata_params(input.top, input.skip)?;
                let odata = Self::ep_odata(
                    input.filter.as_deref(),
                    input.top.unwrap_or(DEFAULT_TOP),
                    input.skip.unwrap_or(0),
                );
                self.ep_odata_get_as(
                    "/api/investigations",
                    &odata,
                    PermissionCategory::ReadWriteNamed,
                )
                .await
            }
            "investigation_get" => {
                if input.action_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'action_id' is not used by action 'investigation_get'",
                    ));
                }
                if input.sha1.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'sha1' is not used by action 'investigation_get'",
                    ));
                }
                if input.command_index.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'command_index' is not used by action 'investigation_get'",
                    ));
                }
                if input.destination_dir.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'destination_dir' is not used by action 'investigation_get'",
                    ));
                }
                if input.top.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'top' is not used by action 'investigation_get'",
                    ));
                }
                if input.skip.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'skip' is not used by action 'investigation_get'",
                    ));
                }
                if input.filter.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'filter' is not used by action 'investigation_get'",
                    ));
                }
                let id = required(&input.investigation_id, "investigation_id", action)?;
                let validated_id = validation::validate_required_id(id, "investigation_id")?;
                let encoded_id = validation::encode_path_segment(validated_id);
                self.ep_simple_get_as(
                    &format!("/api/investigations/{encoded_id}"),
                    PermissionCategory::ReadWriteNamed,
                )
                .await
            }
            "library_file_list" => {
                if input.action_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'action_id' is not used by action 'library_file_list'",
                    ));
                }
                if input.sha1.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'sha1' is not used by action 'library_file_list'",
                    ));
                }
                if input.command_index.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'command_index' is not used by action 'library_file_list'",
                    ));
                }
                if input.destination_dir.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'destination_dir' is not used by action 'library_file_list'",
                    ));
                }
                if input.investigation_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'investigation_id' is not used by action 'library_file_list'",
                    ));
                }
                if input.top.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'top' is not used by action 'library_file_list'",
                    ));
                }
                if input.skip.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'skip' is not used by action 'library_file_list'",
                    ));
                }
                if input.filter.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'filter' is not used by action 'library_file_list'",
                    ));
                }
                self.ep_simple_get_as("/api/libraryfiles", PermissionCategory::ReadWriteNamed)
                    .await
            }
            _ => Err(crate::error::unknown_action_error(
                "defender_forensics",
                action,
                FORENSICS_ACTIONS,
            )),
        }
    }

    /// Consolidated mutating response dispatcher (gated).
    #[tool(
        name = "defender_response",
        description = "Mutating endpoint response actions; obtain explicit human approval before calling. \
                       Disabled unless the server starts with --enable-live-response \
                       (DEFENDER_ENABLE_LIVE_RESPONSE=true); omitted and rejected under --read-only. Actions: \
                       collect_investigation_package (machine_id, comment), stop_and_quarantine_file \
                       (machine_id, sha1, comment), live_response_run (machine_id, commands of type \
                       PutFile/RunScript/GetFile with params, comment; subject to --allowed-commands), \
                       upload_library_file (file_name, file_content, description, optional \
                       parameters_description, override_if_exists), library_file_delete (file_name, comment). \
                       machine_id is the 40-hex Defender machine ID; comment needs at least 10 characters and \
                       is recorded in the audit trail. Returns the upstream MachineAction; poll it with \
                       defender_forensics machine_action_get_status. Requires Machine.CollectForensics, \
                       Machine.StopAndQuarantine, Machine.LiveResponse, or Library.Manage as applicable.",
        annotations(
            title = "Defender Response",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn defender_response(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        Parameters(input): Parameters<ResponseInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.clone();
        let justification = if action == "upload_library_file" {
            input.description.clone()
        } else {
            input.comment.clone()
        };
        let result = self.response_action(context.clone(), input).await;
        if !RESPONSE_ACTIONS.contains(&action.as_str()) {
            return result;
        }
        self.audit_validation_error(
            MutatingTool::Response,
            &action,
            PermissionCategory::LiveResponse,
            justification.as_deref(),
            &context,
            result,
        )
        .await
    }

    async fn response_action(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        input: ResponseInput,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        if !RESPONSE_ACTIONS.contains(&action) {
            return Err(crate::error::unknown_action_error(
                "defender_response",
                action,
                RESPONSE_ACTIONS,
            ));
        }

        match action {
            "collect_investigation_package" => {
                let machine_id_res = validation::validate_machine_id(required(
                    &input.machine_id,
                    "machine_id",
                    action,
                )?);
                let comment_val = input.comment.as_deref().unwrap_or("");
                let machine_id_str = machine_id_res
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let machine_enc = validation::encode_path_segment(&machine_id_str).to_string();
                let comment_str = comment_val.to_string();

                let params = serde_json::Map::new();
                let targets = if machine_id_res.is_ok() {
                    vec![crate::audit::AuditTarget::machine_id(&machine_id_str)]
                } else {
                    vec![]
                };

                let val_res = match machine_id_res {
                    Ok(_) => Ok(()),
                    Err(e) => Err(crate::error::tool_error(e.message)),
                };

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Response,
                    action: "collect_investigation_package",
                    category: PermissionCategory::LiveResponse,
                    targets,
                    parameters: params,
                    justification: Some(comment_val),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |resp: &MutationResponse| (
                        resp.get("id").and_then(Value::as_str).map(str::to_owned),
                        resp.get("status").and_then(Value::as_str).map(str::to_owned),
                    ),
                    upstream: || async move {
                        tracing::info!(machine_id = %machine_id_str, comment = %comment_str, "Investigation package collection initiated");
                        self.endpoint
                            .endpoint_post_as(
                                &format!("/api/machines/{machine_enc}/collectInvestigationPackage"),
                                &json!({ "Comment": comment_str }),
                                PermissionCategory::LiveResponse,
                            )
                            .await
                    },
                }).await
            }
            "stop_and_quarantine_file" => {
                let machine_id_res = validation::validate_machine_id(required(
                    &input.machine_id,
                    "machine_id",
                    action,
                )?);
                let sha1_res = validation::validate_sha1(required(&input.sha1, "sha1", action)?);
                let comment_val = input.comment.as_deref().unwrap_or("");
                let machine_id_str = machine_id_res
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let sha1_str = sha1_res.as_ref().map(|s| s.to_string()).unwrap_or_default();
                let machine_enc = validation::encode_path_segment(&machine_id_str).to_string();
                let comment_str = comment_val.to_string();

                let params = serde_json::Map::new();
                let mut targets = vec![];
                if machine_id_res.is_ok() {
                    targets.push(crate::audit::AuditTarget::machine_id(&machine_id_str));
                }
                if sha1_res.is_ok() {
                    targets.push(crate::audit::AuditTarget::sha1(&sha1_str));
                }

                let val_res = match (machine_id_res, sha1_res) {
                    (Ok(_), Ok(_)) => Ok(()),
                    (Err(e), _) => Err(crate::error::tool_error(e.message)),
                    (_, Err(e)) => Err(crate::error::tool_error(e.message)),
                };

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Response,
                    action: "stop_and_quarantine_file",
                    category: PermissionCategory::LiveResponse,
                    targets,
                    parameters: params,
                    justification: Some(comment_val),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |resp: &MutationResponse| (
                        resp.get("id").and_then(Value::as_str).map(str::to_owned),
                        resp.get("status").and_then(Value::as_str).map(str::to_owned),
                    ),
                    upstream: || async move {
                        tracing::info!(machine_id = %machine_id_str, sha1 = %sha1_str, comment = %comment_str, "Stop and quarantine initiated");
                        self.endpoint
                            .endpoint_post_as(
                                &format!("/api/machines/{machine_enc}/StopAndQuarantineFile"),
                                &json!({ "Comment": comment_str, "Sha1": sha1_str }),
                                PermissionCategory::LiveResponse,
                            )
                            .await
                    },
                }).await
            }
            "live_response_run" => {
                let args = action_args(&input);
                let p: LiveResponseRunInput =
                    serde_json::from_value(Value::Object(args)).map_err(|e| {
                        crate::error::invalid_params(format!(
                            "invalid arguments for this action: {e}"
                        ))
                    })?;

                let machine_res = validation::validate_required_id(&p.machine_id, "machine_id");
                let comment_val = p.comment.clone();
                let commands_res = validation::validate_live_response_commands(
                    &p.commands,
                    self.config.live_response_allowed_commands.as_deref(),
                );
                let machine_id_str = machine_res
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let machine_enc = validation::encode_path_segment(&machine_id_str).to_string();

                let val_res = match (machine_res, commands_res) {
                    (Ok(_), Ok(_)) => Ok(()),
                    (Err(e), _) => Err(crate::error::tool_error(e.message)),
                    (_, Err(e)) => Err(crate::error::tool_error(e.message)),
                };

                let mut param_map = serde_json::Map::new();
                let cmd_types: Vec<Value> = p
                    .commands
                    .iter()
                    .map(|c| Value::String(c.cmd_type.as_str().to_string()))
                    .collect();
                param_map.insert("commands".to_string(), Value::Array(cmd_types));

                let targets = if val_res.is_ok() {
                    vec![crate::audit::AuditTarget::machine_id(&machine_id_str)]
                } else {
                    vec![]
                };

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Response,
                    action: "live_response_run",
                    category: PermissionCategory::LiveResponse,
                    targets,
                    parameters: param_map,
                    justification: Some(&comment_val),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |resp: &MutationResponse| {
                        (
                            resp.get("id").and_then(Value::as_str).map(str::to_owned),
                            resp.get("status")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                        )
                    },
                    upstream: || async move {
                        tracing::info!(
                            machine_id = %machine_id_str,
                            comment = %p.comment,
                            command_count = p.commands.len(),
                            "Live Response run initiated"
                        );
                        let body = json!({
                            "Commands": p.commands,
                            "Comment": p.comment,
                        });
                        self.endpoint
                            .endpoint_post_as(
                                &format!("/api/machines/{machine_enc}/runliveresponse"),
                                &body,
                                PermissionCategory::LiveResponse,
                            )
                            .await
                    },
                })
                .await
            }
            "upload_library_file" => {
                let mut args = action_args(&input);
                args.remove("comment");
                let p: LiveResponseLibraryUploadInput = serde_json::from_value(Value::Object(args))
                    .map_err(|e| {
                        crate::error::invalid_params(format!(
                            "invalid arguments for this action: {e}"
                        ))
                    })?;

                let file_name_res = validation::validate_file_name(&p.file_name);
                let desc_res = validation::validate_description(&p.description);
                let content = p.file_content.into_bytes();
                let content_len = content.len();
                let content_res = if content.is_empty() {
                    Err(crate::error::tool_error("file_content cannot be empty"))
                } else if content_len > crate::constants::MAX_LIBRARY_FILE_SIZE {
                    Err(crate::error::tool_error(format!(
                        "File size {} bytes exceeds maximum of {} bytes (20 MB)",
                        content_len,
                        crate::constants::MAX_LIBRARY_FILE_SIZE
                    )))
                } else {
                    Ok(())
                };

                let val_res = match (&file_name_res, &desc_res, &content_res) {
                    (Ok(_), Ok(_), Ok(_)) => Ok(()),
                    (Err(e), _, _) => Err(crate::error::tool_error(e.message.clone())),
                    (_, Err(e), _) => Err(crate::error::tool_error(e.message.clone())),
                    (_, _, Err(e)) => Err(e.clone()),
                };

                let file_name_str = file_name_res.map(str::to_string).unwrap_or_default();
                let description_str = desc_res.map(str::to_string).unwrap_or_default();

                let mut param_map = serde_json::Map::new();
                if let Some(pd) = &p.parameters_description {
                    param_map.insert(
                        "parameters_description".to_string(),
                        Value::String(pd.clone()),
                    );
                }
                if let Some(ov) = p.override_if_exists {
                    param_map.insert("override_if_exists".to_string(), Value::Bool(ov));
                }

                let targets = if val_res.is_ok() {
                    vec![crate::audit::AuditTarget::file_name(&file_name_str)]
                } else {
                    vec![]
                };

                let upstream_fn = file_name_str.clone();
                let upstream_desc = description_str.clone();

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Response,
                    action: "upload_library_file",
                    category: PermissionCategory::LiveResponse,
                    targets,
                    parameters: param_map,
                    justification: input.comment.as_deref().or(Some(&description_str)),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |resp: &MutationResponse| {
                        (
                            resp.get("id").and_then(Value::as_str).map(str::to_owned),
                            None,
                        )
                    },
                    upstream: || async move {
                        tracing::info!(
                            file_name = %upstream_fn,
                            size = content_len,
                            "Library file upload initiated"
                        );
                        self.endpoint
                            .endpoint_multipart_upload(
                                crate::constants::LIBRARY_FILES_PATH,
                                &upstream_fn,
                                content,
                                &upstream_desc,
                                p.parameters_description.as_deref(),
                                p.override_if_exists,
                            )
                            .await
                    },
                })
                .await
            }
            "library_file_delete" => {
                if input.machine_id.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'machine_id' is not used by action 'library_file_delete'",
                    ));
                }
                if input.sha1.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'sha1' is not used by action 'library_file_delete'",
                    ));
                }
                if input.commands.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'commands' is not used by action 'library_file_delete'",
                    ));
                }
                if input.file_content.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'file_content' is not used by action 'library_file_delete'",
                    ));
                }
                if input.description.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'description' is not used by action 'library_file_delete'",
                    ));
                }
                if input.parameters_description.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'parameters_description' is not used by action 'library_file_delete'",
                    ));
                }
                if input.override_if_exists.is_some() {
                    return Err(crate::error::invalid_params(
                        "field 'override_if_exists' is not used by action 'library_file_delete'",
                    ));
                }

                let fn_val = required(&input.file_name, "file_name", action)?;
                let fn_res = validation::validate_file_name(fn_val);
                let comment_val = input.comment.as_deref().unwrap_or("");
                let fn_str = fn_res.as_ref().map(|s| s.to_string()).unwrap_or_default();
                let fn_enc = validation::encode_path_segment(&fn_str).to_string();

                let val_res = match fn_res {
                    Ok(_) => Ok(()),
                    Err(e) => Err(crate::error::tool_error(e.message)),
                };

                let targets = if val_res.is_ok() {
                    vec![crate::audit::AuditTarget::file_name(&fn_str)]
                } else {
                    vec![]
                };

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Response,
                    action: "library_file_delete",
                    category: PermissionCategory::LiveResponse,
                    targets,
                    parameters: serde_json::Map::new(),
                    justification: Some(comment_val),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async move {
                        let _ = self
                            .endpoint
                            .endpoint_delete_as(
                                &format!("/api/libraryfiles/{fn_enc}"),
                                PermissionCategory::LiveResponse,
                            )
                            .await?;
                        Ok(MutationResponse {
                            http_status: 204,
                            body: json!({ "status": "deleted", "file_name": fn_str }),
                        })
                    },
                })
                .await
            }
            _ => Err(crate::error::unknown_action_error(
                "defender_response",
                action,
                RESPONSE_ACTIONS,
            )),
        }
    }
    /// Consolidated device response and lifecycle actions dispatcher.
    #[tool(
        name = "defender_device_response",
        description = DEVICE_RESPONSE_DESCRIPTION_WITH_OFFBOARD,
        annotations(
            title = "Defender Device Response",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn defender_device_response(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        Parameters(input): Parameters<DeviceResponseInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.clone();
        let justification = input.comment.clone();
        let known = if self.config.categories.offboarding {
            DEVICE_RESPONSE_ACTIONS
        } else {
            DEVICE_RESPONSE_ACTIONS_WITHOUT_OFFBOARD
        }
        .contains(&action.as_str());
        let result = self.device_response_action(context.clone(), input).await;
        if !known {
            return result;
        }
        let category = if action == "offboard" {
            PermissionCategory::Offboarding
        } else {
            PermissionCategory::DeviceResponse
        };
        self.audit_validation_error(
            MutatingTool::DeviceResponse,
            &action,
            category,
            justification.as_deref(),
            &context,
            result,
        )
        .await
    }

    async fn device_response_action(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        input: DeviceResponseInput,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        let valid_actions = if self.config.categories.offboarding {
            DEVICE_RESPONSE_ACTIONS
        } else {
            DEVICE_RESPONSE_ACTIONS_WITHOUT_OFFBOARD
        };
        if !valid_actions.contains(&action) {
            let mut err = crate::error::unknown_action_error(
                "defender_device_response",
                action,
                valid_actions,
            );
            if action == "offboard" && !self.config.categories.offboarding {
                err.message =
                    format!("{}. offboard requires --enable-offboarding", err.message).into();
            }
            return Err(err);
        }

        let unused_field = match action {
            "isolate" => {
                if input.action_id.is_some() {
                    Some("action_id")
                } else if input.scan_type.is_some() {
                    Some("scan_type")
                } else if input.tag.is_some() {
                    Some("tag")
                } else if input.device_value.is_some() {
                    Some("device_value")
                } else {
                    None
                }
            }
            "unisolate"
            | "restrict_app_execution"
            | "unrestrict_app_execution"
            | "start_investigation"
            | "offboard" => {
                if input.action_id.is_some() {
                    Some("action_id")
                } else if input.isolation_type.is_some() {
                    Some("isolation_type")
                } else if input.scan_type.is_some() {
                    Some("scan_type")
                } else if input.tag.is_some() {
                    Some("tag")
                } else if input.device_value.is_some() {
                    Some("device_value")
                } else {
                    None
                }
            }
            "run_av_scan" => {
                if input.action_id.is_some() {
                    Some("action_id")
                } else if input.isolation_type.is_some() {
                    Some("isolation_type")
                } else if input.tag.is_some() {
                    Some("tag")
                } else if input.device_value.is_some() {
                    Some("device_value")
                } else {
                    None
                }
            }
            "cancel_machine_action" => {
                if input.machine_id.is_some() {
                    Some("machine_id")
                } else if input.isolation_type.is_some() {
                    Some("isolation_type")
                } else if input.scan_type.is_some() {
                    Some("scan_type")
                } else if input.tag.is_some() {
                    Some("tag")
                } else if input.device_value.is_some() {
                    Some("device_value")
                } else {
                    None
                }
            }
            "tag_add" | "tag_remove" => {
                if input.action_id.is_some() {
                    Some("action_id")
                } else if input.isolation_type.is_some() {
                    Some("isolation_type")
                } else if input.scan_type.is_some() {
                    Some("scan_type")
                } else if input.device_value.is_some() {
                    Some("device_value")
                } else {
                    None
                }
            }
            "set_device_value" => {
                if input.action_id.is_some() {
                    Some("action_id")
                } else if input.isolation_type.is_some() {
                    Some("isolation_type")
                } else if input.scan_type.is_some() {
                    Some("scan_type")
                } else if input.tag.is_some() {
                    Some("tag")
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(f) = unused_field {
            let val_err =
                crate::error::tool_error(format!("field '{f}' is not used by action '{action}'"));
            return self
                .execute_mutation(MutationRequest {
                    tool: MutatingTool::DeviceResponse,
                    action,
                    category: if action == "offboard" {
                        PermissionCategory::Offboarding
                    } else {
                        PermissionCategory::DeviceResponse
                    },
                    targets: Vec::new(),
                    parameters: serde_json::Map::new(),
                    justification: input.comment.as_deref(),
                    validation_result: Err(val_err),
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async { unreachable!() },
                })
                .await;
        }

        let category = if action == "offboard" {
            PermissionCategory::Offboarding
        } else {
            PermissionCategory::DeviceResponse
        };

        let comment_val = input.comment.as_deref().unwrap_or("");
        let mut params = serde_json::Map::new();

        let (targets, val_res, upstream_path, upstream_body) = if action == "cancel_machine_action"
        {
            let aid_res =
                validation::validate_action_id(required(&input.action_id, "action_id", action)?);
            let aid_str = aid_res.as_ref().map(|s| s.to_string()).unwrap_or_default();
            let enc = validation::encode_path_segment(&aid_str).to_string();
            let t = if !aid_str.is_empty() {
                vec![crate::audit::AuditTarget::machine_action_id(&aid_str)]
            } else {
                vec![]
            };
            let v = aid_res
                .map(|_| ())
                .map_err(|e| crate::error::tool_error(e.message));
            let body = json!({ "Comment": comment_val });
            (t, v, format!("/api/machineactions/{enc}/cancel"), body)
        } else {
            let mid_res =
                validation::validate_machine_id(required(&input.machine_id, "machine_id", action)?);
            let mid_str = mid_res.as_ref().map(|s| s.to_string()).unwrap_or_default();
            let enc = validation::encode_path_segment(&mid_str).to_string();
            let t = if !mid_str.is_empty() {
                vec![crate::audit::AuditTarget::machine_id(&mid_str)]
            } else {
                vec![]
            };
            let v_mid = mid_res
                .as_ref()
                .map(|_| ())
                .map_err(|e| crate::error::tool_error(e.message.clone()));

            match action {
                "isolate" => {
                    let iso = input.isolation_type.unwrap_or(IsolationType::Full);
                    params.insert("isolation_type".to_string(), json!(iso.as_str()));
                    let body = json!({ "Comment": comment_val, "IsolationType": iso.as_str() });
                    (t, v_mid, format!("/api/machines/{enc}/isolate"), body)
                }
                "unisolate" => (
                    t,
                    v_mid,
                    format!("/api/machines/{enc}/unisolate"),
                    json!({ "Comment": comment_val }),
                ),
                "restrict_app_execution" => (
                    t,
                    v_mid,
                    format!("/api/machines/{enc}/restrictCodeExecution"),
                    json!({ "Comment": comment_val }),
                ),
                "unrestrict_app_execution" => (
                    t,
                    v_mid,
                    format!("/api/machines/{enc}/unrestrictCodeExecution"),
                    json!({ "Comment": comment_val }),
                ),
                "run_av_scan" => {
                    let scan_opt = input.scan_type;
                    let scan = scan_opt.ok_or_else(|| {
                        crate::error::invalid_params("action 'run_av_scan' requires 'scan_type'")
                    })?;
                    params.insert("scan_type".to_string(), json!(scan.as_str()));
                    (
                        t,
                        v_mid,
                        format!("/api/machines/{enc}/runAntiVirusScan"),
                        json!({ "Comment": comment_val, "ScanType": scan.as_str() }),
                    )
                }
                "start_investigation" => (
                    t,
                    v_mid,
                    format!("/api/machines/{enc}/startInvestigation"),
                    json!({ "Comment": comment_val }),
                ),
                "tag_add" | "tag_remove" => {
                    let tag_val = required(&input.tag, "tag", action)?;
                    let tag_res = validation::validate_tag(tag_val);
                    let tag_str = tag_res.as_ref().map(|s| s.to_string()).unwrap_or_default();
                    params.insert("tag".to_string(), json!(tag_str));
                    let act_str = if action == "tag_add" { "Add" } else { "Remove" };
                    let v = match (&mid_res, &tag_res) {
                        (Ok(_), Ok(_)) => Ok(()),
                        (Err(e), _) => Err(crate::error::tool_error(e.message.clone())),
                        (_, Err(e)) => Err(crate::error::tool_error(e.message.clone())),
                    };
                    (
                        t,
                        v,
                        format!("/api/machines/{enc}/tags"),
                        json!({ "Value": tag_str, "Action": act_str }),
                    )
                }
                "set_device_value" => {
                    let dv = input.device_value.ok_or_else(|| {
                        crate::error::invalid_params(
                            "action 'set_device_value' requires 'device_value'",
                        )
                    })?;
                    params.insert("device_value".to_string(), json!(dv.as_str()));
                    (
                        t,
                        v_mid,
                        format!("/api/machines/{enc}/setDeviceValue"),
                        json!({ "DeviceValue": dv.as_str() }),
                    )
                }
                "offboard" => (
                    t,
                    v_mid,
                    format!("/api/machines/{enc}/offboard"),
                    json!({ "Comment": comment_val }),
                ),
                _ => unreachable!(),
            }
        };

        let action_owned = action.to_string();
        self.execute_mutation(MutationRequest {
            tool: MutatingTool::DeviceResponse,
            action,
            category,
            targets,
            parameters: params,
            justification: Some(comment_val),
            validation_result: val_res,
            context: &context,
            extract_tracking: |resp: &MutationResponse| {
                let tracking_id = resp.get("id")
                    .or_else(|| resp.get("machineAction").and_then(|m| m.get("id")))
                    .or_else(|| resp.get("investigation").and_then(|i| i.get("id")))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let upstream_status = resp.get("status")
                    .or_else(|| resp.get("machineAction").and_then(|m| m.get("status")))
                    .or_else(|| resp.get("investigation").and_then(|i| i.get("state")))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                (tracking_id, upstream_status)
            },
            upstream: || async move {
                let resp = self.endpoint.endpoint_post_as(&upstream_path, &upstream_body, category).await?;
                match action_owned.as_str() {
                    "isolate" | "unisolate" | "restrict_app_execution" | "unrestrict_app_execution" | "run_av_scan" | "cancel_machine_action" => {
                        Ok(Self::wrap_machine_action(resp, None))
                    }
                    "start_investigation" => {
                        Ok(Self::wrap_investigation(resp))
                    }
                    "offboard" => {
                        Ok(Self::wrap_machine_action(resp, Some(
                            "Offboarding cannot be undone remotely; the device stops reporting until re-onboarded. On Windows the API stops the sensor service but does not remove onboarding registry data."
                        )))
                    }
                    _ => Ok(resp),
                }
            },
        }).await
    }
    /// Consolidated custom indicator management dispatcher.
    #[tool(
        name = "defender_indicators",
        description = INDICATORS_DESCRIPTION,
        annotations(
            title = "Defender Custom Indicators",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn defender_indicators(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        Parameters(input): Parameters<IndicatorsInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.clone();
        let justification = input.comment.clone();
        let result = self.indicators_action(context.clone(), input).await;
        if !INDICATORS_ACTIONS.contains(&action.as_str()) {
            return result;
        }
        self.audit_validation_error(
            MutatingTool::Indicators,
            &action,
            PermissionCategory::Indicators,
            justification.as_deref(),
            &context,
            result,
        )
        .await
    }

    async fn indicators_action(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        input: IndicatorsInput,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        if !INDICATORS_ACTIONS.contains(&action) {
            return Err(crate::error::unknown_action_error(
                "defender_indicators",
                action,
                INDICATORS_ACTIONS,
            ));
        }

        let unused_field = match action {
            "submit" => {
                if input.indicator_id.is_some() {
                    Some("indicator_id")
                } else if input.indicator_ids.is_some() {
                    Some("indicator_ids")
                } else {
                    None
                }
            }
            "delete" => {
                if input.indicator_value.is_some() {
                    Some("indicator_value")
                } else if input.indicator_type.is_some() {
                    Some("indicator_type")
                } else if input.indicator_action.is_some() {
                    Some("indicator_action")
                } else if input.title.is_some() {
                    Some("title")
                } else if input.description.is_some() {
                    Some("description")
                } else if input.severity.is_some() {
                    Some("severity")
                } else if input.expiration_time.is_some() {
                    Some("expiration_time")
                } else if input.rbac_group_names.is_some() {
                    Some("rbac_group_names")
                } else if input.recommended_actions.is_some() {
                    Some("recommended_actions")
                } else if input.generate_alert.is_some() {
                    Some("generate_alert")
                } else if input.indicator_ids.is_some() {
                    Some("indicator_ids")
                } else {
                    None
                }
            }
            "batch_delete" => {
                if input.indicator_id.is_some() {
                    Some("indicator_id")
                } else if input.indicator_value.is_some() {
                    Some("indicator_value")
                } else if input.indicator_type.is_some() {
                    Some("indicator_type")
                } else if input.indicator_action.is_some() {
                    Some("indicator_action")
                } else if input.title.is_some() {
                    Some("title")
                } else if input.description.is_some() {
                    Some("description")
                } else if input.severity.is_some() {
                    Some("severity")
                } else if input.expiration_time.is_some() {
                    Some("expiration_time")
                } else if input.rbac_group_names.is_some() {
                    Some("rbac_group_names")
                } else if input.recommended_actions.is_some() {
                    Some("recommended_actions")
                } else if input.generate_alert.is_some() {
                    Some("generate_alert")
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(f) = unused_field {
            let val_err =
                crate::error::tool_error(format!("field '{f}' is not used by action '{action}'"));
            return self
                .execute_mutation(MutationRequest {
                    tool: MutatingTool::Indicators,
                    action,
                    category: PermissionCategory::Indicators,
                    targets: Vec::new(),
                    parameters: serde_json::Map::new(),
                    justification: input.comment.as_deref(),
                    validation_result: Err(val_err),
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async { unreachable!() },
                })
                .await;
        }

        let comment_val = input.comment.as_deref().unwrap_or("");
        let mut params = serde_json::Map::new();

        match action {
            "submit" => {
                let title = required(&input.title, "title", action)?;
                let title_res = validation::validate_text(title, 256, "title");
                let desc = required(&input.description, "description", action)?;
                let desc_res = validation::validate_description(desc);
                let val_str = required(&input.indicator_value, "indicator_value", action)?;
                let itype = input.indicator_type.ok_or_else(|| {
                    crate::error::invalid_params("action 'submit' requires 'indicator_type'")
                })?;
                let iact = input.indicator_action.ok_or_else(|| {
                    crate::error::invalid_params("action 'submit' requires 'indicator_action'")
                })?;

                let ival_res = validation::validate_indicator_value(itype, val_str);
                let iact_res =
                    validation::validate_indicator_action(itype, iact, input.generate_alert);
                let exp_res = input
                    .expiration_time
                    .as_deref()
                    .map(|exp| validation::validate_future_rfc3339(exp, "expiration_time"))
                    .transpose();
                let rbac_res: Result<Option<()>, McpError> = input
                    .rbac_group_names
                    .as_ref()
                    .map(|groups| {
                        for g in groups {
                            validation::validate_text(g, 128, "rbac_group_names")?;
                        }
                        Ok(())
                    })
                    .transpose();

                let val_res = match (
                    &title_res, &desc_res, &ival_res, &iact_res, &exp_res, &rbac_res,
                ) {
                    (Ok(_), Ok(_), Ok(_), Ok(_), Ok(_), Ok(_)) => Ok(()),
                    (Err(e), _, _, _, _, _) => Err(crate::error::tool_error(e.message.clone())),
                    (_, Err(e), _, _, _, _) => Err(crate::error::tool_error(e.message.clone())),
                    (_, _, Err(e), _, _, _) => Err(crate::error::tool_error(e.message.clone())),
                    (_, _, _, Err(e), _, _) => Err(crate::error::tool_error(e.message.clone())),
                    (_, _, _, _, Err(e), _) => Err(crate::error::tool_error(e.message.clone())),
                    (_, _, _, _, _, Err(e)) => Err(crate::error::tool_error(e.message.clone())),
                };

                let targets = if ival_res.is_ok() {
                    vec![crate::audit::AuditTarget::indicator_value(val_str)]
                } else {
                    vec![]
                };

                params.insert("indicator_type".to_string(), json!(itype.as_str()));
                params.insert("indicator_action".to_string(), json!(iact.as_str()));
                if let Some(sev) = input.severity {
                    params.insert("severity".to_string(), json!(sev.as_str()));
                }

                let mut body = json!({
                    "indicatorValue": val_str,
                    "indicatorType": itype.as_str(),
                    "action": iact.as_str(),
                    "title": title,
                    "description": desc,
                });
                if iact == IndicatorAction::Audit {
                    body["generateAlert"] = json!(true);
                } else if let Some(ga) = input.generate_alert {
                    body["generateAlert"] = json!(ga);
                }
                if let Some(sev) = input.severity {
                    body["severity"] = json!(sev.as_str());
                }
                if let Some(exp) = &input.expiration_time {
                    body["expirationTime"] = json!(exp);
                }
                if let Some(ra) = &input.recommended_actions {
                    body["recommendedActions"] = json!(ra);
                }
                if let Some(rb) = &input.rbac_group_names {
                    body["rbacGroupNames"] = json!(rb);
                }

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Indicators,
                    action: "submit",
                    category: PermissionCategory::Indicators,
                    targets,
                    parameters: params,
                    justification: Some(comment_val),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |resp: &MutationResponse| {
                        (
                            resp.get("id").and_then(Value::as_str).map(str::to_owned),
                            None,
                        )
                    },
                    upstream: || async move {
                        self.endpoint
                            .endpoint_post_as(
                                "/api/indicators",
                                &body,
                                PermissionCategory::Indicators,
                            )
                            .await
                    },
                })
                .await
            }
            "delete" => {
                let id = required(&input.indicator_id, "indicator_id", action)?;
                let id_res = validation::validate_required_id(id, "indicator_id");
                let id_str = id_res.as_ref().map(|s| s.to_string()).unwrap_or_default();
                let enc = validation::encode_path_segment(&id_str).to_string();
                let targets = if !id_str.is_empty() {
                    vec![crate::audit::AuditTarget::indicator_id(&id_str)]
                } else {
                    vec![]
                };
                let val_res = id_res
                    .map(|_| ())
                    .map_err(|e| crate::error::tool_error(e.message));

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Indicators,
                    action: "delete",
                    category: PermissionCategory::Indicators,
                    targets,
                    parameters: params,
                    justification: Some(comment_val),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async move {
                        let _ = self
                            .endpoint
                            .endpoint_delete_as(
                                &format!("/api/indicators/{enc}"),
                                PermissionCategory::Indicators,
                            )
                            .await?;
                        Ok(MutationResponse {
                            http_status: 204,
                            body: json!({ "status": "deleted", "indicator_id": id_str }),
                        })
                    },
                })
                .await
            }
            "batch_delete" => {
                let ids_opt = input.indicator_ids.as_ref();
                let ids = ids_opt.ok_or_else(|| {
                    crate::error::invalid_params("action 'batch_delete' requires 'indicator_ids'")
                })?;
                let batch_res = validation::validate_batch(
                    ids,
                    crate::constants::MAX_INDICATOR_BATCH,
                    "indicator_ids",
                );
                let targets = ids
                    .iter()
                    .map(crate::audit::AuditTarget::indicator_id)
                    .collect();
                params.insert("count".to_string(), json!(ids.len()));
                let val_res = batch_res.map_err(|e| crate::error::tool_error(e.message));
                let count = ids.len();
                let body = json!({ "IndicatorIds": ids });

                self.execute_mutation(MutationRequest {
                    tool: MutatingTool::Indicators,
                    action: "batch_delete",
                    category: PermissionCategory::Indicators,
                    targets,
                    parameters: params,
                    justification: Some(comment_val),
                    validation_result: val_res,
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async move {
                        let _ = self
                            .endpoint
                            .endpoint_post_as(
                                "/api/indicators/BatchDelete",
                                &body,
                                PermissionCategory::Indicators,
                            )
                            .await?;
                        Ok(MutationResponse {
                            http_status: 204,
                            body: json!({ "status": "deleted", "count": count }),
                        })
                    },
                })
                .await
            }
            _ => unreachable!(),
        }
    }
    /// Consolidated alert and incident triage write-back dispatcher.
    #[tool(
        name = "defender_triage",
        description = TRIAGE_DESCRIPTION,
        annotations(
            title = "Defender Triage",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn defender_triage(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        Parameters(input): Parameters<TriageInput>,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.clone();
        let justification = input.justification.clone();
        let result = self.triage_action(context.clone(), input).await;
        if !TRIAGE_ACTIONS.contains(&action.as_str()) {
            return result;
        }
        self.audit_validation_error(
            MutatingTool::Triage,
            &action,
            PermissionCategory::Triage,
            justification.as_deref(),
            &context,
            result,
        )
        .await
    }

    async fn triage_action(
        &self,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
        input: TriageInput,
    ) -> Result<CallToolResult, McpError> {
        let action = input.action.as_str();
        if !TRIAGE_ACTIONS.contains(&action) {
            return Err(crate::error::unknown_action_error(
                "defender_triage",
                action,
                TRIAGE_ACTIONS,
            ));
        }

        let unused_field = match action {
            "endpoint_alert_batch_update" => {
                if input.id.is_some() {
                    Some("id")
                } else if input.tags.is_some() {
                    Some("tags")
                } else {
                    None
                }
            }
            "endpoint_alert_update" => {
                if input.ids.is_some() {
                    Some("ids")
                } else if input.tags.is_some() {
                    Some("tags")
                } else {
                    None
                }
            }
            "endpoint_alert_comment" => {
                if input.ids.is_some() {
                    Some("ids")
                } else if input.status.is_some() {
                    Some("status")
                } else if input.assigned_to.is_some() {
                    Some("assigned_to")
                } else if input.classification.is_some() {
                    Some("classification")
                } else if input.determination.is_some() {
                    Some("determination")
                } else if input.tags.is_some() {
                    Some("tags")
                } else {
                    None
                }
            }
            "xdr_alert_update" => {
                if input.ids.is_some() {
                    Some("ids")
                } else if input.tags.is_some() {
                    Some("tags")
                } else if input.comment.is_some() {
                    Some("comment")
                } else {
                    None
                }
            }
            "xdr_alert_comment" => {
                if input.ids.is_some() {
                    Some("ids")
                } else if input.status.is_some() {
                    Some("status")
                } else if input.assigned_to.is_some() {
                    Some("assigned_to")
                } else if input.classification.is_some() {
                    Some("classification")
                } else if input.determination.is_some() {
                    Some("determination")
                } else if input.tags.is_some() {
                    Some("tags")
                } else {
                    None
                }
            }
            "xdr_incident_update" => {
                if input.ids.is_some() {
                    Some("ids")
                } else if input.comment.is_some() {
                    Some("comment")
                } else {
                    None
                }
            }
            "xdr_incident_comment" => {
                if input.ids.is_some() {
                    Some("ids")
                } else if input.status.is_some() {
                    Some("status")
                } else if input.assigned_to.is_some() {
                    Some("assigned_to")
                } else if input.classification.is_some() {
                    Some("classification")
                } else if input.determination.is_some() {
                    Some("determination")
                } else if input.tags.is_some() {
                    Some("tags")
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(f) = unused_field {
            let val_err =
                crate::error::tool_error(format!("field '{f}' is not used by action '{action}'"));
            return self
                .execute_mutation(MutationRequest {
                    tool: MutatingTool::Triage,
                    action,
                    category: PermissionCategory::Triage,
                    targets: Vec::new(),
                    parameters: serde_json::Map::new(),
                    justification: input.justification.as_deref(),
                    validation_result: Err(val_err),
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async { unreachable!() },
                })
                .await;
        }

        // Enforce update actions have at least one change
        let has_change = match action {
            "endpoint_alert_update" | "endpoint_alert_batch_update" => {
                input.status.is_some()
                    || input.assigned_to.is_some()
                    || input.classification.is_some()
                    || input.comment.is_some()
            }
            "xdr_alert_update" => {
                input.status.is_some()
                    || input.assigned_to.is_some()
                    || input.classification.is_some()
            }
            "xdr_incident_update" => {
                input.status.is_some()
                    || input.assigned_to.is_some()
                    || input.classification.is_some()
                    || input.tags.is_some()
            }
            _ => true,
        };
        if !has_change {
            let val_err = crate::error::tool_error("at least one update field must be specified");
            return self
                .execute_mutation(MutationRequest {
                    tool: MutatingTool::Triage,
                    action,
                    category: PermissionCategory::Triage,
                    targets: Vec::new(),
                    parameters: serde_json::Map::new(),
                    justification: input.justification.as_deref(),
                    validation_result: Err(val_err),
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async { unreachable!() },
                })
                .await;
        }

        let pair_res =
            validation::validate_classification_pair(input.classification, input.determination);
        let assigned_res = input
            .assigned_to
            .as_deref()
            .map(|a| validation::validate_text(a, 256, "assigned_to"))
            .transpose();
        let comment_res = match action {
            "endpoint_alert_comment" | "xdr_alert_comment" | "xdr_incident_comment" => {
                let c = required(&input.comment, "comment", action)?;
                validation::validate_text(c, 1000, "comment").map(|_| ())
            }
            "endpoint_alert_update" | "endpoint_alert_batch_update" => input
                .comment
                .as_deref()
                .map(|c| validation::validate_text(c, 1000, "comment").map(|_| ()))
                .unwrap_or(Ok(())),
            _ => Ok(()),
        };
        let tags_res: Result<Option<()>, McpError> = input
            .tags
            .as_ref()
            .map(|tags| {
                for t in tags {
                    validation::validate_text(t, 128, "tags")?;
                }
                Ok(())
            })
            .transpose();

        let target = match action {
            "endpoint_alert_batch_update" => TriageTarget::MdeAlertBatch,
            "endpoint_alert_update" | "endpoint_alert_comment" => TriageTarget::MdeAlertPatch,
            "xdr_alert_update" | "xdr_alert_comment" => TriageTarget::XdrAlert,
            "xdr_incident_update" | "xdr_incident_comment" => TriageTarget::XdrIncident,
            _ => unreachable!(),
        };

        let status_wire = input.status.map(|s| s.wire(target)).transpose();

        let mut params = serde_json::Map::new();
        if let Some(s) = input.status {
            params.insert("status".to_string(), json!(s.as_str()));
        }
        if let Some(a) = &input.assigned_to {
            params.insert("assigned_to".to_string(), json!(a));
        }
        if let Some(c) = input.classification {
            params.insert("classification".to_string(), json!(c.as_str()));
        }
        if let Some(d) = input.determination {
            params.insert("determination".to_string(), json!(d.as_str()));
        }

        let val_res = match (
            &pair_res,
            &assigned_res,
            &comment_res,
            &tags_res,
            &status_wire,
        ) {
            (Ok(_), Ok(_), Ok(_), Ok(_), Ok(_)) => Ok(()),
            (Err(e), _, _, _, _) => Err(crate::error::tool_error(e.message.clone())),
            (_, Err(e), _, _, _) => Err(crate::error::tool_error(e.message.clone())),
            (_, _, Err(e), _, _) => Err(crate::error::tool_error(e.message.clone())),
            (_, _, _, Err(e), _) => Err(crate::error::tool_error(e.message.clone())),
            (_, _, _, _, Err(e)) => Err(crate::error::tool_error(e.message.clone())),
        };

        if action == "endpoint_alert_batch_update" {
            let ids_opt = input.ids.as_ref();
            let ids = ids_opt.ok_or_else(|| {
                crate::error::invalid_params("action 'endpoint_alert_batch_update' requires 'ids'")
            })?;
            let batch_res =
                validation::validate_batch(ids, crate::constants::MAX_ALERT_BATCH, "ids");
            let targets = ids
                .iter()
                .map(crate::audit::AuditTarget::alert_id)
                .collect();
            let combined_val = match (val_res, batch_res) {
                (Ok(_), Ok(_)) => Ok(()),
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(crate::error::tool_error(e.message)),
            };
            let count = ids.len();
            let mut body = json!({ "alertIds": ids });
            if let Ok(Some(s)) = status_wire {
                body["status"] = json!(s);
            }
            if let Some(a) = &input.assigned_to {
                body["assignedTo"] = json!(a);
            }
            if let Some(c) = input.classification {
                body["classification"] = json!(c.wire(target));
            }
            if let Some(d) = input.determination {
                body["determination"] = json!(d.wire(target));
            }
            if let Some(cm) = &input.comment {
                body["comment"] = json!(cm);
            }

            return self
                .execute_mutation(MutationRequest {
                    tool: MutatingTool::Triage,
                    action,
                    category: PermissionCategory::Triage,
                    targets,
                    parameters: params,
                    justification: input.justification.as_deref(),
                    validation_result: combined_val,
                    context: &context,
                    extract_tracking: |_| (None, None),
                    upstream: || async move {
                        let _ = self
                            .endpoint
                            .endpoint_post_as(
                                "/api/alerts/batchUpdate",
                                &body,
                                PermissionCategory::Triage,
                            )
                            .await?;
                        Ok(MutationResponse {
                            http_status: 200,
                            body: json!({ "status": "ok", "count": count }),
                        })
                    },
                })
                .await;
        }

        let id = required(&input.id, "id", action)?;
        let id_res = validation::validate_required_id(id, "id");
        let id_str = id_res.as_ref().map(|s| s.to_string()).unwrap_or_default();
        let enc = validation::encode_path_segment(&id_str).to_string();
        let is_incident = action.starts_with("xdr_incident");
        let targets = if !id_str.is_empty() {
            if is_incident {
                vec![crate::audit::AuditTarget::incident_id(&id_str)]
            } else {
                vec![crate::audit::AuditTarget::alert_id(&id_str)]
            }
        } else {
            vec![]
        };

        let combined_val = match (val_res, id_res) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(crate::error::tool_error(e.message)),
        };

        let mut body = serde_json::Map::new();
        if let Ok(Some(s)) = status_wire {
            body.insert("status".to_string(), json!(s));
        }
        if let Some(a) = &input.assigned_to {
            body.insert("assignedTo".to_string(), json!(a));
        }
        if let Some(c) = input.classification {
            body.insert("classification".to_string(), json!(c.wire(target)));
        }
        if let Some(d) = input.determination {
            body.insert("determination".to_string(), json!(d.wire(target)));
        }
        if let Some(cm) = &input.comment {
            body.insert("comment".to_string(), json!(cm));
        }
        if let Some(tg) = &input.tags {
            body.insert("customTags".to_string(), json!(tg));
        }
        if action == "xdr_alert_comment" || action == "xdr_incident_comment" {
            body.insert(
                "@odata.type".to_string(),
                json!("microsoft.graph.security.alertComment"),
            );
        }
        let body_val = Value::Object(body);

        let tracking_val = id_str.clone();
        self.execute_mutation(MutationRequest {
            tool: MutatingTool::Triage,
            action,
            category: PermissionCategory::Triage,
            targets,
            parameters: params,
            justification: input.justification.as_deref(),
            validation_result: combined_val,
            context: &context,
            extract_tracking: move |_| (Some(tracking_val), None),
            upstream: || async move {
                match action {
                    "endpoint_alert_update" => {
                        self.endpoint
                            .endpoint_patch_as(
                                &format!("/api/alerts/{enc}"),
                                &body_val,
                                PermissionCategory::Triage,
                            )
                            .await
                    }
                    "endpoint_alert_comment" => {
                        self.endpoint
                            .endpoint_patch_as(
                                &format!("/api/alerts/{enc}"),
                                &body_val,
                                PermissionCategory::Triage,
                            )
                            .await
                    }
                    "xdr_alert_update" => {
                        self.client
                            .graph_patch_as(
                                &format!("/security/alerts_v2/{enc}"),
                                &body_val,
                                PermissionCategory::Triage,
                            )
                            .await
                    }
                    "xdr_alert_comment" => self
                        .client
                        .graph_post_as(
                            &format!("/security/alerts_v2/{enc}/comments"),
                            &body_val,
                            PermissionCategory::Triage,
                        )
                        .await
                        .map(|v| MutationResponse {
                            http_status: 201,
                            body: v,
                        }),
                    "xdr_incident_update" => {
                        self.client
                            .graph_patch_as(
                                &format!("/security/incidents/{enc}"),
                                &body_val,
                                PermissionCategory::Triage,
                            )
                            .await
                    }
                    "xdr_incident_comment" => self
                        .client
                        .graph_post_as(
                            &format!("/security/incidents/{enc}/comments"),
                            &body_val,
                            PermissionCategory::Triage,
                        )
                        .await
                        .map(|v| MutationResponse {
                            http_status: 201,
                            body: v,
                        }),
                    _ => unreachable!(),
                }
            },
        })
        .await
    }
}

#[tool_handler(
    router = self.router,
    name = "microsoft-defender-mcp",
    instructions = "Investigate Microsoft Defender through Microsoft Graph Security and Defender for Endpoint APIs. \
                    Six read-only domain tools are always listed: defender_hunting, defender_ti, \
                    defender_incidents_alerts, defender_machines, defender_vulnerabilities, and defender_forensics \
                    (read-only; downloads forensic archives to the local quarantine directory). Each tool takes an \
                    'action' parameter. Up to four mutating tools are listed only when their category is enabled: \
                    defender_response (--enable-live-response), defender_device_response (--enable-device-response; \
                    offboard also needs --enable-offboarding), defender_indicators (--enable-indicators), and \
                    defender_triage (--enable-triage). --read-only hides and rejects every mutating tool. Destructive \
                    tools ask the human user to confirm each call through an MCP elicitation prompt unless the server \
                    was started with --disable-human-confirmation; defender_triage is not destructive and never \
                    prompts. Every mutating attempt, including rejections, is recorded in an append-only local audit \
                    log with the acting identity. --allowed-commands restricts Live Response command types only. \
                    Authentication is app mode (service principal) by default; in user mode (--auth-mode user) the \
                    signed-in user's own Defender rights apply and permission errors name the missing scope or role. \
                    Tool results preserve upstream JSON; OData collections are objects with a value array and optional \
                    metadata, not flattened arrays. Pagination is not followed automatically. HTTP transport has no \
                    bundled client authentication: use an authenticated, trusted boundary for remote access."
)]
impl ServerHandler for DefenderServer {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let tool_name = request.name.as_ref();
        if let Some(tool) = crate::cli::MutatingTool::from_name(tool_name)
            && !self.router.has_route(tool_name)
        {
            let attempt_id = new_attempt_id();
            let (res, reason) = if self.config.read_only {
                (
                    crate::error::read_only_violation(tool_name),
                    RejectReason::ReadOnly,
                )
            } else {
                (
                    crate::error::category_disabled(tool.enable_flag()),
                    RejectReason::CategoryDisabled,
                )
            };

            let rec = AuditRecord {
                ts: chrono::Utc::now(),
                attempt_id,
                phase: AuditPhase::Final,
                tool: tool_name.to_string(),
                action: String::new(),
                targets: vec![],
                parameters: serde_json::Map::new(),
                justification: None,
                identity: self.identity(),
                confirmation: ConfirmationOutcome::NotApplicable,
                result: AuditResult::Rejected { reason },
            };

            if let Some(sink) = &self.audit_sink {
                let _ = sink.append(&rec).await;
            } else {
                eprintln!(
                    "AUDIT {} {}. targets=0 identity={} confirmation=not_applicable result=rejected",
                    rec.ts.to_rfc3339(),
                    rec.tool,
                    rec.identity.display_summary(),
                );
            }

            return Ok(res.into());
        }

        let context = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.router.call(context).await
    }
}

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

    fn create_test_server(base_url: &str, live_response: bool) -> DefenderServer {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("loopback reqwest client");
        let tm = TokenManager::for_test(http);
        let graph = GraphClient::for_test(tm.clone(), base_url.to_string());
        let endpoint = EndpointClient::for_test(tm, base_url.to_string());
        let categories = crate::cli::MutationCategories {
            live_response,
            ..Default::default()
        };
        let config = crate::cli::ServerConfig {
            transport: crate::cli::TransportMode::Stdio,
            bind_address: "127.0.0.1:8000".to_string(),
            read_only: false,
            categories,
            live_response_allowed_commands: None,
            quarantine_dir: std::path::PathBuf::from("./quarantine_artifacts"),
            audit_log: crate::cli::AuditLogSetting::Default(std::path::PathBuf::from(
                "./audit.jsonl",
            )),
            confirm_destructive: true,
            auth: crate::cli::AuthConfig::App,
        };
        DefenderServer::new_with_config(graph, endpoint, config, None)
    }

    async fn create_test_server_with_sink(
        base_url: &str,
        live_response: bool,
    ) -> (
        DefenderServer,
        rmcp::service::RequestContext<rmcp::RoleServer>,
    ) {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("loopback reqwest client");
        let tm = TokenManager::for_test(http);
        let graph = GraphClient::for_test(tm.clone(), base_url.to_string());
        let endpoint = EndpointClient::for_test(tm, base_url.to_string());
        let categories = crate::cli::MutationCategories {
            live_response,
            ..Default::default()
        };
        let audit_path = std::env::temp_dir().join(format!(
            "mcp_test_audit_{}.jsonl",
            crate::audit::new_attempt_id()
        ));
        let sink = AuditSink::open(&audit_path).await.expect("scratch sink");
        let config = crate::cli::ServerConfig {
            transport: crate::cli::TransportMode::Stdio,
            bind_address: "127.0.0.1:8000".to_string(),
            read_only: false,
            categories,
            live_response_allowed_commands: None,
            quarantine_dir: std::path::PathBuf::from("./quarantine_artifacts"),
            audit_log: crate::cli::AuditLogSetting::Explicit(audit_path),
            confirm_destructive: false,
            auth: crate::cli::AuthConfig::App,
        };
        let server = DefenderServer::new_with_config(
            graph,
            endpoint,
            config,
            Some(std::sync::Arc::new(sink)),
        );
        let (server_t, _client_t) = tokio::io::duplex(1024);
        let running = rmcp::service::serve_directly(server.clone(), server_t, None);
        let ctx = rmcp::service::RequestContext::new(
            rmcp::model::RequestId::Number(1),
            running.peer().clone(),
        );
        (server, ctx)
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
        let (server, ctx) = create_test_server_with_sink(&guard.base_url, true).await;

        let res = server
            .defender_response(
                ctx,
                Parameters(ResponseInput {
                    action: "upload_library_file".to_string(),
                    file_name: Some("remediation.ps1".to_string()),
                    file_content: Some("Write-Output 'Scan'".to_string()),
                    description: Some("Scan C:/Logs\nand /var/log".to_string()),
                    parameters_description: None,
                    override_if_exists: Some(true),
                    comment: Some("Upload justification min 10 chars".to_string()),
                    ..Default::default()
                }),
            )
            .await
            .expect("upload call succeeded");
        let val = res.structured_content.as_ref().expect("structured content");
        assert_eq!(val["id"], "lib-1");
        assert_eq!(val["name"], "remediation.ps1");

        let (server, ctx) = create_test_server_with_sink(&guard.base_url, true).await;
        let empty_res = server
            .defender_response(
                ctx,
                Parameters(ResponseInput {
                    action: "upload_library_file".to_string(),
                    file_name: Some("empty.ps1".to_string()),
                    file_content: Some("".to_string()),
                    description: Some("Valid description".to_string()),
                    parameters_description: None,
                    override_if_exists: None,
                    comment: Some("Upload justification min 10 chars".to_string()),
                    ..Default::default()
                }),
            )
            .await
            .expect("handled empty content");
        assert_eq!(empty_res.is_error, Some(true));

        let (server, ctx) = create_test_server_with_sink(&guard.base_url, true).await;
        let bad_name = server
            .defender_response(
                ctx,
                Parameters(ResponseInput {
                    action: "upload_library_file".to_string(),
                    file_name: Some("../escaped.ps1".to_string()),
                    file_content: Some("Write-Output 'test'".to_string()),
                    description: Some("Valid description".to_string()),
                    parameters_description: None,
                    override_if_exists: None,
                    comment: Some("Upload justification min 10 chars".to_string()),
                    ..Default::default()
                }),
            )
            .await
            .expect("mutation handled error");
        assert_eq!(bad_name.is_error, Some(true));
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
        let (server, ctx) = create_test_server_with_sink(&guard.base_url, true).await;

        let res = server
            .defender_response(
                ctx,
                Parameters(ResponseInput {
                    action: "live_response_run".to_string(),
                    machine_id: Some("dev-machine-01".to_string()),
                    commands: Some(vec![LiveResponseCommand {
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
                    }]),
                    comment: Some("Live response triage for investigation".to_string()),
                    ..Default::default()
                }),
            )
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
