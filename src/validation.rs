//! Input validation helpers for MCP tool parameters.

use std::net::IpAddr;
use std::sync::LazyLock;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;

use crate::constants::{ENDPOINT_MAX_TOP, MAX_SKIP, MAX_TOP};
use crate::error::invalid_params;
use crate::server::{Classification, Determination, IndicatorAction, IndicatorType};

// Pre-compiled regexes
static CVE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^CVE-\d{4}-\d{4,}$").expect("CVE regex must compile"));
static SHA1_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{40}$").expect("SHA1 regex must compile"));
static SHA256_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{64}$").expect("SHA256 regex must compile"));
static MD5_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{32}$").expect("MD5 regex must compile"));

// ---------------------------------------------------------------------------
// Path segment encoding
// ---------------------------------------------------------------------------

/// RFC 3986 Section 2.3 Unreserved Characters: ALPHA / DIGIT / "-" / "." / "_" / "~".
/// Characters outside this set are percent-encoded for safe insertion into URI path segments.
pub const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encode a path segment according to RFC 3986 unreserved characters.
///
/// Note: this does NOT trim the input slice.
pub fn encode_path_segment(segment: &str) -> percent_encoding::PercentEncode<'_> {
    utf8_percent_encode(segment, PATH_SEGMENT_ENCODE_SET)
}

// ---------------------------------------------------------------------------
// Hostname / ID / IP validators
// ---------------------------------------------------------------------------

/// Validate a hostname or domain parameter.
///
/// Returns the trimmed hostname slice. Enforces a maximum length of 253 characters,
/// rejects slashes, control characters, internal whitespace, and dot segments ('.' or '..').
pub fn validate_hostname(hostname: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = hostname.trim();
    if trimmed.is_empty() {
        return Err(invalid_params("hostname cannot be empty"));
    }
    if trimmed.len() > 253 {
        return Err(invalid_params(
            "hostname exceeds maximum length of 253 characters",
        ));
    }
    if trimmed.contains('/') {
        return Err(invalid_params(
            "hostname must not contain slashes — provide a single hostname, not a URL",
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(invalid_params(
            "hostname contains invalid control characters",
        ));
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(invalid_params("hostname must not contain whitespace"));
    }
    if trimmed == "." || trimmed.contains("..") {
        return Err(invalid_params("hostname must not contain dot segments"));
    }
    Ok(trimmed)
}

/// Validate that a required string ID is non-empty, not '.' or '..', and contains no control characters.
///
/// Returns the trimmed ID slice. Note that characters such as `/`, `+`, `=`, etc.
/// are permitted because callers must percent-encode dynamic path segments before
/// inserting them into URLs.
pub fn validate_required_id<'a>(
    value: &'a str,
    param_name: &str,
) -> Result<&'a str, rmcp::ErrorData> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_params(format!("{param_name} cannot be empty")));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(invalid_params(format!(
            "{param_name} cannot be '.' or '..'"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(invalid_params(format!(
            "{param_name} contains invalid control characters"
        )));
    }
    Ok(trimmed)
}

/// Validate an IP address (IPv4 or IPv6) using standard library IP address parsing.
///
/// Returns the trimmed IP address slice on success.
pub fn validate_ip_address(ip: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return Err(invalid_params("ip_address cannot be empty"));
    }
    if trimmed.parse::<IpAddr>().is_err() {
        return Err(invalid_params(format!(
            "ip_address must be a valid IPv4 or IPv6 address, got '{trimmed}'"
        )));
    }
    Ok(trimmed)
}

/// Validate a SHA1 hash (40 hex chars).
///
/// Returns the trimmed SHA1 hash slice on success.
pub fn validate_sha1(hash: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = hash.trim();
    if !SHA1_RE.is_match(trimmed) {
        return Err(invalid_params(
            "file_sha1 must be a 40-character hex string (SHA1 hash)",
        ));
    }
    Ok(trimmed)
}

/// Validate a Defender machine ID (40-character hex string).
///
/// Returns the trimmed machine ID slice on success.
pub fn validate_machine_id(machine_id: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = machine_id.trim();
    if !SHA1_RE.is_match(trimmed) {
        return Err(invalid_params(
            "machine_id must be a 40-character hex string (Defender machine ID)",
        ));
    }
    Ok(trimmed)
}

/// Validate a machine action ID (hex string or GUID).
///
/// Returns the trimmed ID. Only ASCII alphanumerics and `-` are accepted (max 64 chars), so
/// the value is safe both as a URL path segment and inside a staged artifact file name.
pub fn validate_action_id(action_id: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = action_id.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(invalid_params(
            "action_id must be a machine action GUID or hex ID (ASCII letters, digits, and '-' only)",
        ));
    }
    Ok(trimmed)
}

/// Validate a request comment (>= 10 characters).
pub fn validate_comment<'a>(
    comment: &'a str,
    field_name: &str,
) -> Result<&'a str, rmcp::ErrorData> {
    let trimmed = comment.trim();
    let char_count = trimmed.chars().count();
    if char_count < crate::constants::MIN_JUSTIFICATION_LEN {
        return Err(invalid_params(format!(
            "{field_name} must be at least {} characters describing the purpose (got {char_count})",
            crate::constants::MIN_JUSTIFICATION_LEN
        )));
    }
    Ok(trimmed)
}

/// Validate a file hash — accepts MD5 (32), SHA1 (40), or SHA256 (64) hex hash.
///
/// Returns the trimmed hash slice on success.
pub fn validate_file_hash(hash: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = hash.trim();
    let len = trimmed.len();
    let valid = match len {
        32 => MD5_RE.is_match(trimmed),
        40 => SHA1_RE.is_match(trimmed),
        64 => SHA256_RE.is_match(trimmed),
        _ => false,
    };
    if !valid {
        return Err(invalid_params(
            "file_id must be a valid MD5 (32), SHA1 (40), or SHA256 (64) hex hash",
        ));
    }
    Ok(trimmed)
}

/// Validate a tag name parameter for query-based filtering.
///
/// Returns the trimmed tag name slice. Rejects empty strings and control characters,
/// while allowing ordinary punctuation, dots, and slashes as tag_name is a freeform
/// query value rather than a URL path segment.
pub fn validate_tag_name(tag_name: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = tag_name.trim();
    if trimmed.is_empty() {
        return Err(invalid_params("tag_name cannot be empty"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(invalid_params(
            "tag_name contains invalid control characters",
        ));
    }
    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// File upload validators
// ---------------------------------------------------------------------------

/// Validate a file name for file upload.
///
/// Returns the trimmed basename on success. Rejects empty values, '.' or '..',
/// path separators ('/' or '\\'), and control characters to prevent path traversal.
pub fn validate_file_name(file_name: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = file_name.trim();
    if trimmed.is_empty() {
        return Err(invalid_params("file_name cannot be empty"));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(invalid_params("file_name cannot be '.' or '..'"));
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(invalid_params(
            "file_name must be a simple file name without path separators ('/' or '\\')",
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(invalid_params(
            "file_name contains invalid control characters",
        ));
    }
    Ok(trimmed)
}

/// Validate a description parameter for file upload.
///
/// Returns the trimmed description on success. Allows ordinary punctuation, slashes,
/// newlines, and tabs, while rejecting empty descriptions and invalid control characters
/// (such as NUL).
pub fn validate_description(description: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = description.trim();
    if trimmed.is_empty() {
        return Err(invalid_params("description cannot be empty"));
    }
    if trimmed
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(invalid_params(
            "description contains invalid control characters",
        ));
    }
    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// CVE
// ---------------------------------------------------------------------------

/// Validate a CVE ID (pattern CVE-YYYY-NNNN+).
///
/// Returns the trimmed CVE ID slice on success.
pub fn validate_cve_id(cve_id: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = cve_id.trim();
    if !CVE_RE.is_match(trimmed) {
        return Err(invalid_params(
            "CVE ID must match pattern CVE-YYYY-NNNN+ (e.g., CVE-2021-44228)",
        ));
    }
    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// OData parameter validators
// ---------------------------------------------------------------------------

pub fn validate_top(top: Option<i32>) -> Result<(), rmcp::ErrorData> {
    if let Some(t) = top
        && !(1..=MAX_TOP).contains(&t)
    {
        return Err(invalid_params(format!(
            "top must be between 1 and {MAX_TOP}, got {t}"
        )));
    }
    Ok(())
}

pub fn validate_endpoint_top(top: Option<i32>) -> Result<(), rmcp::ErrorData> {
    if let Some(t) = top
        && !(1..=ENDPOINT_MAX_TOP).contains(&t)
    {
        return Err(invalid_params(format!(
            "top must be between 1 and {ENDPOINT_MAX_TOP}, got {t}"
        )));
    }
    Ok(())
}

pub fn validate_skip(skip: Option<i32>) -> Result<(), rmcp::ErrorData> {
    if let Some(s) = skip
        && !(0..=MAX_SKIP).contains(&s)
    {
        return Err(invalid_params(format!(
            "skip must be between 0 and {MAX_SKIP}, got {s}"
        )));
    }
    Ok(())
}

pub fn validate_odata_params(top: Option<i32>, skip: Option<i32>) -> Result<(), rmcp::ErrorData> {
    validate_top(top)?;
    validate_skip(skip)?;
    Ok(())
}

pub fn validate_endpoint_odata_params(
    top: Option<i32>,
    skip: Option<i32>,
) -> Result<(), rmcp::ErrorData> {
    validate_endpoint_top(top)?;
    validate_skip(skip)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Look-back hours
// ---------------------------------------------------------------------------

pub fn validate_look_back_hours(hours: Option<i32>) -> Result<(), rmcp::ErrorData> {
    if let Some(h) = hours
        && !(1..=crate::constants::MAX_LOOK_BACK_HOURS).contains(&h)
    {
        return Err(invalid_params(format!(
            "look_back_hours must be between 1 and {}",
            crate::constants::MAX_LOOK_BACK_HOURS
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KQL (Advanced Hunting)
// ---------------------------------------------------------------------------

/// Validate a KQL Advanced Hunting query.
///
/// Enforces basic client-side boundaries: non-empty query, maximum size limit of 128KB,
/// and rejection of obvious leading-dot management commands (e.g., `.drop`, `.create`).
///
/// Note: Full KQL syntax and semantic validation is the responsibility of Microsoft Graph;
/// this local check is not a security boundary.
pub fn validate_kql_query(query: &str) -> Result<(), rmcp::ErrorData> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(invalid_params("KQL query cannot be empty"));
    }
    if query.len() > 128_000 {
        return Err(invalid_params("KQL query exceeds maximum length of 128KB"));
    }
    if trimmed.starts_with('.') {
        return Err(invalid_params(
            "KQL management commands starting with '.' are not allowed. Only read-only KQL queries are supported.",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Live Response validators
// ---------------------------------------------------------------------------

/// Validate the Live Response commands array against size limits and an optional
/// operator allowlist (resolved from `--allowed-commands` / `DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS`).
pub fn validate_live_response_commands(
    commands: &[crate::server::LiveResponseCommand],
    allowed: Option<&[String]>,
) -> Result<(), rmcp::ErrorData> {
    if commands.is_empty() {
        return Err(invalid_params(
            "commands array cannot be empty — at least one command is required",
        ));
    }
    if commands.len() > crate::constants::MAX_LIVE_RESPONSE_COMMANDS {
        return Err(invalid_params(format!(
            "commands array exceeds maximum of {} commands",
            crate::constants::MAX_LIVE_RESPONSE_COMMANDS
        )));
    }

    if let Some(allowed) = allowed {
        for cmd in commands {
            let cmd_str = cmd.cmd_type.as_str();
            if !allowed.iter().any(|a| a == cmd_str) {
                return Err(invalid_params(format!(
                    "Command type '{cmd_str}' is not in the allowed list (DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS={})",
                    allowed.join(",")
                )));
            }
        }
    }

    Ok(())
}

/// Validate a text parameter (non-empty, length <= max characters, no invalid control characters).
///
/// If `field` represents a comment or justification (e.g. `field == "comment"` or `field == "justification"`
/// or ends with `_comment`/`_justification`), `\n`, `\r`, and `\t` are permitted.
pub fn validate_text<'a>(
    s: &'a str,
    max: usize,
    field: &str,
) -> Result<&'a str, rmcp::ErrorData> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(invalid_params(format!("{field} cannot be empty")));
    }
    let char_count = trimmed.chars().count();
    if char_count > max {
        return Err(invalid_params(format!(
            "{field} exceeds maximum length of {max} characters (got {char_count})"
        )));
    }
    let allows_newlines = field == "comment"
        || field == "justification"
        || field.ends_with("_comment")
        || field.ends_with("_justification");
    let has_invalid_ctrl = if allows_newlines {
        trimmed
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    } else {
        trimmed.chars().any(|c| c.is_control())
    };
    if has_invalid_ctrl {
        return Err(invalid_params(format!(
            "{field} contains invalid control characters"
        )));
    }
    Ok(trimmed)
}

/// Validate a batch of string IDs (length 1..=max, stating the limit, and each ID passing `validate_required_id`).
pub fn validate_batch<T: AsRef<str>>(
    ids: &[T],
    max: usize,
    field: &str,
) -> Result<(), rmcp::ErrorData> {
    if ids.is_empty() {
        return Err(invalid_params(format!(
            "{field} cannot be empty (must contain between 1 and {max} items)"
        )));
    }
    if ids.len() > max {
        return Err(invalid_params(format!(
            "{field} exceeds maximum batch size of {max} items (got {}) (server policy)",
            ids.len()
        )));
    }
    for id in ids {
        validate_required_id(id.as_ref(), field)?;
    }
    Ok(())
}

/// Validate a tag string (1..=200 chars, no control characters). Errors name `tag`.
pub fn validate_tag(tag: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = tag.trim();
    if trimmed.is_empty() {
        return Err(invalid_params("tag cannot be empty"));
    }
    let count = trimmed.chars().count();
    if count > 200 {
        return Err(invalid_params(format!(
            "tag exceeds maximum length of 200 characters (got {count})"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(invalid_params("tag contains invalid control characters"));
    }
    Ok(trimmed)
}

/// Validate that a string has exact hex length and contains only ASCII hex characters.
pub fn validate_hex<'a>(s: &'a str, len: usize, field: &str) -> Result<&'a str, rmcp::ErrorData> {
    let trimmed = s.trim();
    if trimmed.len() != len || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid_params(format!(
            "{field} must be a {len}-character hex string, got '{trimmed}'"
        )));
    }
    Ok(trimmed)
}

/// Validate a URL indicator (http/https scheme, host present). Errors name `indicator_value`.
pub fn validate_url_indicator(s: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = s.trim();
    let parsed = url::Url::parse(trimmed).map_err(|e| {
        invalid_params(format!("indicator_value must be a valid URL: {e}"))
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(invalid_params(format!(
            "indicator_value URL must use http or https scheme, got '{}'",
            parsed.scheme()
        )));
    }
    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() {
        return Err(invalid_params("indicator_value URL must include a host"));
    }
    Ok(trimmed)
}

/// Validate a domain indicator (valid hostname and not an IP literal). Errors name `indicator_value`.
pub fn validate_domain_indicator(s: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = s.trim();
    if trimmed.parse::<IpAddr>().is_ok() {
        return Err(invalid_params(format!(
            "indicator_value for DomainName must not be an IP address, got '{trimmed}'"
        )));
    }
    validate_hostname(trimmed).map_err(|e| {
        invalid_params(format!("indicator_value: {}", e.message))
    })
}

/// Validate an indicator value based on indicator type. Errors name `indicator_value`.
pub fn validate_indicator_value<'a>(
    indicator_type: IndicatorType,
    value: &'a str,
) -> Result<&'a str, rmcp::ErrorData> {
    match indicator_type {
        IndicatorType::FileSha1 | IndicatorType::CertificateThumbprint => {
            validate_hex(value, 40, "indicator_value")
        }
        IndicatorType::FileSha256 => validate_hex(value, 64, "indicator_value"),
        IndicatorType::FileMd5 => validate_hex(value, 32, "indicator_value"),
        IndicatorType::IpAddress => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(invalid_params("indicator_value cannot be empty"));
            }
            if trimmed.parse::<IpAddr>().is_err() {
                return Err(invalid_params(format!(
                    "indicator_value must be a valid IPv4 or IPv6 address, got '{trimmed}'"
                )));
            }
            Ok(trimmed)
        }
        IndicatorType::DomainName => validate_domain_indicator(value),
        IndicatorType::Url => validate_url_indicator(value),
    }
}

/// Validate indicator action compatibility with type and alert generation. Errors name `indicator_action` / `generate_alert`.
pub fn validate_indicator_action(
    indicator_type: IndicatorType,
    action: IndicatorAction,
    generate_alert: Option<bool>,
) -> Result<(), rmcp::ErrorData> {
    match action {
        IndicatorAction::BlockAndRemediate => {
            let allowed = matches!(
                indicator_type,
                IndicatorType::FileSha1
                    | IndicatorType::FileSha256
                    | IndicatorType::FileMd5
                    | IndicatorType::CertificateThumbprint
            );
            if !allowed {
                return Err(invalid_params(format!(
                    "indicator_action 'BlockAndRemediate' is only supported for file hashes and CertificateThumbprint, got {:?}",
                    indicator_type
                )));
            }
        }
        IndicatorAction::Warn => {
            let allowed = matches!(
                indicator_type,
                IndicatorType::IpAddress | IndicatorType::DomainName | IndicatorType::Url
            );
            if !allowed {
                return Err(invalid_params(format!(
                    "indicator_action 'Warn' is only supported for IpAddress, DomainName, and Url, got {:?}",
                    indicator_type
                )));
            }
        }
        IndicatorAction::Audit => {
            if generate_alert == Some(false) {
                return Err(invalid_params(
                    "generate_alert must be true or omitted when indicator_action is Audit"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate that a string is a valid RFC 3339 timestamp strictly in the future. Errors name the field.
pub fn validate_future_rfc3339(
    s: &str,
    field: &str,
) -> Result<chrono::DateTime<chrono::Utc>, rmcp::ErrorData> {
    let trimmed = s.trim();
    let dt = chrono::DateTime::parse_from_rfc3339(trimmed).map_err(|e| {
        invalid_params(format!("{field} must be a valid RFC 3339 timestamp: {e}"))
    })?;
    let utc_dt = dt.with_timezone(&chrono::Utc);
    if utc_dt <= chrono::Utc::now() {
        return Err(invalid_params(format!(
            "{field} must be in the future, got '{trimmed}'"
        )));
    }
    Ok(utc_dt)
}

/// Validate a recent timestamp (must parse RFC 3339, now - max_age_days <= t <= now). Errors name `timestamp`.
/// Returns the normalized UTC string `YYYY-MM-DDThh:mm:ssZ`.
pub fn validate_recent_timestamp(s: &str, max_age_days: i64) -> Result<String, rmcp::ErrorData> {
    let trimmed = s.trim();
    let dt = chrono::DateTime::parse_from_rfc3339(trimmed).map_err(|e| {
        invalid_params(format!("timestamp must be a valid RFC 3339 timestamp: {e}"))
    })?;
    let utc_dt = dt.with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();
    if utc_dt > now {
        return Err(invalid_params(
            "timestamp cannot be in the future".to_string(),
        ));
    }
    let min_dt = now - chrono::Duration::days(max_age_days);
    if utc_dt < min_dt {
        return Err(invalid_params(format!(
            "timestamp cannot be older than {max_age_days} days, got '{trimmed}'"
        )));
    }
    Ok(utc_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Validate a classification and determination pair per R-13. Errors name `determination`.
pub fn validate_classification_pair(
    classification: Option<Classification>,
    determination: Option<Determination>,
) -> Result<(), rmcp::ErrorData> {
    match (classification, determination) {
        (None, Some(_)) => {
            Err(invalid_params("determination requires classification to be specified"))
        }
        (Some(c), Some(d)) => {
            let allowed = Determination::allowed_for(c);
            if !allowed.contains(&d) {
                let valid_str = allowed
                    .iter()
                    .map(|item| item.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(invalid_params(format!(
                    "determination '{}' is not valid for classification '{}'; valid: {}",
                    d.as_str(),
                    c.as_str(),
                    valid_str
                )));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- encode_path_segment ---
    #[test]
    fn test_encode_path_segment_unreserved() {
        let unreserved = "abc-123_test.foo~bar";
        assert_eq!(encode_path_segment(unreserved).to_string(), unreserved);
    }

    #[test]
    fn test_encode_path_segment_reserved_and_unicode() {
        assert_eq!(encode_path_segment("foo/bar").to_string(), "foo%2Fbar");
        assert_eq!(
            encode_path_segment("id with spaces").to_string(),
            "id%20with%20spaces"
        );
        assert_eq!(encode_path_segment("a+b== ").to_string(), "a%2Bb%3D%3D%20");
        assert_eq!(
            encode_path_segment("CVE-2023-1234").to_string(),
            "CVE-2023-1234"
        );
        assert_eq!(encode_path_segment("testé").to_string(), "test%C3%A9");
    }

    // --- hostname ---
    #[test]
    fn test_hostname_valid_domain() {
        assert_eq!(validate_hostname("contoso.com").unwrap(), "contoso.com");
        assert_eq!(
            validate_hostname("sub.domain.example.com").unwrap(),
            "sub.domain.example.com"
        );
    }

    #[test]
    fn test_hostname_valid_ip() {
        assert_eq!(validate_hostname("1.2.3.4").unwrap(), "1.2.3.4");
    }

    #[test]
    fn test_hostname_whitespace_trim() {
        assert_eq!(
            validate_hostname("   contoso.com   ").unwrap(),
            "contoso.com"
        );
    }

    #[test]
    fn test_hostname_empty() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("   ").is_err());
    }

    #[test]
    fn test_hostname_with_slash() {
        assert!(validate_hostname("evil.com/path").is_err());
    }

    #[test]
    fn test_hostname_with_control_chars() {
        assert!(validate_hostname("evil\x00.com").is_err());
    }

    #[test]
    fn test_hostname_with_internal_whitespace() {
        assert!(validate_hostname("evil .com").is_err());
        assert!(validate_hostname("evil\t.com").is_err());
    }

    #[test]
    fn test_hostname_dot_segments() {
        assert!(validate_hostname(".").is_err());
        assert!(validate_hostname("..").is_err());
        assert!(validate_hostname("evil..com").is_err());
    }

    #[test]
    fn test_hostname_exceeds_max_length() {
        let long_name = "a".repeat(254);
        assert!(validate_hostname(&long_name).is_err());
        let max_name = "a".repeat(253);
        assert!(validate_hostname(&max_name).is_ok());
    }

    // --- required_id ---
    #[test]
    fn test_required_id_valid() {
        assert_eq!(validate_required_id("abc123", "id").unwrap(), "abc123");
    }

    #[test]
    fn test_required_id_whitespace_trim() {
        assert_eq!(
            validate_required_id("   abc123   ", "id").unwrap(),
            "abc123"
        );
    }

    #[test]
    fn test_required_id_base64_and_reserved() {
        // Base64 IDs and characters like slash and plus are permitted because callers percent-encode them
        assert_eq!(
            validate_required_id("a/b+c==", "indicator_id").unwrap(),
            "a/b+c=="
        );
        assert_eq!(
            validate_required_id("user@contoso.com", "user_id").unwrap(),
            "user@contoso.com"
        );
    }

    #[test]
    fn test_required_id_empty() {
        assert!(validate_required_id("", "id").is_err());
        assert!(validate_required_id("   ", "id").is_err());
    }

    #[test]
    fn test_required_id_dot_traversal() {
        assert!(validate_required_id(".", "id").is_err());
        assert!(validate_required_id("..", "id").is_err());
        assert!(validate_required_id(" . ", "id").is_err());
        assert!(validate_required_id(" .. ", "id").is_err());
    }

    #[test]
    fn test_required_id_control() {
        assert!(validate_required_id("abc\t123", "id").is_err());
        assert!(validate_required_id("abc\x00123", "id").is_err());
        assert!(validate_required_id("abc\n123", "id").is_err());
    }

    // --- IP address ---
    #[test]
    fn test_ip_valid_v4() {
        assert_eq!(
            validate_ip_address("10.209.67.177").unwrap(),
            "10.209.67.177"
        );
    }

    #[test]
    fn test_ip_valid_v6() {
        assert_eq!(validate_ip_address("::1").unwrap(), "::1");
        assert_eq!(validate_ip_address("2001:db8::1").unwrap(), "2001:db8::1");
    }

    #[test]
    fn test_ip_whitespace_trim() {
        assert_eq!(
            validate_ip_address("  10.209.67.177  ").unwrap(),
            "10.209.67.177"
        );
    }

    #[test]
    fn test_ip_empty() {
        assert!(validate_ip_address("").is_err());
        assert!(validate_ip_address("   ").is_err());
    }

    #[test]
    fn test_ip_slash_cidr_rejected() {
        assert!(validate_ip_address("10.0.0.0/24").is_err());
    }

    #[test]
    fn test_ip_malformed_rejected() {
        // Octets > 255 previously bypassed naive string checks
        assert!(validate_ip_address("999.999.999.999").is_err());
        assert!(validate_ip_address("1.2.3.4.5").is_err());
        assert!(validate_ip_address("1.2.3").is_err());
        assert!(validate_ip_address("not-an-ip").is_err());
        assert!(validate_ip_address("2001:xyz::1").is_err());
    }

    // --- SHA1 ---
    #[test]
    fn test_sha1_valid() {
        assert_eq!(
            validate_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_sha1_invalid() {
        assert!(validate_sha1("not-a-hash").is_err());
        assert!(validate_sha1("abc123").is_err());
    }

    // --- file hash ---
    #[test]
    fn test_file_hash_sha1() {
        assert_eq!(
            validate_file_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_file_hash_md5() {
        assert_eq!(
            validate_file_hash("d41d8cd98f00b204e9800998ecf8427e").unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn test_file_hash_sha256() {
        assert_eq!(
            validate_file_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_file_hash_whitespace_trim() {
        assert_eq!(
            validate_file_hash("  d41d8cd98f00b204e9800998ecf8427e  ").unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn test_file_hash_invalid() {
        assert!(validate_file_hash("short").is_err());
        assert!(validate_file_hash("g41d8cd98f00b204e9800998ecf8427e").is_err());
    }

    // --- CVE ---
    #[test]
    fn test_cve_valid() {
        assert_eq!(validate_cve_id("CVE-2021-44228").unwrap(), "CVE-2021-44228");
    }

    #[test]
    fn test_cve_invalid_format() {
        assert!(validate_cve_id("CVE-2021").is_err());
        assert!(validate_cve_id("cve-2021-44228").is_err());
    }

    #[test]
    fn test_cve_empty() {
        assert!(validate_cve_id("").is_err());
    }

    // --- tag_name ---
    #[test]
    fn test_tag_name_valid() {
        assert_eq!(validate_tag_name("production").unwrap(), "production");
        assert_eq!(validate_tag_name("dept/finance").unwrap(), "dept/finance");
        assert_eq!(validate_tag_name("tag.v1.0").unwrap(), "tag.v1.0");
        assert_eq!(validate_tag_name("  tag-name  ").unwrap(), "tag-name");
    }

    #[test]
    fn test_tag_name_empty() {
        assert!(validate_tag_name("").is_err());
        assert!(validate_tag_name("   ").is_err());
    }

    #[test]
    fn test_tag_name_control() {
        assert!(validate_tag_name("tag\tname").is_err());
        assert!(validate_tag_name("tag\0name").is_err());
    }

    // --- file_name ---
    #[test]
    fn test_file_name_valid() {
        assert_eq!(validate_file_name("script.ps1").unwrap(), "script.ps1");
        assert_eq!(
            validate_file_name("  remediation.py  ").unwrap(),
            "remediation.py"
        );
    }

    #[test]
    fn test_file_name_empty() {
        assert!(validate_file_name("").is_err());
        assert!(validate_file_name("   ").is_err());
    }

    #[test]
    fn test_file_name_dot_segments() {
        assert!(validate_file_name(".").is_err());
        assert!(validate_file_name("..").is_err());
        assert!(validate_file_name(" . ").is_err());
        assert!(validate_file_name(" .. ").is_err());
    }

    #[test]
    fn test_file_name_path_traversal() {
        assert!(validate_file_name("../script.ps1").is_err());
        assert!(validate_file_name("..\\script.ps1").is_err());
        assert!(validate_file_name("subdir/test.txt").is_err());
        assert!(validate_file_name("subdir\\test.txt").is_err());
    }

    #[test]
    fn test_file_name_control() {
        assert!(validate_file_name("script\x00.ps1").is_err());
        assert!(validate_file_name("script\n.ps1").is_err());
    }

    // --- description ---
    #[test]
    fn test_description_valid() {
        let desc = "Upload script for remediation:\n- Step 1: scan\n- Path: /tmp/output\t(allowed)";
        assert_eq!(validate_description(desc).unwrap(), desc);
        assert_eq!(
            validate_description("   trimmed text   ").unwrap(),
            "trimmed text"
        );
    }

    #[test]
    fn test_description_empty() {
        assert!(validate_description("").is_err());
        assert!(validate_description("   ").is_err());
    }

    #[test]
    fn test_description_null_and_control_rejected() {
        assert!(validate_description("description\0with null").is_err());
        assert!(validate_description("description\x07with bell").is_err());
    }

    // --- top ---
    #[test]
    fn test_top_valid() {
        assert!(validate_top(Some(50)).is_ok());
        assert!(validate_top(None).is_ok());
    }

    #[test]
    fn test_top_zero() {
        assert!(validate_top(Some(0)).is_err());
    }

    #[test]
    fn test_top_exceeds_max() {
        assert!(validate_top(Some(2000)).is_err());
    }

    // --- skip ---
    #[test]
    fn test_skip_valid() {
        assert!(validate_skip(Some(0)).is_ok());
        assert!(validate_skip(None).is_ok());
    }

    #[test]
    fn test_skip_negative() {
        assert!(validate_skip(Some(-1)).is_err());
    }

    // --- KQL ---
    #[test]
    fn test_kql_valid_simple() {
        assert!(validate_kql_query("DeviceProcessEvents | take 5").is_ok());
    }

    #[test]
    fn test_kql_benign_literals_and_comments() {
        // Query containing "update package" in string literal must not be rejected by substring blacklist
        assert!(
            validate_kql_query(
                r#"DeviceProcessEvents | where ProcessCommandLine contains "update package""#
            )
            .is_ok()
        );

        // Query with SQL-like comment must be allowed
        assert!(validate_kql_query("// DROP TABLE foo\nDeviceProcessEvents | take 10").is_ok());

        // Query with string literal containing mutation-sounding phrase
        assert!(
            validate_kql_query(r#"DeviceEvents | where AdditionalFields has "DROP TABLE""#).is_ok()
        );
        assert!(
            validate_kql_query(r#"DeviceNetworkEvents | where RemoteUrl contains "delete from""#)
                .is_ok()
        );
    }

    #[test]
    fn test_kql_leading_dot_management_rejected() {
        assert!(validate_kql_query(".drop table foo").is_err());
        assert!(validate_kql_query("  .alter cluster foo  ").is_err());
        assert!(validate_kql_query(".create table bar (x: string)").is_err());
    }

    #[test]
    fn test_kql_empty() {
        assert!(validate_kql_query("").is_err());
        assert!(validate_kql_query("   ").is_err());
    }

    #[test]
    fn test_kql_exceeds_max_length() {
        let oversized = "a".repeat(128_001);
        assert!(validate_kql_query(&oversized).is_err());
        let at_limit = "a".repeat(128_000);
        assert!(validate_kql_query(&at_limit).is_ok());
    }

    // --- look back hours ---
    #[test]
    fn test_look_back_valid() {
        assert!(validate_look_back_hours(Some(720)).is_ok());
        assert!(validate_look_back_hours(None).is_ok());
    }

    #[test]
    fn test_look_back_zero() {
        assert!(validate_look_back_hours(Some(0)).is_err());
    }

    #[test]
    fn test_look_back_exceeds() {
        assert!(validate_look_back_hours(Some(721)).is_err());
    }

    // --- Live Response commands ---
    fn make_cmd(
        cmd_type: crate::server::LiveResponseCommandType,
    ) -> crate::server::LiveResponseCommand {
        crate::server::LiveResponseCommand {
            cmd_type,
            params: vec![crate::server::LiveResponseParam {
                key: "Path".to_string(),
                value: "C:\\test.txt".to_string(),
            }],
        }
    }

    #[test]
    fn test_lr_commands_empty_rejected() {
        let result = validate_live_response_commands(&[], None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("cannot be empty"));
    }

    #[test]
    fn test_lr_commands_too_many_rejected() {
        let mut cmds = Vec::new();
        for _ in 0..21 {
            cmds.push(make_cmd(crate::server::LiveResponseCommandType::GetFile));
        }
        let result = validate_live_response_commands(&cmds, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("exceeds maximum"));
    }

    #[test]
    fn test_lr_commands_valid_accepted() {
        let cmds = vec![
            make_cmd(crate::server::LiveResponseCommandType::GetFile),
            make_cmd(crate::server::LiveResponseCommandType::RunScript),
        ];
        assert!(validate_live_response_commands(&cmds, None).is_ok());
    }

    #[test]
    fn test_lr_commands_allowlist_passes() {
        let allowed = vec!["GetFile".to_string(), "RunScript".to_string()];
        let cmds = vec![
            make_cmd(crate::server::LiveResponseCommandType::GetFile),
            make_cmd(crate::server::LiveResponseCommandType::RunScript),
        ];
        assert!(validate_live_response_commands(&cmds, Some(&allowed)).is_ok());
    }

    #[test]
    fn test_lr_commands_allowlist_rejected() {
        let allowed = vec!["GetFile".to_string()];
        let cmds = vec![make_cmd(crate::server::LiveResponseCommandType::RunScript)];
        let result = validate_live_response_commands(&cmds, Some(&allowed));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not in the allowed list"));
    }

    // --- Live Response comment ---
    #[test]
    fn test_lr_comment_valid_ascii() {
        assert_eq!(
            validate_comment(
                "Investigating suspicious process on the endpoint",
                "comment"
            )
            .unwrap(),
            "Investigating suspicious process on the endpoint"
        );
    }

    #[test]
    fn test_lr_comment_short_rejected() {
        let result = validate_comment("short", "comment");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("must be at least"));
    }

    #[test]
    fn test_lr_comment_empty_rejected() {
        assert!(validate_comment("", "comment").is_err());
        assert!(validate_comment("          ", "comment").is_err());
    }

    #[test]
    fn test_lr_comment_multibyte_boundary() {
        // 5 multibyte characters (15 UTF-8 bytes) -> rejected because character count 5 < 10
        let short_multibyte = "你好世界！";
        assert_eq!(short_multibyte.len(), 15);
        assert_eq!(short_multibyte.chars().count(), 5);
        assert!(validate_comment(short_multibyte, "comment").is_err());

        // 10 multibyte characters (30 UTF-8 bytes) -> accepted because character count 10 >= 10
        let valid_multibyte = "你好世界！你好世界！";
        assert_eq!(valid_multibyte.chars().count(), 10);
        assert_eq!(
            validate_comment(valid_multibyte, "comment").unwrap(),
            valid_multibyte
        );
    }

    #[test]
    fn test_lr_comment_whitespace_trim() {
        assert_eq!(
            validate_comment(
                "   Investigating suspicious process on endpoint   ",
                "comment"
            )
            .unwrap(),
            "Investigating suspicious process on endpoint"
        );
    }

    #[test]
    fn test_validate_machine_id() {
        let valid = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07";
        assert_eq!(validate_machine_id(valid).unwrap(), valid);
        assert!(validate_machine_id("invalid-id").is_err());
        assert!(validate_machine_id("1e5bc9d7e413ddd7902c2932e418702b84d0cc0").is_err()); // 39 chars
    }

    #[test]
    fn test_validate_action_id() {
        let valid = "7327b54fd718525cbca07dacde913b5ac3c85673";
        assert_eq!(validate_action_id(valid).unwrap(), valid);
        assert!(validate_action_id("").is_err());
        assert!(validate_action_id("..").is_err());
        assert!(validate_action_id("../etc/passwd").is_err());
        assert!(validate_action_id("action/id").is_err());
        assert!(validate_action_id("action\\id").is_err());
    }

    #[test]
    fn test_validate_text_boundaries() {
        // Empty / whitespace
        assert!(validate_text("", 10, "title").is_err());
        assert!(validate_text("   ", 10, "title").is_err());

        // Length boundaries
        let exact = "1234567890";
        assert_eq!(validate_text(exact, 10, "title").unwrap(), exact);
        let too_long = "12345678901";
        let err = validate_text(too_long, 10, "title").unwrap_err();
        assert!(err.message.contains("title exceeds maximum length of 10"));

        // Control characters: disallowed in generic text
        assert!(validate_text("hello\nworld", 20, "title").is_err());
        assert!(validate_text("hello\tworld", 20, "title").is_err());
        assert!(validate_text("hello\0world", 20, "title").is_err());

        // Control characters in comments: newlines and tabs allowed, NUL disallowed
        assert_eq!(
            validate_text("line1\nline2\ttab", 50, "comment").unwrap(),
            "line1\nline2\ttab"
        );
        assert_eq!(
            validate_text("justification\ntext", 50, "justification").unwrap(),
            "justification\ntext"
        );
        assert!(validate_text("bad\0comment", 50, "comment").is_err());
    }

    #[test]
    fn test_validate_batch_boundaries() {
        // Empty batch
        let empty: Vec<String> = vec![];
        let err_empty = validate_batch(&empty, 3, "ids").unwrap_err();
        assert!(err_empty.message.contains("ids cannot be empty"));
        assert!(err_empty.message.contains("between 1 and 3"));

        // Within limits
        let one = vec!["id-1"];
        assert!(validate_batch(&one, 3, "ids").is_ok());

        let three = vec!["id-1", "id-2", "id-3"];
        assert!(validate_batch(&three, 3, "ids").is_ok());

        // Exceeds max
        let four = vec!["id-1", "id-2", "id-3", "id-4"];
        let err_four = validate_batch(&four, 3, "ids").unwrap_err();
        assert!(err_four.message.contains("ids exceeds maximum batch size of 3 items (got 4)"));

        // Invalid ID inside batch
        let invalid_item = vec!["id-1", "..", "id-3"];
        let err_item = validate_batch(&invalid_item, 3, "ids").unwrap_err();
        assert!(err_item.message.contains("ids cannot be '.' or '..'"));

        let empty_item = vec!["id-1", "   ", "id-3"];
        let err_empty_item = validate_batch(&empty_item, 3, "ids").unwrap_err();
        assert!(err_empty_item.message.contains("ids cannot be empty"));
    }

    #[test]
    fn test_validate_tag() {
        assert!(validate_tag("").is_err());
        assert!(validate_tag("   ").is_err());
        assert!(validate_tag("server-prod").is_ok());
        assert_eq!(validate_tag("  tier-1  ").unwrap(), "tier-1");

        let exact_200 = "a".repeat(200);
        assert_eq!(validate_tag(&exact_200).unwrap(), exact_200.as_str());

        let too_long = "a".repeat(201);
        let err = validate_tag(&too_long).unwrap_err();
        assert!(err.message.contains("tag exceeds maximum length of 200"));

        let with_ctrl = "tag\nwith\tcontrol";
        let err_ctrl = validate_tag(with_ctrl).unwrap_err();
        assert!(err_ctrl.message.contains("tag contains invalid control characters"));
    }

    #[test]
    fn test_validate_hex() {
        let sha1 = "1234567890abcdef1234567890abcdef12345678";
        assert_eq!(validate_hex(sha1, 40, "sha1").unwrap(), sha1);

        // Short
        let short = "1234567890abcdef1234567890abcdef1234567";
        let err_short = validate_hex(short, 40, "sha1").unwrap_err();
        assert!(err_short.message.contains("sha1 must be a 40-character hex string"));

        // Non-hex
        let non_hex = "1234567890abcdef1234567890abcdef1234567g";
        let err_non_hex = validate_hex(non_hex, 40, "sha1").unwrap_err();
        assert!(err_non_hex.message.contains("sha1 must be a 40-character hex string"));
    }

    #[test]
    fn test_validate_url_indicator() {
        assert!(validate_url_indicator("https://example.com/malware.exe").is_ok());
        assert!(validate_url_indicator("http://example.com").is_ok());

        // Non-http/https
        let ftp = validate_url_indicator("ftp://example.com/file").unwrap_err();
        assert!(ftp.message.contains("indicator_value URL must use http or https scheme"));

        let no_host = validate_url_indicator("https://").unwrap_err();
        assert!(no_host.message.contains("indicator_value"));
        // Invalid URL
        assert!(validate_url_indicator("not a url").is_err());
    }

    #[test]
    fn test_validate_domain_indicator() {
        assert!(validate_domain_indicator("example.com").is_ok());
        assert!(validate_domain_indicator("sub.domain.co.uk").is_ok());

        // IP literal rejected
        let ip_err = validate_domain_indicator("192.168.1.1").unwrap_err();
        assert!(ip_err.message.contains("indicator_value for DomainName must not be an IP address"));

        let ipv6_err = validate_domain_indicator("::1").unwrap_err();
        assert!(ipv6_err.message.contains("indicator_value for DomainName must not be an IP address"));

        // Invalid hostname
        assert!(validate_domain_indicator("http://example.com").is_err());
    }

    #[test]
    fn test_validate_indicator_value() {
        let sha1 = "1234567890abcdef1234567890abcdef12345678";
        assert!(validate_indicator_value(IndicatorType::FileSha1, sha1).is_ok());
        assert!(validate_indicator_value(IndicatorType::CertificateThumbprint, sha1).is_ok());
        assert!(validate_indicator_value(IndicatorType::FileSha1, "short").is_err());

        let sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(validate_indicator_value(IndicatorType::FileSha256, sha256).is_ok());
        assert!(validate_indicator_value(IndicatorType::FileSha256, sha1).is_err());

        let md5 = "1234567890abcdef1234567890abcdef";
        assert!(validate_indicator_value(IndicatorType::FileMd5, md5).is_ok());
        assert!(validate_indicator_value(IndicatorType::FileMd5, sha1).is_err());

        assert!(validate_indicator_value(IndicatorType::IpAddress, "192.168.1.1").is_ok());
        assert!(validate_indicator_value(IndicatorType::IpAddress, "2001:db8::1").is_ok());
        assert!(validate_indicator_value(IndicatorType::IpAddress, "999.999.999.999").is_err());

        assert!(validate_indicator_value(IndicatorType::DomainName, "contoso.com").is_ok());
        assert!(validate_indicator_value(IndicatorType::DomainName, "192.168.1.1").is_err());

        assert!(validate_indicator_value(IndicatorType::Url, "https://contoso.com/evil").is_ok());
        assert!(validate_indicator_value(IndicatorType::Url, "ftp://evil.com").is_err());
    }

    #[test]
    fn test_validate_indicator_action() {
        // BlockAndRemediate
        assert!(validate_indicator_action(IndicatorType::FileSha256, IndicatorAction::BlockAndRemediate, None).is_ok());
        assert!(validate_indicator_action(IndicatorType::CertificateThumbprint, IndicatorAction::BlockAndRemediate, None).is_ok());
        let bar_url = validate_indicator_action(IndicatorType::Url, IndicatorAction::BlockAndRemediate, None).unwrap_err();
        assert!(bar_url.message.contains("BlockAndRemediate"));

        // Warn
        assert!(validate_indicator_action(IndicatorType::Url, IndicatorAction::Warn, None).is_ok());
        assert!(validate_indicator_action(IndicatorType::DomainName, IndicatorAction::Warn, None).is_ok());
        assert!(validate_indicator_action(IndicatorType::IpAddress, IndicatorAction::Warn, None).is_ok());
        let warn_sha = validate_indicator_action(IndicatorType::FileSha256, IndicatorAction::Warn, None).unwrap_err();
        assert!(warn_sha.message.contains("Warn"));

        // Audit
        assert!(validate_indicator_action(IndicatorType::FileSha256, IndicatorAction::Audit, None).is_ok());
        assert!(validate_indicator_action(IndicatorType::FileSha256, IndicatorAction::Audit, Some(true)).is_ok());
        let audit_false = validate_indicator_action(IndicatorType::FileSha256, IndicatorAction::Audit, Some(false)).unwrap_err();
        assert!(audit_false.message.contains("generate_alert must be true"));
    }

    #[test]
    fn test_indicator_action_deserialize_legacy_alert_and_block() {
        let allowed: IndicatorAction = serde_json::from_str("\"Allowed\"").unwrap();
        assert_eq!(allowed, IndicatorAction::Allowed);

        let err_alert: Result<IndicatorAction, _> = serde_json::from_str("\"Alert\"");
        let msg_alert = err_alert.unwrap_err().to_string();
        assert!(msg_alert.contains("legacy, unsupported since January 2022"));

        let err_both: Result<IndicatorAction, _> = serde_json::from_str("\"AlertAndBlock\"");
        let msg_both = err_both.unwrap_err().to_string();
        assert!(msg_both.contains("legacy, unsupported since January 2022"));
    }

    #[test]
    fn test_validate_future_rfc3339() {
        let future = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        assert!(validate_future_rfc3339(&future, "expiration_time").is_ok());

        let past = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let err_past = validate_future_rfc3339(&past, "expiration_time").unwrap_err();
        assert!(err_past.message.contains("expiration_time must be in the future"));

        assert!(validate_future_rfc3339("not-a-date", "expiration_time").is_err());
    }

    #[test]
    fn test_validate_recent_timestamp() {
        let now = chrono::Utc::now();
        let valid = (now - chrono::Duration::days(5)).to_rfc3339();
        let res = validate_recent_timestamp(&valid, 30).unwrap();
        assert!(res.ends_with('Z'));

        let future = (now + chrono::Duration::minutes(5)).to_rfc3339();
        let err_future = validate_recent_timestamp(&future, 30).unwrap_err();
        assert!(err_future.message.contains("timestamp cannot be in the future"));

        let old = (now - chrono::Duration::days(31)).to_rfc3339();
        let err_old = validate_recent_timestamp(&old, 30).unwrap_err();
        assert!(err_old.message.contains("timestamp cannot be older than 30 days"));
    }

    #[test]
    fn test_validate_classification_pair() {
        // determination without classification
        let err_orphan = validate_classification_pair(None, Some(Determination::Malware)).unwrap_err();
        assert!(err_orphan.message.contains("determination requires classification"));

        // valid pair
        assert!(validate_classification_pair(Some(Classification::TruePositive), Some(Determination::Malware)).is_ok());
        assert!(validate_classification_pair(Some(Classification::FalsePositive), Some(Determination::NotMalicious)).is_ok());

        // invalid pair with exact required format
        let err_invalid = validate_classification_pair(Some(Classification::FalsePositive), Some(Determination::Malware)).unwrap_err();
        assert_eq!(
            err_invalid.message,
            "determination 'malware' is not valid for classification 'falsePositive'; valid: notMalicious, notEnoughDataToValidate, other"
        );
    }

    #[test]
    fn test_triage_wire_spellings_per_target() {
        use crate::server::TriageTarget;

        // Determination wire spellings
        assert_eq!(Determination::ConfirmedActivity.wire(TriageTarget::MdeAlertPatch), "ConfirmedActivity");
        assert_eq!(Determination::ConfirmedActivity.wire(TriageTarget::MdeAlertBatch), "ConfirmedUserActivity");
        assert_eq!(Determination::ConfirmedActivity.wire(TriageTarget::XdrAlert), "confirmedActivity");

        assert_eq!(Determination::NotMalicious.wire(TriageTarget::MdeAlertPatch), "NotMalicious");
        assert_eq!(Determination::NotMalicious.wire(TriageTarget::MdeAlertBatch), "Clean");
        assert_eq!(Determination::NotMalicious.wire(TriageTarget::XdrAlert), "notMalicious");

        assert_eq!(Determination::CompromisedAccount.wire(TriageTarget::MdeAlertPatch), "CompromisedUser");
        assert_eq!(Determination::CompromisedAccount.wire(TriageTarget::MdeAlertBatch), "CompromisedUser");
        assert_eq!(Determination::CompromisedAccount.wire(TriageTarget::XdrIncident), "compromisedAccount");

        assert_eq!(Determination::NotEnoughDataToValidate.wire(TriageTarget::MdeAlertPatch), "InsufficientData");
        assert_eq!(Determination::NotEnoughDataToValidate.wire(TriageTarget::MdeAlertBatch), "InsufficientData");
        assert_eq!(Determination::NotEnoughDataToValidate.wire(TriageTarget::XdrAlert), "notEnoughDataToValidate");

        // Classification wire spellings
        assert_eq!(Classification::TruePositive.wire(TriageTarget::MdeAlertPatch), "TruePositive");
        assert_eq!(Classification::TruePositive.wire(TriageTarget::XdrAlert), "truePositive");

        // TriageStatus wire spellings
        use crate::server::TriageStatus;
        assert_eq!(TriageStatus::New.wire(TriageTarget::MdeAlertPatch).unwrap(), "New");
        assert_eq!(TriageStatus::New.wire(TriageTarget::XdrAlert).unwrap(), "new");
        assert!(TriageStatus::New.wire(TriageTarget::XdrIncident).is_err());
        assert!(TriageStatus::Active.wire(TriageTarget::MdeAlertPatch).is_err());
        assert_eq!(TriageStatus::Active.wire(TriageTarget::XdrIncident).unwrap(), "active");
    }
}
