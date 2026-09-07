//! Input validation helpers for MCP tool parameters.

use std::net::IpAddr;
use std::sync::LazyLock;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;

use crate::constants::{ENDPOINT_MAX_TOP, MAX_SKIP, MAX_TOP};
use crate::error::invalid_params;

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

/// Validate the Live Response commands array.
pub fn validate_live_response_commands(
    commands: &[crate::server::LiveResponseCommand],
) -> Result<(), rmcp::ErrorData> {
    let allowed: Option<Vec<String>> =
        std::env::var(crate::constants::ENV_LIVE_RESPONSE_ALLOWED_COMMANDS)
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            });

    validate_live_response_commands_with_allowlist(commands, allowed.as_deref())
}

/// Pure helper for validating Live Response commands with an optional allowlist.
/// Extracted so unit tests can test allowlist rules without mutating global process environment.
fn validate_live_response_commands_with_allowlist(
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

/// Validate the Live Response comment.
///
/// Returns the trimmed comment slice. Requires at least 10 trimmed characters
/// (based on Unicode character count, not raw byte length) describing the purpose.
pub fn validate_live_response_comment(comment: &str) -> Result<&str, rmcp::ErrorData> {
    let trimmed = comment.trim();
    if trimmed.chars().count() < crate::constants::MIN_LIVE_RESPONSE_COMMENT_LEN {
        return Err(invalid_params(format!(
            "comment must be at least {} trimmed characters describing the purpose of this live response action",
            crate::constants::MIN_LIVE_RESPONSE_COMMENT_LEN
        )));
    }
    Ok(trimmed)
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
        let result = validate_live_response_commands_with_allowlist(&[], None);
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
        let result = validate_live_response_commands_with_allowlist(&cmds, None);
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
        assert!(validate_live_response_commands_with_allowlist(&cmds, None).is_ok());
    }

    #[test]
    fn test_lr_commands_allowlist_passes() {
        let allowed = vec!["GetFile".to_string(), "RunScript".to_string()];
        let cmds = vec![
            make_cmd(crate::server::LiveResponseCommandType::GetFile),
            make_cmd(crate::server::LiveResponseCommandType::RunScript),
        ];
        assert!(validate_live_response_commands_with_allowlist(&cmds, Some(&allowed)).is_ok());
    }

    #[test]
    fn test_lr_commands_allowlist_rejected() {
        let allowed = vec!["GetFile".to_string()];
        let cmds = vec![make_cmd(crate::server::LiveResponseCommandType::RunScript)];
        let result = validate_live_response_commands_with_allowlist(&cmds, Some(&allowed));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not in the allowed list"));
    }

    // --- Live Response comment ---
    #[test]
    fn test_lr_comment_valid_ascii() {
        assert_eq!(
            validate_live_response_comment("Investigating suspicious process on the endpoint")
                .unwrap(),
            "Investigating suspicious process on the endpoint"
        );
    }

    #[test]
    fn test_lr_comment_short_rejected() {
        let result = validate_live_response_comment("short");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("must be at least"));
    }

    #[test]
    fn test_lr_comment_empty_rejected() {
        assert!(validate_live_response_comment("").is_err());
        assert!(validate_live_response_comment("          ").is_err());
    }

    #[test]
    fn test_lr_comment_multibyte_boundary() {
        // 5 multibyte characters (15 UTF-8 bytes) -> rejected because character count 5 < 10
        let short_multibyte = "你好世界！";
        assert_eq!(short_multibyte.len(), 15);
        assert_eq!(short_multibyte.chars().count(), 5);
        assert!(validate_live_response_comment(short_multibyte).is_err());

        // 10 multibyte characters (30 UTF-8 bytes) -> accepted because character count 10 >= 10
        let valid_multibyte = "你好世界！你好世界！";
        assert_eq!(valid_multibyte.chars().count(), 10);
        assert_eq!(
            validate_live_response_comment(valid_multibyte).unwrap(),
            valid_multibyte
        );
    }

    #[test]
    fn test_lr_comment_whitespace_trim() {
        assert_eq!(
            validate_live_response_comment("   Investigating suspicious process on endpoint   ")
                .unwrap(),
            "Investigating suspicious process on endpoint"
        );
    }
}
