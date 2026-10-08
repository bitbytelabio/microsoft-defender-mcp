//! Error types and helpers for the Microsoft Defender MCP server.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;
use serde_json::json;

use crate::auth::{AuthKind, PermissionCategory};

/// Note appended for operations Microsoft documents as application-only.
pub const APP_ONLY_NOTE: &str =
    "Microsoft documents only an application permission for this operation.";

/// Build a tool-level error result that is visible to the LLM agent.
pub fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({"error": message.into()}))
}

/// Build a tool-level error from an HTTP status code, auth kind, and permission category.
pub fn http_error(
    status_code: u16,
    context: &str,
    auth_kind: AuthKind,
    category: PermissionCategory,
) -> CallToolResult {
    match auth_kind {
        AuthKind::App => {
            let msg = match status_code {
                400 => format!("Bad request: {context}. Check input parameters."),
                401 => "Authentication failed. Check AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET.".to_string(),
                403 => format!("Permission denied for: {context}. Ensure the application registration has the required permissions and the tenant has appropriate licenses."),
                404 => format!("Resource not found: {context}. Check that the identifier is correct."),
                429 => format!("Rate limit exceeded for: {context}. Wait before retrying the request."),
                504 => "Request timed out. The query may be too complex or the service is busy. Try simplifying the query or narrowing the timespan.".to_string(),
                s => format!("API request failed with HTTP {s} for: {context}."),
            };
            CallToolResult::structured_error(json!({
                "error": msg,
                "httpStatus": status_code,
            }))
        }
        AuthKind::User => match status_code {
            401 => {
                let app_only_suffix = if category.is_app_only() {
                    format!(" {APP_ONLY_NOTE}")
                } else {
                    String::new()
                };
                let msg = format!(
                    "Authentication rejected by {}; re-authentication may be required — restart the server to sign in again.{app_only_suffix}",
                    category.audience()
                );
                CallToolResult::structured_error(json!({
                    "error": msg,
                    "httpStatus": 401,
                }))
            }
            403 => {
                let app_only_suffix = if category.is_app_only() {
                    format!(" {APP_ONLY_NOTE}")
                } else {
                    String::new()
                };
                let msg = format!(
                    "Permission denied for {context}. The signed-in user's own rights apply (Defender role, device-group scope, consented scopes), not the server's. Required: {} — delegated scope {}; Defender role permission '{}'.{app_only_suffix}",
                    category.category_name(),
                    category.delegated_scope(),
                    category.defender_role()
                );
                CallToolResult::structured_error(json!({
                    "error": msg,
                    "httpStatus": 403,
                    "permission_category": category.wire_name(),
                }))
            }
            400 => CallToolResult::structured_error(json!({
                "error": format!("Bad request: {context}. Check input parameters."),
                "httpStatus": 400,
            })),
            404 => CallToolResult::structured_error(json!({
                "error": format!("Resource not found: {context}. Check that the identifier is correct."),
                "httpStatus": 404,
            })),
            429 => CallToolResult::structured_error(json!({
                "error": format!("Rate limit exceeded for: {context}. Wait before retrying the request."),
                "httpStatus": 429,
            })),
            504 => CallToolResult::structured_error(json!({
                "error": "Request timed out. The query may be too complex or the service is busy. Try simplifying the query or narrowing the timespan.",
                "httpStatus": 504,
            })),
            s => CallToolResult::structured_error(json!({
                "error": format!("API request failed with HTTP {s} for: {context}."),
                "httpStatus": s,
            })),
        },
    }
}

/// Build a tool-level error from a network/transport error.
pub fn network_error(err: &reqwest::Error, context: &str) -> CallToolResult {
    if err.is_timeout() {
        tool_error(format!(
            "Request timed out for: {context}. Try narrowing the query scope."
        ))
    } else if err.is_connect() {
        tool_error(format!(
            "Connection failed for: {context}. Check network connectivity and service reachability."
        ))
    } else {
        tool_error(format!("Network error for {context}: {err}"))
    }
}

/// Build a protocol-level internal error.
pub fn internal_error(message: impl Into<std::borrow::Cow<'static, str>>) -> McpError {
    McpError::internal_error(message, None)
}

/// Build a protocol-level invalid params error.
pub fn invalid_params(message: impl Into<std::borrow::Cow<'static, str>>) -> McpError {
    McpError::invalid_params(message, None)
}

/// Build a structured error for read-only violations.
pub fn read_only_violation(tool_or_action: &str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": format!("Server is operating in read-only mode: mutating operation '{tool_or_action}' is disallowed"),
        "code": "read_only_violation"
    }))
}

/// Build a structured error when a category is disabled.
pub fn category_disabled(flag: &str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": format!("Category is disabled. Enable it with {flag}"),
        "code": "category_disabled"
    }))
}

/// Build a structured error when confirmation prompt cannot be shown.
pub fn confirmation_unavailable() -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": "The client cannot show confirmation prompts (it did not declare the elicitation capability with form mode). To run destructive tools without confirmation in trusted automation, start the server with --disable-human-confirmation.",
        "code": "confirmation_unavailable"
    }))
}

/// Build a structured error when the user declined or did not confirm an action.
pub fn not_confirmed() -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": "Action not confirmed by user",
        "code": "not_confirmed"
    }))
}

/// Build a structured error when the audit log cannot be written.
pub fn audit_unavailable() -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": "Audit log is not available; mutating action was rejected",
        "code": "audit_unavailable"
    }))
}

/// Build a structured error when re-authentication is required in user mode.
pub fn reauthentication_required(reason: &str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": format!("Re-authentication required ({reason}). Restart the server to sign in again."),
        "code": "reauthentication_required",
        "reason": reason
    }))
}

/// Build a structured error when the signed-in user has not consented to audience scopes.
pub fn consent_missing(audience: &str, scopes: &[String]) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": format!(
            "The signed-in user has not consented to {audience} scopes ({}); an administrator must grant consent, then restart the server.",
            scopes.join(" ")
        ),
        "code": "consent_missing",
        "audience": audience
    }))
}

/// Build a structured error when a write-named scope was not requested under `--read-only`.
pub fn scope_not_requested(action: &str, scope: &str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": format!("{action} needs {scope}, which is write-named and is not requested under --read-only"),
        "code": "scope_not_requested"
    }))
}

/// Build a protocol-level error for unknown tool actions.
pub fn unknown_action_error(tool: &str, action: &str, valid_actions: &[&str]) -> McpError {
    McpError::invalid_params(
        format!(
            "Unknown action '{action}' for tool '{tool}'. Valid actions are: {}",
            valid_actions.join(", ")
        ),
        None,
    )
}

/// Build a tool-level error for an investigation package that is still in progress (HTTP 404).
pub fn package_not_ready(status: &str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": format!("Investigation package is not ready yet (current status: {status}). Please retry when status is Succeeded."),
        "httpStatus": 404,
        "status": status,
    }))
}

/// Build a tool-level error for artifact download and staging filesystem failures.
pub fn staging_filesystem_error(err: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": format!("Filesystem error in artifact staging directory: {err}"),
        "code": "filesystem_error"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_structured(res: &CallToolResult) -> serde_json::Value {
        assert_eq!(res.is_error, Some(true));
        res.structured_content.clone().expect("structured_content")
    }

    #[test]
    fn test_user_mode_403_wording_and_category() {
        let err = http_error(
            403,
            "/api/machines",
            AuthKind::User,
            PermissionCategory::ReadEndpoint,
        );
        let json = parse_structured(&err);
        assert_eq!(json["httpStatus"], 403);
        assert_eq!(json["permission_category"], "read_endpoint");
        let msg = json["error"].as_str().unwrap();
        assert!(msg.contains("signed-in user's own rights apply"));
        assert!(msg.contains("delegated scope the *.Read equivalents, plus User.Read.All"));
        assert!(msg.contains("Defender role permission 'View data'"));
    }

    #[test]
    fn test_user_mode_401_restart_guidance() {
        let err = http_error(
            401,
            "/api/machines",
            AuthKind::User,
            PermissionCategory::ReadEndpoint,
        );
        let json = parse_structured(&err);
        assert_eq!(json["httpStatus"], 401);
        let msg = json["error"].as_str().unwrap();
        assert!(msg.contains("Authentication rejected by endpoint"));
        assert!(msg.contains("restart the server to sign in again"));
    }

    #[test]
    fn test_app_mode_403_unchanged() {
        let err = http_error(
            403,
            "/api/machines",
            AuthKind::App,
            PermissionCategory::ReadEndpoint,
        );
        let json = parse_structured(&err);
        assert_eq!(json["httpStatus"], 403);
        assert!(json.get("permission_category").is_none());
        let msg = json["error"].as_str().unwrap();
        assert!(msg.contains("Ensure the application registration has the required permissions"));
    }

    #[test]
    fn test_reauthentication_required_contract_shape() {
        let err = reauthentication_required("session_expired");
        let json = parse_structured(&err);
        assert_eq!(json["code"], "reauthentication_required");
        assert_eq!(json["reason"], "session_expired");
        assert_eq!(
            json["error"],
            "Re-authentication required (session_expired). Restart the server to sign in again."
        );
    }

    #[test]
    fn test_consent_missing_contract_shape() {
        let scopes = vec![
            "ThreatHunting.Read.All".to_string(),
            "SecurityAlert.Read.All".to_string(),
        ];
        let err = consent_missing("graph", &scopes);
        let json = parse_structured(&err);
        assert_eq!(json["code"], "consent_missing");
        assert_eq!(json["audience"], "graph");
        assert_eq!(
            json["error"],
            "The signed-in user has not consented to graph scopes (ThreatHunting.Read.All SecurityAlert.Read.All); an administrator must grant consent, then restart the server."
        );
    }

    #[test]
    fn test_scope_not_requested_contract_shape() {
        let err = scope_not_requested("find_by_ip", "Machine.ReadWrite");
        let json = parse_structured(&err);
        assert_eq!(json["code"], "scope_not_requested");
        assert_eq!(
            json["error"],
            "find_by_ip needs Machine.ReadWrite, which is write-named and is not requested under --read-only"
        );
    }
}
