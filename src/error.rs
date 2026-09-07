//! Error types and helpers for the Microsoft Defender MCP server.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;
use serde_json::json;

/// Build a tool-level error result that is visible to the LLM agent.
pub fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({"error": message.into()}))
}

/// Build a tool-level error from an HTTP status code.
pub fn http_error(status_code: u16, context: &str) -> CallToolResult {
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
