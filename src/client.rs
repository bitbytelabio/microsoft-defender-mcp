//! API clients with authentication for both Microsoft Graph and Defender for Endpoint.

use serde_json::Value;

use crate::auth::TokenManager;
use crate::constants::{
    ENDPOINT_BASE_URL, ENDPOINT_SCOPE, ENV_ENDPOINT_BASE_URL, ENV_GRAPH_BASE_URL, GRAPH_BASE_URL,
    GRAPH_SCOPE,
};
use crate::error::{http_error, network_error};

/// OData query parameters for list endpoints.
#[derive(Debug, Default, Clone)]
pub struct ODataParams {
    pub top: Option<i32>,
    pub skip: Option<i32>,
    pub filter: Option<String>,
    pub select: Option<String>,
    pub expand: Option<String>,
    pub search: Option<String>,
    pub count: Option<bool>,
}

impl ODataParams {
    pub fn to_query_vec(&self) -> Vec<(&'static str, String)> {
        let mut params = Vec::new();
        if let Some(top) = self.top {
            params.push(("$top", top.to_string()));
        }
        if let Some(skip) = self.skip {
            params.push(("$skip", skip.to_string()));
        }
        if let Some(ref filter) = self.filter
            && !filter.is_empty()
        {
            params.push(("$filter", filter.clone()));
        }
        if let Some(ref select) = self.select
            && !select.is_empty()
        {
            params.push(("$select", select.clone()));
        }
        if let Some(ref expand) = self.expand
            && !expand.is_empty()
        {
            params.push(("$expand", expand.clone()));
        }
        if let Some(ref search) = self.search
            && !search.is_empty()
        {
            params.push(("$search", search.clone()));
        }
        if self.count == Some(true) {
            params.push(("$count", "true".to_string()));
        }
        params
    }
}

// ---------------------------------------------------------------------------
// Internal: generic HTTP helper
// ---------------------------------------------------------------------------

/// Perform an authenticated HTTP request and return deserialized JSON.
/// Used by both GraphClient and EndpointClient.
#[allow(clippy::too_many_arguments)]
async fn api_request(
    http: &reqwest::Client,
    token_manager: &TokenManager,
    scope: &str,
    base_url: &str,
    method: reqwest::Method,
    path: &str,
    query: &[(&str, String)],
    body: Option<&Value>,
) -> Result<Value, rmcp::model::CallToolResult> {
    let url = format!("{base_url}{path}");
    let token = token_manager
        .get_token(scope)
        .await
        .map_err(|e| crate::error::tool_error(format!("Auth error: {e}")))?;

    let query_pairs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let req = match method {
        reqwest::Method::GET => http.get(&url).query(&query_pairs),
        reqwest::Method::POST => http
            .post(&url)
            .query(&query_pairs)
            .header("Content-Type", "application/json; charset=utf-8"),
        _ => {
            return Err(crate::error::tool_error(format!(
                "Unsupported HTTP method: {method}"
            )));
        }
    };

    let req = req.bearer_auth(&token).header("Accept", "application/json");

    let resp = if let Some(b) = body {
        req.json(b).send().await
    } else {
        req.send().await
    }
    .map_err(|e| network_error(&e, path))?;

    let status = resp.status().as_u16();

    // 201 Created is acceptable for POST (Live Response)
    let ok = status == 200 || (method == reqwest::Method::POST && status == 201);

    if !ok {
        return Err(http_error(status, path));
    }

    let response_body: Value = resp
        .json()
        .await
        .map_err(|e| crate::error::tool_error(format!("Invalid JSON response: {e}")))?;

    Ok(response_body)
}

// ---------------------------------------------------------------------------
// GraphClient — Microsoft Graph APIs (existing TI/Advanced Hunting tools)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct GraphClient {
    http: reqwest::Client,
    token_manager: TokenManager,
    base_url: String,
}

impl GraphClient {
    pub fn new(token_manager: TokenManager) -> Self {
        let base_url =
            std::env::var(ENV_GRAPH_BASE_URL).unwrap_or_else(|_| GRAPH_BASE_URL.to_string());
        Self {
            http: token_manager.http_client.clone(),
            token_manager,
            base_url,
        }
    }

    pub async fn graph_get(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value, rmcp::model::CallToolResult> {
        api_request(
            &self.http,
            &self.token_manager,
            GRAPH_SCOPE,
            &self.base_url,
            reqwest::Method::GET,
            path,
            query,
            None,
        )
        .await
    }

    pub async fn graph_post(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<Value, rmcp::model::CallToolResult> {
        api_request(
            &self.http,
            &self.token_manager,
            GRAPH_SCOPE,
            &self.base_url,
            reqwest::Method::POST,
            path,
            &[],
            Some(body),
        )
        .await
    }

    pub async fn graph_get_with_odata(
        &self,
        path: &str,
        odata: &ODataParams,
    ) -> Result<Value, rmcp::model::CallToolResult> {
        let query = odata.to_query_vec();
        self.graph_get(path, &query).await
    }
}

// ---------------------------------------------------------------------------
// EndpointClient — Defender for Endpoint APIs
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct EndpointClient {
    http: reqwest::Client,
    token_manager: TokenManager,
    base_url: String,
}

impl EndpointClient {
    pub fn new(token_manager: TokenManager) -> Self {
        let base_url =
            std::env::var(ENV_ENDPOINT_BASE_URL).unwrap_or_else(|_| ENDPOINT_BASE_URL.to_string());
        Self {
            http: token_manager.http_client.clone(),
            token_manager,
            base_url,
        }
    }

    pub async fn endpoint_get(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value, rmcp::model::CallToolResult> {
        api_request(
            &self.http,
            &self.token_manager,
            ENDPOINT_SCOPE,
            &self.base_url,
            reqwest::Method::GET,
            path,
            query,
            None,
        )
        .await
    }

    pub async fn endpoint_post(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<Value, rmcp::model::CallToolResult> {
        api_request(
            &self.http,
            &self.token_manager,
            ENDPOINT_SCOPE,
            &self.base_url,
            reqwest::Method::POST,
            path,
            &[],
            Some(body),
        )
        .await
    }

    pub async fn endpoint_get_with_odata(
        &self,
        path: &str,
        odata: &ODataParams,
    ) -> Result<Value, rmcp::model::CallToolResult> {
        let query = odata.to_query_vec();
        self.endpoint_get(path, &query).await
    }

    /// Upload a file to the live response library via multipart/form-data.
    pub async fn endpoint_multipart_upload(
        &self,
        path: &str,
        file_name: &str,
        file_content: &[u8],
        description: &str,
        parameters_description: Option<&str>,
        override_if_exists: Option<bool>,
    ) -> Result<Value, rmcp::model::CallToolResult> {
        let url = format!("{}{}", self.base_url, path);
        let token = self
            .token_manager
            .get_token(crate::constants::ENDPOINT_SCOPE)
            .await
            .map_err(|e| crate::error::tool_error(format!("Auth error: {e}")))?;

        let content = Vec::from(file_content);
        let file_part = reqwest::multipart::Part::bytes(content)
            .file_name(file_name.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| crate::error::tool_error(format!("Invalid MIME type: {e}")))?;

        let mut form = reqwest::multipart::Form::new()
            .part("file", file_part)
            .text("Description", description.to_string());

        if let Some(pd) = parameters_description {
            form = form.text("ParametersDescription", pd.to_string());
        }
        if let Some(ov) = override_if_exists {
            form = form.text("OverrideIfExists", ov.to_string());
        }

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .header("Accept", "application/json")
            .multipart(form)
            .send()
            .await
            .map_err(|e| crate::error::network_error(&e, path))?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(crate::error::http_error(status, path));
        }

        let response_body: Value = resp
            .json()
            .await
            .map_err(|e| crate::error::tool_error(format!("Invalid JSON response: {e}")))?;

        Ok(response_body)
    }
}

#[cfg(test)]
impl GraphClient {
    /// Test constructor supporting loopback fixture endpoints.
    pub fn for_test(token_manager: TokenManager, base_url: String) -> Self {
        Self {
            http: token_manager.http_client.clone(),
            token_manager,
            base_url,
        }
    }
}

#[cfg(test)]
impl EndpointClient {
    /// Test constructor supporting loopback fixture endpoints.
    pub fn for_test(token_manager: TokenManager, base_url: String) -> Self {
        Self {
            http: token_manager.http_client.clone(),
            token_manager,
            base_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_tool_error(err: &rmcp::model::CallToolResult) -> serde_json::Value {
        assert_eq!(err.is_error, Some(true));
        let content = &err.content[0];
        let text = content.as_text().expect("expected text content");
        serde_json::from_str(&text.text).expect("valid json in error content")
    }

    async fn setup_test_server(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (server_url, handle)
    }

    async fn handle_403() -> (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        &'static str,
    ) {
        (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html")],
            "<html><body>403 Forbidden: WAF blocked</body></html>",
        )
    }

    async fn handle_429() -> (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        &'static str,
    ) {
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            [("content-type", "text/plain")],
            "Rate limit exceeded",
        )
    }

    async fn handle_504() -> (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        &'static str,
    ) {
        (
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            [("content-type", "text/html")],
            "<html><body>504 Gateway Timeout</body></html>",
        )
    }

    async fn handle_success_json() -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({"value": [{"id": "item1"}]})),
        )
    }

    async fn handle_created_json() -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        (
            axum::http::StatusCode::CREATED,
            axum::Json(serde_json::json!({"id": "action1", "status": "Pending"})),
        )
    }

    async fn handle_malformed_json() -> (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        &'static str,
    ) {
        (
            axum::http::StatusCode::OK,
            [("content-type", "application/json")],
            "this is not json {{",
        )
    }

    async fn handle_multipart_400() -> (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        &'static str,
    ) {
        (
            axum::http::StatusCode::BAD_REQUEST,
            [("content-type", "text/plain")],
            "Bad Request: invalid file",
        )
    }

    async fn handle_multipart_success() -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({"id": "file-1", "name": "test.ps1"})),
        )
    }

    #[tokio::test]
    async fn test_plain_text_403_retains_status_not_json_parse() {
        let app = axum::Router::new().route("/test-403", axum::routing::get(handle_403));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let graph = GraphClient::for_test(tm, base_url);

        let err = graph.graph_get("/test-403", &[]).await.unwrap_err();
        let err_json = parse_tool_error(&err);
        assert_eq!(err_json["httpStatus"], 403);
        let msg = err_json["error"].as_str().unwrap();
        assert!(msg.contains("Permission denied for: /test-403"));
        assert!(!msg.contains("Invalid JSON response"));
        handle.abort();
    }

    #[tokio::test]
    async fn test_plain_text_429_retains_status_not_json_parse() {
        let app = axum::Router::new().route("/test-429", axum::routing::get(handle_429));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let graph = GraphClient::for_test(tm, base_url);

        let err = graph.graph_get("/test-429", &[]).await.unwrap_err();
        let err_json = parse_tool_error(&err);
        assert_eq!(err_json["httpStatus"], 429);
        let msg = err_json["error"].as_str().unwrap();
        assert!(msg.contains("Rate limit exceeded for: /test-429"));
        assert!(!msg.contains("Invalid JSON response"));
        handle.abort();
    }

    #[tokio::test]
    async fn test_plain_text_504_retains_status_not_json_parse() {
        let app = axum::Router::new().route("/test-504", axum::routing::get(handle_504));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let graph = GraphClient::for_test(tm, base_url);

        let err = graph.graph_get("/test-504", &[]).await.unwrap_err();
        let err_json = parse_tool_error(&err);
        assert_eq!(err_json["httpStatus"], 504);
        let msg = err_json["error"].as_str().unwrap();
        assert!(msg.contains("Request timed out"));
        assert!(!msg.contains("Invalid JSON response"));
        handle.abort();
    }

    #[tokio::test]
    async fn test_success_json_preserved() {
        let app = axum::Router::new().route("/success", axum::routing::get(handle_success_json));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let graph = GraphClient::for_test(tm, base_url);

        let val = graph.graph_get("/success", &[]).await.unwrap();
        assert_eq!(val["value"][0]["id"], "item1");
        handle.abort();
    }

    #[tokio::test]
    async fn test_post_201_created_success_preserved() {
        let app = axum::Router::new().route("/created", axum::routing::post(handle_created_json));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let graph = GraphClient::for_test(tm, base_url);

        let val = graph
            .graph_post("/created", &serde_json::json!({"action": "run"}))
            .await
            .unwrap();
        assert_eq!(val["id"], "action1");
        assert_eq!(val["status"], "Pending");
        handle.abort();
    }

    #[tokio::test]
    async fn test_malformed_success_json_errors() {
        let app =
            axum::Router::new().route("/malformed", axum::routing::get(handle_malformed_json));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let graph = GraphClient::for_test(tm, base_url);

        let err = graph.graph_get("/malformed", &[]).await.unwrap_err();
        let err_json = parse_tool_error(&err);
        assert!(err_json.get("httpStatus").is_none());
        let msg = err_json["error"].as_str().unwrap();
        assert!(msg.contains("Invalid JSON response"));
        handle.abort();
    }

    #[tokio::test]
    async fn test_multipart_non_json_error_retains_status() {
        let app =
            axum::Router::new().route("/upload-err", axum::routing::post(handle_multipart_400));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let endpoint = EndpointClient::for_test(tm, base_url);

        let err = endpoint
            .endpoint_multipart_upload(
                "/upload-err",
                "script.ps1",
                b"write-host test",
                "sample description",
                None,
                None,
            )
            .await
            .unwrap_err();
        let err_json = parse_tool_error(&err);
        assert_eq!(err_json["httpStatus"], 400);
        let msg = err_json["error"].as_str().unwrap();
        assert!(msg.contains("Bad request: /upload-err"));
        assert!(!msg.contains("Invalid JSON response"));
        handle.abort();
    }

    #[tokio::test]
    async fn test_multipart_success_json_preserved() {
        let app =
            axum::Router::new().route("/upload-ok", axum::routing::post(handle_multipart_success));
        let (base_url, handle) = setup_test_server(app).await;
        let client = reqwest::Client::new();
        let tm = TokenManager::for_test(client);
        let endpoint = EndpointClient::for_test(tm, base_url);

        let val = endpoint
            .endpoint_multipart_upload(
                "/upload-ok",
                "script.ps1",
                b"write-host test",
                "sample description",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(val["id"], "file-1");
        assert_eq!(val["name"], "test.ps1");
        handle.abort();
    }
}
