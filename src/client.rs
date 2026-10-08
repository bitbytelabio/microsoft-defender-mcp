//! API clients with authentication for both Microsoft Graph and Defender for Endpoint.

use std::borrow::Cow;
use std::path::Path;

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::auth::TokenManager;
use crate::constants::{
    ENDPOINT_BASE_URL, ENDPOINT_SCOPE, ENV_ENDPOINT_BASE_URL, ENV_GRAPH_BASE_URL, GRAPH_BASE_URL,
    GRAPH_SCOPE,
};
use crate::error::{http_error, network_error, staging_filesystem_error, tool_error};

/// Empty query string for requests without parameters.
const NO_QUERY: &[(&str, &str)] = &[];

/// Write-buffer size for artifact downloads; batches small network chunks into fewer
/// blocking-pool file writes.
const ARTIFACT_WRITE_BUFFER: usize = 256 * 1024;

/// Downloaded investigation or quarantine artifact details.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DownloadedArtifact {
    pub status: String,
    pub file_path: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha1: Option<String>,
}

/// Ensure the staging directory exists. On Unix every directory created here gets mode
/// `0700`, and the leaf directory is re-restricted to `0700` if it already existed.
async fn ensure_staging_directory(dir: &Path) -> std::io::Result<()> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.mode(0o700);
        builder.create(dir).await?;
        tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    #[cfg(not(unix))]
    builder.create(dir).await?;
    Ok(())
}

/// OData query parameters for list endpoints, borrowing string values from the tool input.
#[derive(Debug, Default, Clone, Copy)]
pub struct ODataParams<'a> {
    pub top: Option<i32>,
    pub skip: Option<i32>,
    pub filter: Option<&'a str>,
    pub select: Option<&'a str>,
    pub expand: Option<&'a str>,
    pub search: Option<&'a str>,
    pub count: Option<bool>,
}

impl<'a> ODataParams<'a> {
    /// Query pairs in `$top, $skip, $filter, $select, $expand, $search, $count` order; empty
    /// strings are omitted.
    pub fn to_query_vec(&self) -> Vec<(&'static str, Cow<'a, str>)> {
        let mut params = Vec::with_capacity(7);
        if let Some(top) = self.top {
            params.push(("$top", Cow::Owned(top.to_string())));
        }
        if let Some(skip) = self.skip {
            params.push(("$skip", Cow::Owned(skip.to_string())));
        }
        for (key, value) in [
            ("$filter", self.filter),
            ("$select", self.select),
            ("$expand", self.expand),
            ("$search", self.search),
        ] {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                params.push((key, Cow::Borrowed(value)));
            }
        }
        if self.count == Some(true) {
            params.push(("$count", Cow::Borrowed("true")));
        }
        params
    }
}

// ---------------------------------------------------------------------------
// Internal: authenticated JSON client shared by GraphClient and EndpointClient
// ---------------------------------------------------------------------------

/// Authenticated JSON client bound to one upstream base URL and OAuth scope.
#[derive(Clone)]
struct ApiClient {
    http: reqwest::Client,
    token_manager: TokenManager,
    base_url: String,
    scope: &'static str,
}

impl ApiClient {
    fn new(token_manager: TokenManager, base_url: String, scope: &'static str) -> Self {
        Self {
            http: token_manager.http_client.clone(),
            token_manager,
            base_url,
            scope,
        }
    }

    async fn token(&self) -> Result<String, CallToolResult> {
        self.token_manager
            .get_token(self.scope)
            .await
            .map_err(|e| tool_error(format!("Auth error: {e}")))
    }

    /// Authenticated GET (no body) or JSON POST (with body); returns the decoded JSON response.
    async fn request<Q: Serialize + ?Sized>(
        &self,
        path: &str,
        query: &Q,
        body: Option<&Value>,
    ) -> Result<Value, CallToolResult> {
        let token = self.token().await?;
        let url = format!("{}{path}", self.base_url);
        let req = match body {
            Some(body) => self
                .http
                .post(url)
                .header(CONTENT_TYPE, "application/json; charset=utf-8")
                .json(body),
            None => self.http.get(url),
        };
        let resp = req
            .query(query)
            .bearer_auth(&token)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| network_error(&e, path))?;
        // 201 Created is acceptable for POST (Live Response).
        read_json(resp, path, body.is_some()).await
    }
}

/// Reject non-success statuses with `http_error`, otherwise decode the JSON body.
async fn read_json(
    resp: reqwest::Response,
    path: &str,
    accept_created: bool,
) -> Result<Value, CallToolResult> {
    let status = resp.status().as_u16();
    if status != 200 && !(accept_created && status == 201) {
        return Err(http_error(status, path));
    }
    resp.json()
        .await
        .map_err(|e| tool_error(format!("Invalid JSON response: {e}")))
}

// ---------------------------------------------------------------------------
// GraphClient — Microsoft Graph APIs (existing TI/Advanced Hunting tools)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct GraphClient(ApiClient);

impl GraphClient {
    pub fn new(token_manager: TokenManager) -> Self {
        let base_url =
            std::env::var(ENV_GRAPH_BASE_URL).unwrap_or_else(|_| GRAPH_BASE_URL.to_string());
        Self(ApiClient::new(token_manager, base_url, GRAPH_SCOPE))
    }

    /// Constructor with an explicit base URL (loopback fixture endpoints in tests).
    pub fn for_test(token_manager: TokenManager, base_url: String) -> Self {
        Self(ApiClient::new(token_manager, base_url, GRAPH_SCOPE))
    }

    pub async fn graph_get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<Value, CallToolResult> {
        self.0.request(path, query, None).await
    }

    pub async fn graph_post(&self, path: &str, body: &Value) -> Result<Value, CallToolResult> {
        self.0.request(path, NO_QUERY, Some(body)).await
    }

    pub async fn graph_get_with_odata(
        &self,
        path: &str,
        odata: &ODataParams<'_>,
    ) -> Result<Value, CallToolResult> {
        self.0.request(path, &odata.to_query_vec(), None).await
    }
}

// ---------------------------------------------------------------------------
// EndpointClient — Defender for Endpoint APIs
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct EndpointClient(ApiClient);

impl EndpointClient {
    pub fn new(token_manager: TokenManager) -> Self {
        let base_url =
            std::env::var(ENV_ENDPOINT_BASE_URL).unwrap_or_else(|_| ENDPOINT_BASE_URL.to_string());
        Self(ApiClient::new(token_manager, base_url, ENDPOINT_SCOPE))
    }

    /// Constructor with an explicit base URL (loopback fixture endpoints in tests).
    pub fn for_test(token_manager: TokenManager, base_url: String) -> Self {
        Self(ApiClient::new(token_manager, base_url, ENDPOINT_SCOPE))
    }

    pub async fn endpoint_get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<Value, CallToolResult> {
        self.0.request(path, query, None).await
    }

    pub async fn endpoint_post(&self, path: &str, body: &Value) -> Result<Value, CallToolResult> {
        self.0.request(path, NO_QUERY, Some(body)).await
    }

    pub async fn endpoint_get_with_odata(
        &self,
        path: &str,
        odata: &ODataParams<'_>,
    ) -> Result<Value, CallToolResult> {
        self.0.request(path, &odata.to_query_vec(), None).await
    }

    /// Upload a file to the live response library via multipart/form-data.
    pub async fn endpoint_multipart_upload(
        &self,
        path: &str,
        file_name: &str,
        file_content: Vec<u8>,
        description: &str,
        parameters_description: Option<&str>,
        override_if_exists: Option<bool>,
    ) -> Result<Value, CallToolResult> {
        let token = self.0.token().await?;

        let file_part = reqwest::multipart::Part::bytes(file_content)
            .file_name(file_name.to_owned())
            .mime_str("application/octet-stream")
            .map_err(|e| tool_error(format!("Invalid MIME type: {e}")))?;

        let mut form = reqwest::multipart::Form::new()
            .part("file", file_part)
            .text("Description", description.to_owned());
        if let Some(pd) = parameters_description {
            form = form.text("ParametersDescription", pd.to_owned());
        }
        if let Some(ov) = override_if_exists {
            form = form.text("OverrideIfExists", ov.to_string());
        }

        let resp = self
            .0
            .http
            .post(format!("{}{path}", self.0.base_url))
            .bearer_auth(&token)
            .header(ACCEPT, "application/json")
            .multipart(form)
            .send()
            .await
            .map_err(|e| network_error(&e, path))?;
        read_json(resp, path, false).await
    }

    /// Stream a pre-authenticated (SAS) artifact URL into `dest_dir/dest_filename`.
    ///
    /// No bearer token is sent: SAS URLs carry their own authorization. The file is created
    /// with mode `0600` on Unix (no window with wider permissions), the SHA-256 digest is
    /// computed while streaming, and a partially written file is removed on failure.
    pub async fn download_artifact(
        &self,
        download_url: &str,
        dest_dir: &Path,
        dest_filename: &str,
        source_action_id: Option<String>,
        source_sha1: Option<String>,
    ) -> Result<DownloadedArtifact, CallToolResult> {
        ensure_staging_directory(dest_dir).await.map_err(|e| {
            staging_filesystem_error(format!(
                "failed to create staging directory {}: {e}",
                dest_dir.display()
            ))
        })?;

        let resp = self
            .0
            .http
            .get(download_url)
            .send()
            .await
            .map_err(|e| network_error(&e, "artifact download"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(http_error(status, "artifact download"));
        }

        let file_path = dest_dir.join(dest_filename);
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&file_path).await.map_err(|e| {
            staging_filesystem_error(format!(
                "failed to create artifact file {}: {e}",
                file_path.display()
            ))
        })?;

        let (file_size_bytes, sha256) = match stream_to_file(resp, file).await {
            Ok(v) => v,
            Err(e) => {
                let _ = tokio::fs::remove_file(&file_path).await;
                return Err(e);
            }
        };

        let file_path = match tokio::fs::canonicalize(&file_path).await {
            Ok(canonical) => canonical,
            Err(_) => file_path,
        };
        Ok(DownloadedArtifact {
            status: "Downloaded".to_string(),
            file_path: file_path.to_string_lossy().into_owned(),
            file_size_bytes,
            sha256,
            source_action_id,
            source_sha1,
        })
    }
}

/// Copy a response body into `file`, returning the byte count and lowercase hex SHA-256.
async fn stream_to_file(
    mut resp: reqwest::Response,
    file: tokio::fs::File,
) -> Result<(u64, String), CallToolResult> {
    let mut file = tokio::io::BufWriter::with_capacity(ARTIFACT_WRITE_BUFFER, file);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| network_error(&e, "artifact download streaming"))?
    {
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| staging_filesystem_error(format!("failed to write artifact file: {e}")))?;
        total += chunk.len() as u64;
    }
    file.flush()
        .await
        .map_err(|e| staging_filesystem_error(format!("failed to flush artifact file: {e}")))?;
    Ok((total, format!("{:x}", hasher.finalize())))
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
                b"write-host test".to_vec(),
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
                b"write-host test".to_vec(),
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
