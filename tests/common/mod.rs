//! Shared integration-test helpers. Everything is hermetic:
//! - [`McpProcess`] drives the real binary over MCP stdio with dummy credentials and upstream
//!   base URLs pointed at a closed loopback port; callers only exercise paths that never fetch a token.
//! - [`MockUpstream`] + [`test_server`] run an in-process server against a loopback Axum fixture.
#![allow(dead_code)]
pub mod idp;
#[allow(unused_imports)]
pub use idp::MockIdp;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::routing::post;
use axum::{Json, Router};
use microsoft_defender_mcp_server::audit::AuditSink;
use microsoft_defender_mcp_server::auth::TokenManager;
use microsoft_defender_mcp_server::cli::{
    AuthConfig, AuditLogSetting, MutationCategories, ServerConfig, TransportMode,
};
use microsoft_defender_mcp_server::client::{EndpointClient, GraphClient};
use microsoft_defender_mcp_server::server::DefenderServer;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

pub const SENTINEL_APP_TOKEN: &str = "SENTINEL-AT-APP-0001";
pub const SENTINEL_CLIENT_SECRET: &str = "SENTINEL-CS-0001";

/// Loopback Axum fixture; aborted on drop.
pub struct MockUpstream {
    pub base_url: String,
    pub hits: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl MockUpstream {
    /// Return the count of requests made to this exact path.
    pub fn hit_count(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }

    /// Return total requests handled across all paths.
    pub fn total_hits(&self) -> usize {
        self.hits.lock().unwrap().values().sum()
    }

    /// Assert exact hit count for a given path.
    pub fn assert_hits(&self, path: &str, n: usize) {
        let actual = self.hit_count(path);
        assert_eq!(
            actual, n,
            "expected {n} hits for '{path}', but got {actual}; all recorded hits: {:?}",
            self.hits.lock().unwrap()
        );
    }
}

pub async fn spawn_mock(app: Router) -> MockUpstream {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind loopback port");
    let base_url = format!("http://{}", std_listener.local_addr().expect("local addr"));
    std_listener.set_nonblocking(true).expect("set nonblocking");

    let hits: Arc<std::sync::Mutex<HashMap<String, usize>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let hits_counter = hits.clone();

    let app = app.layer(middleware::from_fn(
        move |req: Request, next: Next| {
            let hits_counter = hits_counter.clone();
            async move {
                let path = req.uri().path().to_string();
                {
                    let mut map = hits_counter.lock().unwrap();
                    *map.entry(path).or_insert(0) += 1;
                }
                next.run(req).await
            }
        },
    ));

    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("mock tokio runtime");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(shutdown_tx);
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener)
                .expect("convert to tokio listener");
            let server = axum::serve(listener, app);
            tokio::select! {
                _ = server => {},
                _ = shutdown_rx => {},
            }
        });
    });

    let shutdown_tx = rx.recv().expect("mock started");
    MockUpstream {
        base_url,
        hits,
        shutdown_tx: Some(shutdown_tx),
        thread: Some(thread),
    }
}

/// Helper router that mocks the Entra ID app-mode client_credentials token route.
pub fn mock_token_router() -> Router {
    Router::new().route(
        "/{tenant}/oauth2/v2.0/token",
        post(|| async {
            Json(json!({
                "token_type": "Bearer",
                "access_token": SENTINEL_APP_TOKEN,
                "expires_in": 3600
            }))
        }),
    )
}

/// Combine application routes with the mock token route.
pub fn with_token_route(app: Router) -> Router {
    app.merge(mock_token_router())
}

/// Baseline config: domain tools, writable, all mutation categories off,
/// confirm_destructive on, App auth, and audit_log in a per-test scratch dir.
pub fn base_config() -> ServerConfig {
    let scratch_dir = std::env::temp_dir().join(format!(
        "defender-audit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&scratch_dir);
    let audit_path = scratch_dir.join("audit.jsonl");

    ServerConfig {
        transport: TransportMode::Stdio,
        bind_address: "127.0.0.1:8000".to_string(),
        read_only: false,
        categories: MutationCategories::default(),
        live_response_allowed_commands: None,
        quarantine_dir: PathBuf::from("./quarantine_artifacts"),
        audit_log: AuditLogSetting::Explicit(audit_path),
        confirm_destructive: true,
        auth: AuthConfig::App,
    }
}

/// In-process server whose Graph and Endpoint clients target `base_url` with pre-seeded tokens.
pub fn test_server(base_url: &str, config: ServerConfig) -> DefenderServer {
    test_server_with_sink(base_url, config, None)
}

/// In-process server with an optional AuditSink.
pub fn test_server_with_sink(
    base_url: &str,
    config: ServerConfig,
    audit_sink: Option<Arc<AuditSink>>,
) -> DefenderServer {
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("loopback reqwest client");
    let tm = TokenManager::for_test(http);
    DefenderServer::new_with_config(
        GraphClient::for_test(tm.clone(), base_url.to_string()),
        EndpointClient::for_test(tm, base_url.to_string()),
        config,
        audit_sink,
    )
}

/// Unique scratch directory under the system temp dir; removed on drop.
pub struct ScratchDir(pub PathBuf);

impl ScratchDir {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "defender-mcp-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Scripted response for client-side elicitation answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationResponse {
    AcceptConfirm,
    AcceptReject,
    Decline,
    Cancel,
    NoAnswer,
}

pub struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    pub elicitation_response: ElicitationResponse,
    pub elicitation_messages: Vec<String>,
    stderr_file: Option<PathBuf>,
}

impl Drop for McpProcess {
    /// Never leave an orphaned server behind, even when an assertion fails mid-test.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(path) = &self.stderr_file {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Build a command for the server binary with all `DEFENDER_*`/transport env cleared.
pub fn server_command(args: &[&str], envs: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_microsoft-defender-mcp-server"));
    for var in [
        "TRANSPORT",
        "BIND_ADDRESS",
        "DEFENDER_TOOL_MODE",
        "DEFENDER_READ_ONLY",
        "DEFENDER_ENABLE_LIVE_RESPONSE",
        "DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS",
        "DEFENDER_QUARANTINE_DIR",
        "DEFENDER_ENABLE_DEVICE_RESPONSE",
        "DEFENDER_ENABLE_OFFBOARDING",
        "DEFENDER_ENABLE_INDICATORS",
        "DEFENDER_ENABLE_TRIAGE",
        "DEFENDER_DISABLE_HUMAN_CONFIRMATION",
        "DEFENDER_AUDIT_LOG",
        "DEFENDER_AUTH_MODE",
        "DEFENDER_SIGN_IN_FLOW",
        "DEFENDER_AUTHORITY_BASE_URL",
        "DEFENDER_TEST_BROWSER_CMD",
        "DEFENDER_TEST_DEVICE_CODE_INTERVAL_MS",
        "DEFENDER_TEST_ELICITATION_TIMEOUT_MS",
    ] {
        cmd.env_remove(var);
    }

    let default_scratch = std::env::temp_dir().join(format!(
        "defender-cmd-audit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&default_scratch);
    let default_audit = default_scratch.join("audit.jsonl");

    cmd.args(args)
        .env("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
        .env("AZURE_CLIENT_ID", "11111111-1111-1111-1111-111111111111")
        .env("AZURE_CLIENT_SECRET", SENTINEL_CLIENT_SECRET)
        .env("DEFENDER_AUDIT_LOG", default_audit)
        .env("GRAPH_BASE_URL", "http://127.0.0.1:9")
        .env("DEFENDER_ENDPOINT_BASE_URL", "http://127.0.0.1:9")
        .env("NO_PROXY", "*")
        .env("no_proxy", "*")
        .env("RUST_LOG", "off");
    for (k, v) in envs {
        if *k == "AZURE_CLIENT_SECRET" && v.is_empty() {
            cmd.env_remove(k);
        } else {
            cmd.env(k, v);
        }
    }
    cmd
}

impl McpProcess {
    /// Spawn the server over stdio without declaring elicitation capability.
    pub fn start(args: &[&str], envs: &[(&str, &str)]) -> Self {
        Self::start_with_options(args, envs, false, ElicitationResponse::AcceptConfirm, false)
    }

    /// Spawn the server with elicitation capability enabled (defaults to AcceptConfirm).
    pub fn start_with_elicitation(args: &[&str], envs: &[(&str, &str)]) -> Self {
        Self::start_with_options(args, envs, true, ElicitationResponse::AcceptConfirm, false)
    }

    /// Spawn the server with elicitation capability and a specific scripted response.
    pub fn initialize_with_elicitation(
        args: &[&str],
        envs: &[(&str, &str)],
        response: ElicitationResponse,
    ) -> Self {
        Self::start_with_options(args, envs, true, response, false)
    }

    /// Spawn the server with stderr directed to /dev/null.
    pub fn start_with_null_stderr(
        args: &[&str],
        envs: &[(&str, &str)],
        with_elicitation: bool,
        response: ElicitationResponse,
    ) -> Self {
        Self::start_with_options(args, envs, with_elicitation, response, true)
    }

    fn start_with_options(
        args: &[&str],
        envs: &[(&str, &str)],
        with_elicitation: bool,
        response: ElicitationResponse,
        null_stderr: bool,
    ) -> Self {
        let (stderr_cfg, stderr_path) = if null_stderr {
            (Stdio::null(), None)
        } else {
            static STDERR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let seq = STDERR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "mcp-proc-stderr-{}-{:?}-{seq}-{}.log",
                std::process::id(),
                std::thread::current().id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            let f = std::fs::File::create(&p).expect("create stderr log file");
            (Stdio::from(f), Some(p))
        };

        let mut child = server_command(args, envs)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr_cfg)
            .spawn()
            .expect("spawn server binary");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));

        let mut proc = Self {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 1,
            elicitation_response: response,
            elicitation_messages: Vec::new(),
            stderr_file: stderr_path,
        };

        let capabilities = if with_elicitation {
            json!({
                "elicitation": {
                    "form": {}
                }
            })
        } else {
            json!({})
        };

        let init = proc.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": capabilities,
                "clientInfo": { "name": "integration-test", "version": "0" }
            }),
        );
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        proc.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        proc
    }

    /// Read all captured stderr so far.
    pub fn captured_stderr(&self) -> String {
        self.stderr_file
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default()
    }

    /// Set the scripted response for subsequent elicitation requests.
    pub fn set_elicitation_response(&mut self, response: ElicitationResponse) {
        self.elicitation_response = response;
    }

    /// Slice of all elicitation messages received during tool execution.
    pub fn recorded_elicitations(&self) -> &[String] {
        &self.elicitation_messages
    }

    fn send(&mut self, msg: Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{msg}").expect("write request");
        stdin.flush().expect("flush request");
    }

    /// Send a JSON-RPC request and return the response with the matching id.
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).expect("read response");
            assert!(n > 0, "server closed stdout before answering {method}");
            let msg: Value = serde_json::from_str(&line).expect("response is JSON");
            if msg.get("id") == Some(&json!(id)) {
                return msg;
            }

            // Server-initiated elicitation request
            if msg.get("method").and_then(Value::as_str) == Some("elicitation/create") {
                if let Some(msg_text) = msg.pointer("/params/message").and_then(Value::as_str) {
                    self.elicitation_messages.push(msg_text.to_string());
                }
                let s_id = msg.get("id").cloned().expect("server request id");
                match self.elicitation_response {
                    ElicitationResponse::AcceptConfirm => {
                        self.send(json!({
                            "jsonrpc": "2.0",
                            "id": s_id,
                            "result": {
                                "action": "accept",
                                "content": { "confirm": true }
                            }
                        }));
                    }
                    ElicitationResponse::AcceptReject => {
                        self.send(json!({
                            "jsonrpc": "2.0",
                            "id": s_id,
                            "result": {
                                "action": "accept",
                                "content": { "confirm": false }
                            }
                        }));
                    }
                    ElicitationResponse::Decline => {
                        self.send(json!({
                            "jsonrpc": "2.0",
                            "id": s_id,
                            "result": {
                                "action": "decline"
                            }
                        }));
                    }
                    ElicitationResponse::Cancel => {
                        self.send(json!({
                            "jsonrpc": "2.0",
                            "id": s_id,
                            "result": {
                                "action": "cancel"
                            }
                        }));
                    }
                    ElicitationResponse::NoAnswer => {
                        // Do not reply, trigger server elicitation timeout
                    }
                }
            }
        }
    }

    /// Names returned by `tools/list`.
    pub fn tool_names(&mut self) -> Vec<String> {
        let resp = self.request("tools/list", json!({}));
        resp["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().expect("tool name").to_string())
            .collect()
    }

    /// Full tools array returned by `tools/list`.
    pub fn tools(&mut self) -> Vec<Value> {
        let resp = self.request("tools/list", json!({}));
        resp["result"]["tools"]
            .as_array()
            .expect("tools array")
            .clone()
    }

    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    /// Close stdin and require the server to exit on its own.
    pub fn shutdown(mut self) -> std::process::ExitStatus {
        drop(self.stdin.take());
        self.child.wait().expect("wait for server exit")
    }
}
