//! Shared integration-test helpers. Everything is hermetic:
//! - [`McpProcess`] drives the real binary over MCP stdio with dummy credentials and upstream
//!   base URLs pointed at a closed loopback port; callers only exercise paths that never fetch a token.
//! - [`MockUpstream`] + [`test_server`] run an in-process server against a loopback Axum fixture.
#![allow(dead_code)]

use microsoft_defender_mcp_server::auth::TokenManager;
use microsoft_defender_mcp_server::cli::{ServerConfig, ToolMode, TransportMode};
use microsoft_defender_mcp_server::client::{EndpointClient, GraphClient};
use microsoft_defender_mcp_server::server::DefenderServer;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

/// Loopback Axum fixture; aborted on drop.
pub struct MockUpstream {
    pub base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub async fn spawn_mock(app: axum::Router) -> MockUpstream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback port");
    let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    MockUpstream { base_url, handle }
}

/// Baseline config: granular, writable, Live Response disabled, quarantine in `./quarantine_artifacts`.
pub fn base_config() -> ServerConfig {
    ServerConfig {
        transport: TransportMode::Stdio,
        bind_address: "127.0.0.1:8000".to_string(),
        tool_mode: ToolMode::Granular,
        read_only: false,
        live_response_enabled: false,
        live_response_allowed_commands: None,
        quarantine_dir: PathBuf::from("./quarantine_artifacts"),
    }
}

/// In-process server whose Graph and Endpoint clients target `base_url` with pre-seeded tokens.
pub fn test_server(base_url: &str, config: ServerConfig) -> DefenderServer {
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
pub struct McpProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Drop for McpProcess {
    /// Never leave an orphaned server behind, even when an assertion fails mid-test.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
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
    ] {
        cmd.env_remove(var);
    }
    cmd.args(args)
        .env("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
        .env("AZURE_CLIENT_ID", "11111111-1111-1111-1111-111111111111")
        .env("AZURE_CLIENT_SECRET", "test-secret")
        .env("GRAPH_BASE_URL", "http://127.0.0.1:9")
        .env("DEFENDER_ENDPOINT_BASE_URL", "http://127.0.0.1:9")
        .env("RUST_LOG", "off");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd
}

impl McpProcess {
    /// Spawn the server over stdio and complete the MCP initialize handshake.
    pub fn start(args: &[&str], envs: &[(&str, &str)]) -> Self {
        let mut child = server_command(args, envs)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server binary");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut proc = Self {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 1,
        };
        let init = proc.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "integration-test", "version": "0" }
            }),
        );
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        proc.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        proc
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
