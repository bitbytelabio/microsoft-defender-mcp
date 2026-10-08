//! Microsoft Defender MCP Server
//!
//! An MCP server providing access to Microsoft Defender APIs via Microsoft Graph
//! Security and Defender for Endpoint APIs. Exposes 6 read-only domain tools by default,
//! and up to 4 mutating tools when enabled. Mutating tools are hidden and rejected
//! under `--read-only`. See `--help` and [`cli`](microsoft_defender_mcp_server::cli).

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use microsoft_defender_mcp_server::audit::AuditSink;
use microsoft_defender_mcp_server::auth::{IdentitySnapshot, TokenManager};
use microsoft_defender_mcp_server::cli::{
    AuthConfig, AuthMode, Cli, ServerConfig, TransportMode, validate_credentials,
    warn_if_non_loopback,
};
use microsoft_defender_mcp_server::client::{EndpointClient, GraphClient};
use microsoft_defender_mcp_server::constants::{ENV_REMOVED_TOOL_MODE, REQUEST_TIMEOUT_SECS};
use microsoft_defender_mcp_server::server::DefenderServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Parse CLI arguments.
    let cli = Cli::parse();

    // 2. Tombstone check for removed --tool-mode / DEFENDER_TOOL_MODE.
    if cli.tool_mode_tombstone.is_some() || std::env::var_os(ENV_REMOVED_TOOL_MODE).is_some() {
        eprintln!(
            "--tool-mode was removed in 1.0.0: granular mode no longer exists; the server always exposes domain tools (see the migration table)"
        );
        std::process::exit(1);
    }

    // 3. Reject --sign-in-flow given with --auth-mode app.
    if cli.auth_mode == AuthMode::App && cli.sign_in_flow.is_some() {
        eprintln!("--sign-in-flow requires --auth-mode user");
        std::process::exit(1);
    }
    // 4. Validate credentials for the selected mode.
    if let Err(e) = validate_credentials(cli.auth_mode) {
        eprintln!("Configuration error: {e}");
        std::process::exit(1);
    }

    // Capture flags for notices before config construction.
    let cli_any_enablement = cli.enable_live_response
        || cli.enable_device_response
        || cli.enable_offboarding
        || cli.enable_indicators
        || cli.enable_triage;
    let cli_read_only = cli.read_only;

    let config = ServerConfig::from_cli(cli);

    // Non-fatal notices to stderr.
    if cli_read_only && cli_any_enablement {
        eprintln!("NOTE: --read-only overrides --enable-…; no mutating tools are exposed.");
    }
    if config.categories.any() && !config.confirm_destructive {
        eprintln!(
            "WARNING: human confirmation for destructive actions is turned OFF; destructive tools run without a confirmation prompt and the audit log records each one as unconfirmed."
        );
    }
    if config.transport == TransportMode::Http {
        warn_if_non_loopback(&config.bind_address);
    }
    // 4. Open AuditSink when any mutating category is enabled or audit log path was set explicitly.
    let audit_sink = if config.categories.any() || config.audit_log.is_explicit() {
        let path = config.audit_log.path();
        match AuditSink::open(path).await {
            Ok(sink) => Some(Arc::new(sink)),
            Err(e) => {
                eprintln!(
                    "Audit log '{}' is not writable: {e}; set --audit-log to a writable path",
                    path.display()
                );
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Log to stderr — stdout is reserved for the MCP stdio protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // 5. Build shared HTTP client with timeout.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .expect("failed to build reqwest client");

    // 6. Initialize token manager and perform sign-in (T036).
    let token_manager = match config.auth {
        AuthConfig::App => {
            TokenManager::from_env(http).map_err(|e| anyhow::anyhow!("Configuration error: {e}"))?
        }
        AuthConfig::User { flow } => match TokenManager::sign_in_user(&config, flow, http).await {
            Ok(tm) => {
                if config.transport == TransportMode::Http
                    && let IdentitySnapshot::User { account, .. } = tm.identity()
                {
                    eprintln!(
                        "SECURITY WARNING: every HTTP client connected to this server acts as {account} with that user's Defender rights; run one server per analyst for per-person attribution."
                    );
                }
                tm
            }
            Err(e) => {
                eprintln!("Sign-in not completed: {e}. The server did not start.");
                std::process::exit(1);
            }
        },
    };

    let graph_client = GraphClient::new(token_manager.clone());
    let endpoint_client = EndpointClient::new(token_manager);

    // 7. Serve or bind HTTP.
    match config.transport {
        TransportMode::Http => run_http(graph_client, endpoint_client, config, audit_sink).await,
        TransportMode::Stdio => run_stdio(graph_client, endpoint_client, config, audit_sink).await,
    }
}

/// Run the server over stdio transport (for local MCP client integration).
async fn run_stdio(
    graph_client: GraphClient,
    endpoint_client: EndpointClient,
    config: ServerConfig,
    audit_sink: Option<Arc<AuditSink>>,
) -> anyhow::Result<()> {
    let service =
        DefenderServer::new_with_config(graph_client, endpoint_client, config, audit_sink)
            .serve(rmcp::transport::io::stdio())
            .await?;
    tracing::info!("Defender MCP server running on stdio");
    service.waiting().await?;
    Ok(())
}

/// Run the server over streamable HTTP transport (for remote MCP clients).
async fn run_http(
    graph_client: GraphClient,
    endpoint_client: EndpointClient,
    config: ServerConfig,
    audit_sink: Option<Arc<AuditSink>>,
) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };

    let bind_addr = config.bind_address.clone();
    let ct = tokio_util::sync::CancellationToken::new();

    let service = StreamableHttpService::new(
        move || {
            let g = graph_client.clone();
            let e = endpoint_client.clone();
            let c = config.clone();
            let a = audit_sink.clone();
            Ok(DefenderServer::new_with_config(g, e, c, a))
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_cancellation_token(ct.child_token()),
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Defender MCP server listening on http://{bind_addr}/mcp");
    let cancel = ct.child_token();
    tokio::select! {
        res = axum::serve(listener, router) => {
            res?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received, draining HTTP connections...");
            cancel.cancel();
        }
    }
    Ok(())
}
