//! Microsoft Defender MCP Server
//!
//! An MCP server providing access to Microsoft Defender APIs via Microsoft Graph
//! Security and Defender for Endpoint APIs. `--tool-mode granular` (default) exposes 88
//! tools (86 read-only); `--tool-mode consolidated` exposes 7 action-based tools including
//! forensic artifact retrieval. Mutating tools are gated by `--enable-live-response` and
//! hidden/rejected under `--read-only`. See `--help` and [`cli`](microsoft_defender_mcp_server::cli).
//!
//! ## Prerequisites
//!
//! - Azure AD (Entra ID) application registration. Following least privilege, grant only
//!   the application permissions required by the specific tools you plan to use (refer to
//!   tool descriptions for endpoint details). Common permission examples include:
//!   - Microsoft Graph: e.g., `ThreatHunting.Read.All`, `ThreatIntelligence.Read.All`,
//!     `SecurityAlert.Read.All`, `SecurityIncident.Read.All`
//!   - Defender for Endpoint: e.g., `Machine.Read.All`, `Vulnerability.Read.All`,
//!     `Software.Read.All`, `Score.Read.All`, `Alert.Read.All`
//!   - Response & library management: `Machine.LiveResponse`, `Library.Manage`,
//!     `Machine.CollectForensics`, `Machine.StopAndQuarantine`
//!   - Note: Upstream Defender for Endpoint APIs require write-named scopes for a few specific
//!     read-only queries (e.g., domain/file/user related machines require `Machine.ReadWrite.All`,
//!     and file-related alerts require `Alert.ReadWrite.All`).
//! - Active Microsoft Defender Threat Intelligence Portal license and API add-on
//!   license for the tenant (if using TI tools).
//! - Environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
//!   `AZURE_CLIENT_SECRET`. Server options are CLI flags with environment fallbacks
//!   (e.g. `--read-only` / `DEFENDER_READ_ONLY`).
//!
//! ## Transport
//!
//! Defaults to stdio transport (for local MCP client integration).
//! `--transport http` serves streamable HTTP on `--bind-address` (default `127.0.0.1:8000`).
//!
//! ### Security Notice for Remote HTTP Deployments
//!
//! The streamable HTTP transport does not provide built-in authentication or encryption.
//! When binding beyond localhost (`127.0.0.1`), the HTTP endpoint MUST be protected
//! behind an authenticated reverse proxy, VPN, or equivalent network security boundary.

use std::time::Duration;

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use microsoft_defender_mcp_server::auth::TokenManager;
use microsoft_defender_mcp_server::cli::{Cli, ServerConfig, TransportMode, warn_if_non_loopback};
use microsoft_defender_mcp_server::client::{EndpointClient, GraphClient};
use microsoft_defender_mcp_server::constants::REQUEST_TIMEOUT_SECS;
use microsoft_defender_mcp_server::server::DefenderServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI arguments (handles --help and --version immediately before auth or network init).
    let cli = Cli::parse();
    let config = ServerConfig::from_cli(cli);

    // If running in HTTP mode, validate loopback and print security notice to stderr if needed.
    if config.transport == TransportMode::Http {
        warn_if_non_loopback(&config.bind_address);
    }

    // Log to stderr — stdout is reserved for the MCP stdio protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // Build shared HTTP client with timeout.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .expect("failed to build reqwest client");

    // Initialize token manager from environment.
    let token_manager =
        TokenManager::from_env(http).map_err(|e| anyhow::anyhow!("Configuration error: {e}"))?;

    let graph_client = GraphClient::new(token_manager.clone());
    let endpoint_client = EndpointClient::new(token_manager);

    match config.transport {
        TransportMode::Http => run_http(graph_client, endpoint_client, config).await,
        TransportMode::Stdio => run_stdio(graph_client, endpoint_client, config).await,
    }
}

/// Run the server over stdio transport (for local MCP client integration).
async fn run_stdio(
    graph_client: GraphClient,
    endpoint_client: EndpointClient,
    config: ServerConfig,
) -> anyhow::Result<()> {
    let service = DefenderServer::new_with_config(graph_client, endpoint_client, config)
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
            Ok(DefenderServer::new_with_config(g, e, c))
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_cancellation_token(ct.child_token()),
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Defender MCP server listening on http://{bind_addr}/mcp");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            ct.cancel();
        })
        .await?;

    Ok(())
}
