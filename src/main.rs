//! Microsoft Defender MCP Server
//!
//! An MCP server providing access to Microsoft Defender APIs via Microsoft Graph
//! Security and Defender for Endpoint APIs. The vast majority of tools are read-only
//! inspection, search, and threat intelligence operations; live response remediation
//! and file library upload provide gated mutation capabilities.
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
//!   - Live Response remediation & library management: `Machine.LiveResponse`, `Library.Manage`
//!   - Note: Upstream Defender for Endpoint APIs require write-named scopes for a few specific
//!     read-only queries (e.g., domain/file/user related machines require `Machine.ReadWrite.All`,
//!     and file-related alerts require `Alert.ReadWrite.All`).
//! - Active Microsoft Defender Threat Intelligence Portal license and API add-on
//!   license for the tenant (if using TI tools).
//! - Environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
//!   `AZURE_CLIENT_SECRET`.
//! - Optional Live Response gating variables: `DEFENDER_ENABLE_LIVE_RESPONSE`,
//!   `DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS`.
//!
//! ## Transport
//!
//! Defaults to stdio transport (for local MCP client integration).
//! Set `TRANSPORT=http` for streamable HTTP (on `BIND_ADDRESS`, default `127.0.0.1:8000`).
//!
//! ### Security Notice for Remote HTTP Deployments
//!
//! The streamable HTTP transport does not provide built-in authentication or encryption.
//! When binding beyond localhost (`127.0.0.1`), the HTTP endpoint MUST be protected
//! behind an authenticated reverse proxy, VPN, or equivalent network security boundary.
mod auth;
mod client;
mod constants;
mod error;
mod server;
mod validation;

use std::time::Duration;

use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use crate::auth::TokenManager;
use crate::client::{EndpointClient, GraphClient};
use crate::constants::{ENV_TRANSPORT, REQUEST_TIMEOUT_SECS};
use crate::server::DefenderServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    match std::env::var(ENV_TRANSPORT).as_deref() {
        Ok("http") => run_http(graph_client, endpoint_client).await,
        _ => run_stdio(graph_client, endpoint_client).await,
    }
}

/// Run the server over stdio transport (for local MCP client integration).
async fn run_stdio(
    graph_client: GraphClient,
    endpoint_client: EndpointClient,
) -> anyhow::Result<()> {
    let service = DefenderServer::new(graph_client, endpoint_client)
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
) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };

    let bind_addr = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8000".to_string());
    let ct = tokio_util::sync::CancellationToken::new();

    let service = StreamableHttpService::new(
        move || {
            let g = graph_client.clone();
            let e = endpoint_client.clone();
            Ok(DefenderServer::new(g, e))
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
