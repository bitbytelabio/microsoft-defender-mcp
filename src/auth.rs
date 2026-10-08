//! Azure AD token acquisition and caching — multi-scope support.
//!
//! Uses `client_credentials` grant against the Entra ID OAuth2 v2.0 endpoint.
//! Tokens are cached in memory per scope with a 60-second expiry buffer.
//! Cache key: `"{tenant}:{client}:{scope}"`.

pub mod session;
pub mod signin;

pub use session::{Audience, ConsentState, DelegatedSession, IdTokenClaims, ReauthReason, Secret};
pub use signin::{
    BrowserLauncher, LoopbackListener, Pkce, RefreshTokenError, RefreshTokenSuccess, SignInError,
    TokenEndpointError, interactive_sign_in, refresh_token_grant,
};

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;

use crate::constants::{
    AUTHORITY_BASE_URL, ENV_AUTHORITY_BASE_URL, ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_TENANT_ID,
    TOKEN_EXPIRY_BUFFER_SECS,
};
use crate::error::internal_error;

/// Credential held by the token manager: client secret in app mode, delegated session in user mode.
enum Credential {
    ClientSecret(Secret),
    Delegated(DelegatedSession),
}

/// A cached access token with an expiry timestamp.
#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: i64,
}

impl CachedToken {
    fn is_valid(&self) -> bool {
        Utc::now().timestamp() + TOKEN_EXPIRY_BUFFER_SECS < self.expires_at
    }
}

/// Manages Azure AD token acquisition and in-memory caching per audience.
#[derive(Clone)]
pub struct TokenManager {
    tenant_id: String,
    client_id: String,
    credential: Arc<Credential>,
    pub http_client: reqwest::Client,
    /// Cache keyed by audience.
    cache: Arc<RwLock<HashMap<Audience, CachedToken>>>,
    /// Guards in-flight renewals so exactly one request is made concurrently.
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
    /// Configured scopes per audience for delegated refresh grants.
    audience_scopes: Arc<HashMap<Audience, Vec<String>>>,
}

impl TokenManager {
    /// Create a new TokenManager in app mode from environment variables.
    pub fn from_env(http_client: reqwest::Client) -> Result<Self, anyhow::Error> {
        let tenant_id = std::env::var(ENV_TENANT_ID)
            .map_err(|_| anyhow::anyhow!("{ENV_TENANT_ID} environment variable is required"))?;
        let client_id = std::env::var(ENV_CLIENT_ID)
            .map_err(|_| anyhow::anyhow!("{ENV_CLIENT_ID} environment variable is required"))?;
        let client_secret = std::env::var(ENV_CLIENT_SECRET)
            .map_err(|_| anyhow::anyhow!("{ENV_CLIENT_SECRET} environment variable is required"))?;

        let mut audience_scopes = HashMap::new();
        audience_scopes.insert(
            Audience::Endpoint,
            vec![format!("{}/.default", Audience::Endpoint.resource_url())],
        );
        audience_scopes.insert(
            Audience::Graph,
            vec![format!("{}/.default", Audience::Graph.resource_url())],
        );

        Ok(Self {
            tenant_id,
            client_id,
            credential: Arc::new(Credential::ClientSecret(Secret::new(client_secret))),
            http_client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            audience_scopes: Arc::new(audience_scopes),
        })
    }

    /// Interactive sign-in in delegated user mode at startup (T036).
    pub async fn sign_in_user(
        config: &crate::cli::ServerConfig,
        flow: crate::cli::SignInFlow,
        http_client: reqwest::Client,
    ) -> Result<Self, anyhow::Error> {
        let tenant_id = std::env::var(ENV_TENANT_ID)
            .map_err(|_| anyhow::anyhow!("{ENV_TENANT_ID} environment variable is required"))?;
        let client_id = std::env::var(ENV_CLIENT_ID)
            .map_err(|_| anyhow::anyhow!("{ENV_CLIENT_ID} environment variable is required"))?;

        let audience_scopes = compute_audience_scopes(config);
        let mut all_resource_scopes = Vec::new();
        for aud in [Audience::Endpoint, Audience::Graph] {
            if let Some(sc) = audience_scopes.get(&aud) {
                for s in sc {
                    if !all_resource_scopes.contains(s) {
                        all_resource_scopes.push(s.clone());
                    }
                }
            }
        }

        let (claims, mut current_rt) = signin::interactive_sign_in(
            &http_client,
            &tenant_id,
            &client_id,
            flow,
            &all_resource_scopes,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.failure_reason()))?;

        let mut consent_map = HashMap::new();
        let mut initial_cache = HashMap::new();

        for aud in [Audience::Endpoint, Audience::Graph] {
            let scopes = audience_scopes.get(&aud).cloned().unwrap_or_default();
            let res = signin::refresh_token_grant(
                &http_client,
                &tenant_id,
                &client_id,
                &current_rt,
                &scopes,
            )
            .await;

            match res {
                Ok(success) => {
                    if let Some(new_rt) = success.refresh_token {
                        current_rt = new_rt;
                    }
                    let expires_at = Utc::now().timestamp() + success.expires_in as i64;
                    consent_map.insert(
                        aud,
                        ConsentState::Granted {
                            scopes: success.scopes,
                            expires_at,
                        },
                    );
                    initial_cache.insert(
                        aud,
                        CachedToken {
                            token: success.access_token.expose().to_string(),
                            expires_at,
                        },
                    );
                }
                Err(err) => {
                    if let Some(ep_err) = err.as_endpoint_error()
                        && ep_err.error == "invalid_grant"
                        && ep_err.aadsts == Some(65001)
                    {
                        consent_map.insert(
                            aud,
                            ConsentState::Missing {
                                aadsts: Some(65001),
                            },
                        );
                        continue;
                    }
                    return Err(anyhow::anyhow!("{err}"));
                }
            }
        }

        let endpoint_missing = matches!(
            consent_map.get(&Audience::Endpoint),
            Some(ConsentState::Missing { .. })
        );
        let graph_missing = matches!(
            consent_map.get(&Audience::Graph),
            Some(ConsentState::Missing { .. })
        );
        if endpoint_missing && graph_missing {
            return Err(anyhow::anyhow!("consent missing for both audiences"));
        }

        let account = claims.account_name().unwrap_or("unknown").to_string();
        let session_tenant_id = claims.tid.unwrap_or(tenant_id.clone());
        let session = DelegatedSession::new(
            account,
            session_tenant_id,
            current_rt,
            all_resource_scopes,
            consent_map,
        );

        eprintln!("{}", session.status_line());

        Ok(Self {
            tenant_id,
            client_id,
            credential: Arc::new(Credential::Delegated(session)),
            http_client,
            cache: Arc::new(RwLock::new(initial_cache)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            audience_scopes: Arc::new(audience_scopes),
        })
    }

    /// Get a valid access token for the given audience, refreshing if necessary.
    pub async fn get_token(
        &self,
        audience: Audience,
    ) -> Result<String, rmcp::model::CallToolResult> {
        // Fast fail if session is reauth-required or consent is missing
        if let Credential::Delegated(session) = self.credential.as_ref() {
            if let Some(reason) = session.reauth.get() {
                return Err(crate::error::reauthentication_required(reason.as_str()));
            }
            if let Some(ConsentState::Missing { .. }) = session.consent_state(&audience) {
                let scopes = self
                    .audience_scopes
                    .get(&audience)
                    .cloned()
                    .unwrap_or_default();
                return Err(crate::error::consent_missing(audience.as_str(), &scopes));
            }
        }

        // Fast path: read from cache
        {
            let guard = self.cache.read().await;
            if let Some(cached) = guard.get(&audience)
                && cached.is_valid()
            {
                return Ok(cached.token.clone());
            }
        }

        // Slow path: single-flight refresh lock
        let _guard = self.refresh_lock.lock().await;

        // Re-check reauth, consent, and cache after acquiring the lock
        if let Credential::Delegated(session) = self.credential.as_ref() {
            if let Some(reason) = session.reauth.get() {
                return Err(crate::error::reauthentication_required(reason.as_str()));
            }
            if let Some(ConsentState::Missing { .. }) = session.consent_state(&audience) {
                let scopes = self
                    .audience_scopes
                    .get(&audience)
                    .cloned()
                    .unwrap_or_default();
                return Err(crate::error::consent_missing(audience.as_str(), &scopes));
            }
        }

        {
            let guard = self.cache.read().await;
            if let Some(cached) = guard.get(&audience)
                && cached.is_valid()
            {
                return Ok(cached.token.clone());
            }
        }

        match self.credential.as_ref() {
            Credential::ClientSecret(secret) => {
                let token = self
                    .fetch_app_token(audience, secret)
                    .await
                    .map_err(|e| crate::error::tool_error(format!("Auth error: {e}")))?;
                let mut guard = self.cache.write().await;
                guard.insert(audience, token.clone());
                Ok(token.token)
            }
            Credential::Delegated(session) => {
                let current_rt = {
                    let guard = session.refresh_token.lock().unwrap();
                    guard.expose().to_string()
                };
                let scopes = self
                    .audience_scopes
                    .get(&audience)
                    .cloned()
                    .unwrap_or_default();
                let res = signin::refresh_token_grant(
                    &self.http_client,
                    &self.tenant_id,
                    &self.client_id,
                    &Secret::new(current_rt),
                    &scopes,
                )
                .await;

                match res {
                    Ok(success) => {
                        if let Some(new_rt) = success.refresh_token {
                            let mut guard = session.refresh_token.lock().unwrap();
                            *guard = new_rt;
                        }
                        let expires_at = Utc::now().timestamp() + success.expires_in as i64;
                        let cached = CachedToken {
                            token: success.access_token.expose().to_string(),
                            expires_at,
                        };
                        let mut guard = self.cache.write().await;
                        guard.insert(audience, cached.clone());
                        Ok(cached.token)
                    }
                    Err(err) => {
                        if let Some(ep_err) = err.as_endpoint_error() {
                            if ep_err.error == "invalid_grant" {
                                match ep_err.aadsts {
                                    Some(700082) | Some(70043) | Some(50173) => {
                                        session.set_reauth(ReauthReason::SessionExpired);
                                        return Err(crate::error::reauthentication_required(
                                            ReauthReason::SessionExpired.as_str(),
                                        ));
                                    }
                                    Some(50076) | Some(50079) => {
                                        session.set_reauth(ReauthReason::MfaRequired);
                                        return Err(crate::error::reauthentication_required(
                                            ReauthReason::MfaRequired.as_str(),
                                        ));
                                    }
                                    Some(65001) => {
                                        session.set_consent(
                                            audience,
                                            ConsentState::Missing {
                                                aadsts: Some(65001),
                                            },
                                        );
                                        return Err(crate::error::consent_missing(
                                            audience.as_str(),
                                            &scopes,
                                        ));
                                    }
                                    _ => {
                                        session.set_reauth(ReauthReason::SessionRevoked);
                                        return Err(crate::error::reauthentication_required(
                                            ReauthReason::SessionRevoked.as_str(),
                                        ));
                                    }
                                }
                            } else if ep_err.error == "interaction_required" {
                                session.set_reauth(ReauthReason::InteractionRequired);
                                return Err(crate::error::reauthentication_required(
                                    ReauthReason::InteractionRequired.as_str(),
                                ));
                            }
                        }
                        Err(crate::error::tool_error(format!(
                            "Token refresh failed: {err}"
                        )))
                    }
                }
            }
        }
    }

    async fn fetch_app_token(
        &self,
        audience: Audience,
        secret: &Secret,
    ) -> Result<CachedToken, rmcp::ErrorData> {
        let authority = std::env::var(ENV_AUTHORITY_BASE_URL)
            .unwrap_or_else(|_| AUTHORITY_BASE_URL.to_string());
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            authority.trim_end_matches('/'),
            self.tenant_id
        );

        let scope = format!("{}/.default", audience.resource_url());
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", secret.expose()),
            ("scope", &scope),
        ];

        let resp = self
            .http_client
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| internal_error(format!("token request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let _body = resp.text().await.unwrap_or_default();
            tracing::error!(
                status = %status.as_u16(),
                audience = %audience,
                "Token acquisition failed"
            );
            return Err(internal_error(format!(
                "token acquisition failed (HTTP {}) for audience {}",
                status.as_u16(),
                audience
            )));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: i64,
        }

        let data: TokenResponse = resp
            .json()
            .await
            .map_err(|e| internal_error(format!("failed to parse token response: {e}")))?;

        let expires_at = Utc::now().timestamp() + data.expires_in;

        tracing::info!(
            audience = %audience,
            expires_in = %data.expires_in,
            "Token acquired"
        );

        Ok(CachedToken {
            token: data.access_token,
            expires_at,
        })
    }

    /// Record a re-authentication requirement (e.g. from an upstream 401 with claims challenge).
    pub fn set_reauth(&self, reason: ReauthReason) {
        if let Credential::Delegated(session) = self.credential.as_ref() {
            session.set_reauth(reason);
        }
    }
    /// Return the current identity snapshot for audit logging and confirmation prompts.
    pub fn identity(&self) -> IdentitySnapshot {
        match self.credential.as_ref() {
            Credential::ClientSecret(_) => IdentitySnapshot::App {
                client_id: self.client_id.clone(),
            },
            Credential::Delegated(session) => IdentitySnapshot::User {
                account: session.account.clone(),
                tenant_id: session.tenant_id.clone(),
            },
        }
    }

    /// Return the authentication kind (App or User).
    pub fn auth_kind(&self) -> AuthKind {
        match self.credential.as_ref() {
            Credential::ClientSecret(_) => AuthKind::App,
            Credential::Delegated(_) => AuthKind::User,
        }
    }
}

/// Authentication kind for the current session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    App,
    User,
}

/// Snapshot of acting identity for audit logs and confirmation prompts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentitySnapshot {
    App { client_id: String },
    User { account: String, tenant_id: String },
}

impl IdentitySnapshot {
    /// Format for human confirmation prompt.
    pub fn display_prompt(&self) -> String {
        match self {
            Self::App { client_id } => format!("application {client_id} (app)"),
            Self::User { account, .. } => format!("{account} (user)"),
        }
    }

    /// Format for stderr audit summary line.
    pub fn display_summary(&self) -> String {
        match self {
            Self::App { client_id } => format!("app:{client_id}"),
            Self::User { account, .. } => format!("user:{account}"),
        }
    }
}

/// Permission categories mapping to required scopes and Defender role permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCategory {
    ReadEndpoint,
    ReadGraph,
    ReadWriteNamed,
    LiveResponse,
    DeviceResponse,
    Offboarding,
    Indicators,
    Triage,
}

impl PermissionCategory {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::ReadEndpoint => "read_endpoint",
            Self::ReadGraph => "read_graph",
            Self::ReadWriteNamed => "read_write_named",
            Self::LiveResponse => "live_response",
            Self::DeviceResponse => "device_response",
            Self::Offboarding => "offboarding",
            Self::Indicators => "indicators",
            Self::Triage => "triage",
        }
    }

    pub fn category_name(&self) -> &'static str {
        match self {
            Self::ReadEndpoint => "Read (endpoint)",
            Self::ReadGraph => "Read (Graph)",
            Self::ReadWriteNamed => "Reads needing write-named scopes",
            Self::LiveResponse => "Live Response",
            Self::DeviceResponse => "Device response",
            Self::Offboarding => "Offboarding",
            Self::Indicators => "Indicators",
            Self::Triage => "Triage",
        }
    }

    pub fn audience(&self) -> &'static str {
        match self {
            Self::ReadGraph | Self::Triage => "graph",
            _ => "endpoint",
        }
    }

    pub fn delegated_scope(&self) -> &'static str {
        match self {
            Self::ReadEndpoint => "the *.Read equivalents, plus User.Read.All",
            Self::ReadGraph => {
                "ThreatHunting.Read.All, ThreatIntelligence.Read.All, SecurityAlert.Read.All, SecurityIncident.Read.All"
            }
            Self::ReadWriteNamed => {
                "Machine.ReadWrite, Alert.ReadWrite, Ti.ReadWrite, Library.Manage"
            }
            Self::LiveResponse => {
                "Machine.LiveResponse, Machine.CollectForensics, Machine.StopAndQuarantine, Library.Manage"
            }
            Self::DeviceResponse => {
                "Machine.Isolate, Machine.RestrictExecution, Machine.Scan, Machine.ReadWrite, Alert.ReadWrite"
            }
            Self::Offboarding => "Machine.Offboard",
            Self::Indicators => "Ti.ReadWrite",
            Self::Triage => {
                "Alert.ReadWrite, SecurityAlert.ReadWrite.All, SecurityIncident.ReadWrite.All"
            }
        }
    }

    pub fn defender_role(&self) -> &'static str {
        match self {
            Self::ReadEndpoint => "View data",
            Self::ReadGraph => "Entra Security Reader, or a Unified RBAC role with equivalent read",
            Self::ReadWriteNamed => "View data",
            Self::LiveResponse => {
                "Live response capabilities; Alerts investigation; Active remediation actions"
            }
            Self::DeviceResponse => {
                "Active remediation actions (isolate, restrict, scan, investigate); Manage security settings (tags, device value)"
            }
            Self::Offboarding => "Per Permission options",
            Self::Indicators => "Active remediation actions (manage indicators)",
            Self::Triage => "Alerts investigation; Entra Security Operator",
        }
    }

    pub fn is_app_only(&self) -> bool {
        false
    }
}

impl TokenManager {
    /// Create a test token manager pre-seeded with valid dummy tokens for Graph and Endpoint audiences.
    pub fn for_test(http: reqwest::Client) -> Self {
        let mut cache = HashMap::new();
        let far_future = Utc::now().timestamp() + 86400 * 365;
        cache.insert(
            Audience::Graph,
            CachedToken {
                token: "test-graph-token".to_string(),
                expires_at: far_future,
            },
        );
        cache.insert(
            Audience::Endpoint,
            CachedToken {
                token: "test-endpoint-token".to_string(),
                expires_at: far_future,
            },
        );

        let mut audience_scopes = HashMap::new();
        audience_scopes.insert(
            Audience::Endpoint,
            vec![format!("{}/.default", Audience::Endpoint.resource_url())],
        );
        audience_scopes.insert(
            Audience::Graph,
            vec![format!("{}/.default", Audience::Graph.resource_url())],
        );

        Self {
            tenant_id: "test-tenant-id".to_string(),
            client_id: "test-client-id".to_string(),
            credential: Arc::new(Credential::ClientSecret(Secret::new("test-client-secret"))),
            http_client: http,
            cache: Arc::new(RwLock::new(cache)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            audience_scopes: Arc::new(audience_scopes),
        }
    }

    /// Create a test token manager in delegated user mode.
    pub fn for_test_user(
        http: reqwest::Client,
        account: impl Into<String>,
        tenant_id: impl Into<String>,
        scopes: HashMap<Audience, Vec<String>>,
        consent: HashMap<Audience, ConsentState>,
        refresh_token: Secret,
    ) -> Self {
        let account_str = account.into();
        let tenant_str = tenant_id.into();
        let all_scopes: Vec<String> = scopes.values().flatten().cloned().collect();
        let mut initial_cache = HashMap::new();
        for (aud, state) in &consent {
            if let ConsentState::Granted { expires_at, .. } = state {
                initial_cache.insert(
                    *aud,
                    CachedToken {
                        token: format!("test-{}-token", aud.as_str()),
                        expires_at: *expires_at,
                    },
                );
            }
        }

        let session = DelegatedSession::new(
            account_str,
            tenant_str.clone(),
            refresh_token,
            all_scopes,
            consent,
        );

        Self {
            tenant_id: tenant_str,
            client_id: "test-client-id".to_string(),
            credential: Arc::new(Credential::Delegated(session)),
            http_client: http,
            cache: Arc::new(RwLock::new(initial_cache)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            audience_scopes: Arc::new(scopes),
        }
    }
}

/// Compute requested scope sets per R-05 from ServerConfig.
pub fn compute_audience_scopes(
    config: &crate::cli::ServerConfig,
) -> HashMap<Audience, Vec<String>> {
    let mut endpoint_scopes = vec![
        "Machine.Read",
        "Alert.Read",
        "Vulnerability.Read",
        "Software.Read",
        "SecurityRecommendation.Read",
        "Score.Read",
        "RemediationTasks.Read",
        "User.Read.All",
    ];

    if !config.read_only {
        endpoint_scopes.extend([
            "Machine.ReadWrite",
            "Alert.ReadWrite",
            "Ti.ReadWrite",
            "Library.Manage",
        ]);
    }

    if config.categories.live_response {
        endpoint_scopes.extend([
            "Machine.LiveResponse",
            "Machine.CollectForensics",
            "Machine.StopAndQuarantine",
            "Library.Manage",
        ]);
    }

    if config.categories.device_response {
        endpoint_scopes.extend([
            "Machine.Isolate",
            "Machine.RestrictExecution",
            "Machine.Scan",
            "Machine.ReadWrite",
            "Alert.ReadWrite",
        ]);
    }

    if config.categories.offboarding {
        endpoint_scopes.push("Machine.Offboard");
    }

    if config.categories.indicators {
        endpoint_scopes.push("Ti.ReadWrite");
    }

    if config.categories.triage {
        endpoint_scopes.push("Alert.ReadWrite");
    }

    let mut graph_scopes = vec![
        "ThreatHunting.Read.All",
        "ThreatIntelligence.Read.All",
        "SecurityAlert.Read.All",
        "SecurityIncident.Read.All",
    ];

    if config.categories.triage {
        graph_scopes.extend([
            "SecurityAlert.ReadWrite.All",
            "SecurityIncident.ReadWrite.All",
        ]);
    }

    let mut ep_prefixed = Vec::new();
    for s in endpoint_scopes {
        let full = format!("https://api.securitycenter.microsoft.com/{s}");
        if !ep_prefixed.contains(&full) {
            ep_prefixed.push(full);
        }
    }

    let mut gr_prefixed = Vec::new();
    for s in graph_scopes {
        let full = format!("https://graph.microsoft.com/{s}");
        if !gr_prefixed.contains(&full) {
            gr_prefixed.push(full);
        }
    }

    let mut map = HashMap::new();
    map.insert(Audience::Endpoint, ep_prefixed);
    map.insert(Audience::Graph, gr_prefixed);
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn parse_tool_error(err: &rmcp::model::CallToolResult) -> serde_json::Value {
        assert_eq!(err.is_error, Some(true));
        err.structured_content.clone().expect("structured_content")
    }

    #[test]
    fn test_compute_audience_scopes_read_only() {
        let cli = crate::cli::Cli {
            transport: crate::cli::TransportMode::Stdio,
            bind_address: "127.0.0.1:8000".to_string(),
            read_only: true,
            enable_live_response: true,
            allowed_commands: None,
            enable_device_response: true,
            enable_offboarding: true,
            enable_indicators: true,
            enable_triage: true,
            disable_human_confirmation: false,
            audit_log: None,
            auth_mode: crate::cli::AuthMode::User,
            sign_in_flow: None,
            quarantine_dir: std::path::PathBuf::from("./quarantine"),
            tool_mode_tombstone: None,
        };
        let config = crate::cli::ServerConfig::from_cli(cli);
        let scopes = compute_audience_scopes(&config);

        let ep = scopes.get(&Audience::Endpoint).unwrap();
        let gr = scopes.get(&Audience::Graph).unwrap();

        assert_eq!(ep.len(), 8);
        assert!(ep.iter().all(|s| !s.contains(".default")));
        assert!(ep.contains(&"https://api.securitycenter.microsoft.com/Machine.Read".to_string()));
        assert!(ep.contains(&"https://api.securitycenter.microsoft.com/User.Read.All".to_string()));
        assert!(
            !ep.contains(&"https://api.securitycenter.microsoft.com/Machine.ReadWrite".to_string())
        );
        assert!(
            !ep.contains(&"https://api.securitycenter.microsoft.com/Machine.Isolate".to_string())
        );
        assert!(
            !ep.contains(&"https://api.securitycenter.microsoft.com/Machine.Offboard".to_string())
        );
        assert!(!ep.contains(&"https://api.securitycenter.microsoft.com/Ti.ReadWrite".to_string()));
        assert!(
            !ep.contains(&"https://api.securitycenter.microsoft.com/Library.Manage".to_string())
        );

        assert_eq!(gr.len(), 4);
        assert!(gr.iter().all(|s| !s.contains(".default")));
        assert!(gr.contains(&"https://graph.microsoft.com/ThreatHunting.Read.All".to_string()));
        assert!(
            !gr.contains(&"https://graph.microsoft.com/SecurityAlert.ReadWrite.All".to_string())
        );
    }

    #[test]
    fn test_compute_audience_scopes_all_categories() {
        let cli = crate::cli::Cli {
            transport: crate::cli::TransportMode::Stdio,
            bind_address: "127.0.0.1:8000".to_string(),
            read_only: false,
            enable_live_response: true,
            allowed_commands: None,
            enable_device_response: true,
            enable_offboarding: true,
            enable_indicators: true,
            enable_triage: true,
            disable_human_confirmation: false,
            audit_log: None,
            auth_mode: crate::cli::AuthMode::User,
            sign_in_flow: None,
            quarantine_dir: std::path::PathBuf::from("./quarantine"),
            tool_mode_tombstone: None,
        };
        let config = crate::cli::ServerConfig::from_cli(cli);
        let scopes = compute_audience_scopes(&config);

        let ep = scopes.get(&Audience::Endpoint).unwrap();
        let gr = scopes.get(&Audience::Graph).unwrap();

        assert!(
            ep.contains(&"https://api.securitycenter.microsoft.com/Machine.ReadWrite".to_string())
        );
        assert!(ep.contains(
            &"https://api.securitycenter.microsoft.com/Machine.LiveResponse".to_string()
        ));
        assert!(
            ep.contains(&"https://api.securitycenter.microsoft.com/Machine.Isolate".to_string())
        );
        assert!(
            ep.contains(&"https://api.securitycenter.microsoft.com/Machine.Offboard".to_string())
        );
        assert!(ep.contains(&"https://api.securitycenter.microsoft.com/Ti.ReadWrite".to_string()));
        assert!(
            ep.contains(&"https://api.securitycenter.microsoft.com/Library.Manage".to_string())
        );

        assert!(
            gr.contains(&"https://graph.microsoft.com/SecurityAlert.ReadWrite.All".to_string())
        );
        assert!(
            gr.contains(&"https://graph.microsoft.com/SecurityIncident.ReadWrite.All".to_string())
        );
    }

    #[test]
    fn test_identity_snapshot_formats() {
        let snap = IdentitySnapshot::User {
            account: "alice@contoso.com".to_string(),
            tenant_id: "72f988bf-1234-5678-9abc-def012345678".to_string(),
        };
        assert_eq!(snap.display_prompt(), "alice@contoso.com (user)");
        assert_eq!(snap.display_summary(), "user:alice@contoso.com");
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["kind"], "user");
        assert_eq!(json["account"], "alice@contoso.com");
        assert_eq!(json["tenant_id"], "72f988bf-1234-5678-9abc-def012345678");

        let app = IdentitySnapshot::App {
            client_id: "my-app-id".to_string(),
        };
        assert_eq!(app.display_prompt(), "application my-app-id (app)");
        assert_eq!(app.display_summary(), "app:my-app-id");
    }

    #[tokio::test]
    async fn test_single_flight_refresh_concurrent() {
        let _env_guard = crate::auth::signin::tests::TEST_ENV_LOCK.lock().await;
        #[derive(Clone)]
        struct MockState {
            refresh_hits: Arc<AtomicUsize>,
        }

        let state = MockState {
            refresh_hits: Arc::new(AtomicUsize::new(0)),
        };

        let app = Router::new()
            .route(
                "/{tenant}/oauth2/v2.0/token",
                post(|State(state): State<MockState>| async move {
                    state.refresh_hits.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Json(json!({
                        "access_token": "NEW-REFRESHED-AT",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "ROTATED-RT",
                        "scope": "https://api.securitycenter.microsoft.com/Machine.Read"
                    }))
                }),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_url = format!("http://{addr}");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        unsafe {
            std::env::set_var(crate::constants::ENV_AUTHORITY_BASE_URL, &server_url);
        }

        let http = reqwest::Client::new();
        let mut scopes = HashMap::new();
        scopes.insert(
            Audience::Endpoint,
            vec!["https://api.securitycenter.microsoft.com/Machine.Read".to_string()],
        );

        let mut consent = HashMap::new();
        consent.insert(
            Audience::Endpoint,
            ConsentState::Granted {
                scopes: vec!["Machine.Read".to_string()],
                expires_at: Utc::now().timestamp() - 100, // expired!
            },
        );

        let tm = TokenManager::for_test_user(
            http,
            "alice@contoso.com",
            "tenant-1",
            scopes,
            consent,
            Secret::new("INITIAL-RT"),
        );

        // Spawn 20 concurrent requests for Audience::Endpoint
        let mut handles = Vec::new();
        for _ in 0..20 {
            let tm_clone = tm.clone();
            handles.push(tokio::spawn(async move {
                tm_clone.get_token(Audience::Endpoint).await
            }));
        }

        for h in handles {
            let res = h.await.unwrap();
            assert_eq!(res.unwrap(), "NEW-REFRESHED-AT");
        }

        // Exactly one refresh hit occurred
        assert_eq!(state.refresh_hits.load(Ordering::SeqCst), 1);

        // Refresh token rotated
        if let Credential::Delegated(session) = tm.credential.as_ref() {
            assert_eq!(session.refresh_token.lock().unwrap().expose(), "ROTATED-RT");
        } else {
            panic!("expected delegated session");
        }
        unsafe {
            std::env::remove_var(crate::constants::ENV_AUTHORITY_BASE_URL);
        }
    }

    #[tokio::test]
    async fn test_reauth_classification_table_and_fail_fast() {
        let _env_guard = crate::auth::signin::tests::TEST_ENV_LOCK.lock().await;
        #[derive(Clone)]
        struct ErrorMockState {
            hits: Arc<AtomicUsize>,
            status: axum::http::StatusCode,
            error_body: serde_json::Value,
        }

        let cases = [
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "AADSTS700082: The refresh token has expired"}),
                "session_expired",
            ),
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "AADSTS70043: Refresh token expired"}),
                "session_expired",
            ),
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "AADSTS50173: Fresh auth needed"}),
                "session_expired",
            ),
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "AADSTS50076: Due to a configuration change MFA is required"}),
                "mfa_required",
            ),
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "AADSTS50079: User must enroll MFA"}),
                "mfa_required",
            ),
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "interaction_required", "error_description": "Interaction required"}),
                "interaction_required",
            ),
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "AADSTS99999: Something revoked"}),
                "session_revoked",
            ),
        ];

        for (status, body, expected_reason) in cases {
            let hits = Arc::new(AtomicUsize::new(0));
            let state = ErrorMockState {
                hits: hits.clone(),
                status,
                error_body: body,
            };

            let app = Router::new()
                .route(
                    "/{tenant}/oauth2/v2.0/token",
                    post(|State(state): State<ErrorMockState>| async move {
                        state.hits.fetch_add(1, Ordering::SeqCst);
                        (state.status, Json(state.error_body))
                    }),
                )
                .with_state(state);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_url = format!("http://{addr}");
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });

            unsafe {
                std::env::set_var(crate::constants::ENV_AUTHORITY_BASE_URL, &server_url);
            }

            let http = reqwest::Client::new();
            let mut scopes = HashMap::new();
            scopes.insert(
                Audience::Endpoint,
                vec!["https://api.securitycenter.microsoft.com/Machine.Read".to_string()],
            );
            let consent = HashMap::new();

            let tm = TokenManager::for_test_user(
                http,
                "alice@contoso.com",
                "tenant-1",
                scopes,
                consent,
                Secret::new("RT-1"),
            );

            let res = tm.get_token(Audience::Endpoint).await.unwrap_err();
            let json = parse_tool_error(&res);
            assert_eq!(json["code"], "reauthentication_required");
            assert_eq!(json["reason"], expected_reason);
            assert_eq!(hits.load(Ordering::SeqCst), 1);

            // Second call: fails fast with NO network hit
            let res2 = tm.get_token(Audience::Endpoint).await.unwrap_err();
            let json2 = parse_tool_error(&res2);
            assert_eq!(json2["code"], "reauthentication_required");
            assert_eq!(json2["reason"], expected_reason);
            assert_eq!(
                hits.load(Ordering::SeqCst),
                1,
                "network must not be hit after reauth is set"
            );
            unsafe {
                std::env::remove_var(crate::constants::ENV_AUTHORITY_BASE_URL);
            }
        }
    }

    #[tokio::test]
    async fn test_consent_missing_on_65001() {
        let _env_guard = crate::auth::signin::tests::TEST_ENV_LOCK.lock().await;
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();

        let app = Router::new().route(
            "/{tenant}/oauth2/v2.0/token",
            post(move || {
                let hits = hits_clone.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "AADSTS65001: The user or administrator has not consented to use the application with ID..."
                        })),
                    )
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_url = format!("http://{addr}");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        unsafe {
            std::env::set_var(crate::constants::ENV_AUTHORITY_BASE_URL, &server_url);
        }

        let http = reqwest::Client::new();
        let mut scopes = HashMap::new();
        scopes.insert(
            Audience::Graph,
            vec!["https://graph.microsoft.com/ThreatHunting.Read.All".to_string()],
        );
        let consent = HashMap::new();

        let tm = TokenManager::for_test_user(
            http,
            "alice@contoso.com",
            "tenant-1",
            scopes,
            consent,
            Secret::new("RT-1"),
        );

        let res = tm.get_token(Audience::Graph).await.unwrap_err();
        let json = parse_tool_error(&res);
        assert_eq!(json["code"], "consent_missing");
        assert_eq!(json["audience"], "graph");
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // Reauth must NOT be set on 65001
        if let Credential::Delegated(session) = tm.credential.as_ref() {
            assert!(session.reauth.get().is_none());
        }

        // Subsequent call fails fast without network
        let res2 = tm.get_token(Audience::Graph).await.unwrap_err();
        let json2 = parse_tool_error(&res2);
        assert_eq!(json2["code"], "consent_missing");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        unsafe {
            std::env::remove_var(crate::constants::ENV_AUTHORITY_BASE_URL);
        }
    }
}
