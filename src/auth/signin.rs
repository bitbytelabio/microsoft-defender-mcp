//! Interactive public-client sign-in flows: authorization code with PKCE and device code.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use super::session::{IdTokenClaims, IdTokenError, Secret};
pub use crate::cli::SignInFlow;
/// Token endpoint error response parsed strictly into `error` and optional `aadsts` code.
///
/// Discards `error_description` completely to prevent secret or PII leakage into error logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEndpointError {
    /// OAuth2 error identifier (e.g. `invalid_grant`, `authorization_pending`).
    pub error: String,
    /// Extracted numeric AADSTS error code (e.g. 700082, 65001), if present.
    pub aadsts: Option<u32>,
}

impl fmt::Display for TokenEndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(code) = self.aadsts {
            write!(f, " (AADSTS{code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for TokenEndpointError {}

/// Parse token-endpoint error body into [`TokenEndpointError`].
pub fn parse_token_error(body: &str) -> TokenEndpointError {
    #[derive(serde::Deserialize)]
    struct Raw {
        error: Option<String>,
        error_description: Option<String>,
        error_codes: Option<Vec<u32>>,
    }

    if let Ok(raw) = serde_json::from_str::<Raw>(body) {
        let error = raw.error.unwrap_or_else(|| "unknown_error".to_string());
        let aadsts = if let Some(codes) = raw.error_codes {
            codes.first().copied()
        } else if let Some(desc) = raw.error_description {
            extract_aadsts_code(&desc)
        } else {
            None
        };
        TokenEndpointError { error, aadsts }
    } else {
        TokenEndpointError {
            error: "unparseable_error_response".to_string(),
            aadsts: None,
        }
    }
}

fn extract_aadsts_code(desc: &str) -> Option<u32> {
    if let Some(pos) = desc.find("AADSTS") {
        let remainder = &desc[pos + 6..];
        let digits: String = remainder.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u32>().ok()
    } else {
        None
    }
}

/// Errors occurring during sign-in flows.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    /// Sign-in aborted by user (e.g. Ctrl-C).
    #[error("cancelled by user")]
    Cancelled,
    /// Timed out waiting for browser redirect.
    #[error("timed out waiting for sign-in redirect")]
    Timeout,
    /// Device code or token expired.
    #[error("expired token")]
    ExpiredToken,
    /// User explicitly declined authorization on the device-code prompt.
    #[error("authorization declined")]
    AuthorizationDeclined,
    /// Bad verification code entered.
    #[error("bad verification code")]
    BadVerificationCode,
    /// OAuth2 state parameter mismatch on loopback redirect.
    #[error("state mismatch")]
    StateMismatch,
    /// Invalid scope error from authorization server.
    #[error("invalid scope")]
    InvalidScope,
    /// Missing ID token in token response.
    #[error("missing id_token in token response")]
    MissingIdToken,
    /// Missing refresh token in token response.
    #[error("missing refresh_token in token response")]
    MissingRefreshToken,
    /// Consent is missing for both audiences.
    #[error("consent missing for both audiences")]
    ConsentMissingBothAudiences,
    /// Failed to spawn the system browser launcher.
    #[error("browser launcher failed: {0}")]
    BrowserLaunchFailed(String),
    /// Error from the token endpoint.
    #[error("token endpoint error: {0}")]
    TokenEndpoint(#[from] TokenEndpointError),
    /// ID token decoding error.
    #[error("id token claim error: {0}")]
    IdToken(#[from] IdTokenError),
    /// HTTP network error.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    /// General internal failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl SignInError {
    /// Human-readable reason for `Sign-in not completed: <reason>. The server did not start.`
    pub fn failure_reason(&self) -> String {
        match self {
            Self::Cancelled => "cancelled by user".into(),
            Self::Timeout => "timed out waiting for browser redirect".into(),
            Self::ExpiredToken => "expired token".into(),
            Self::AuthorizationDeclined => "authorization declined".into(),
            Self::BadVerificationCode => "bad verification code".into(),
            Self::StateMismatch => "state mismatch".into(),
            Self::InvalidScope => "invalid scope".into(),
            Self::TokenEndpoint(err) => err.to_string(),
            _ => self.to_string(),
        }
    }
}

/// PKCE code verifier and challenge pair.
pub struct Pkce {
    /// 32-byte secret verifier string.
    pub verifier: Secret,
    /// S256 challenge string.
    pub challenge: String,
    /// Challenge method (always `"S256"`).
    pub method: &'static str,
}

/// Compute S256 code challenge from an ASCII verifier per RFC 7636.
pub fn compute_s256_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a 32-byte cryptographically secure PKCE verifier and S256 challenge.
pub fn generate_pkce() -> Result<Pkce, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let verifier_str = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = compute_s256_challenge(&verifier_str);
    Ok(Pkce {
        verifier: Secret::new(verifier_str),
        challenge,
        method: "S256",
    })
}

/// Generate a 32-byte cryptographically secure random state parameter.
pub fn generate_state() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns the configured Entra ID authority base URL, trimmed of trailing slashes.
pub fn authority_base_url() -> String {
    std::env::var(crate::constants::ENV_AUTHORITY_BASE_URL)
        .unwrap_or_else(|_| crate::constants::AUTHORITY_BASE_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Returns the OAuth2 authorize endpoint for a given tenant.
pub fn authorize_endpoint(tenant: &str) -> String {
    format!("{}/{}/oauth2/v2.0/authorize", authority_base_url(), tenant)
}

/// Returns the OAuth2 device authorization endpoint for a given tenant.
pub fn devicecode_endpoint(tenant: &str) -> String {
    format!("{}/{}/oauth2/v2.0/devicecode", authority_base_url(), tenant)
}

/// Returns the OAuth2 token endpoint for a given tenant.
pub fn token_endpoint(tenant: &str) -> String {
    format!("{}/{}/oauth2/v2.0/token", authority_base_url(), tenant)
}

/// Build the full `/authorize` URL for interactive browser sign-in.
pub fn build_authorize_url(
    tenant: &str,
    client_id: &str,
    redirect_uri: &str,
    requested_scopes: &[String],
    state: &str,
    code_challenge: &str,
) -> Result<url::Url, url::ParseError> {
    let mut scopes = vec![
        "openid".to_string(),
        "profile".to_string(),
        "offline_access".to_string(),
    ];
    for s in requested_scopes {
        if !scopes.contains(s) {
            scopes.push(s.clone());
        }
    }
    let scopes_str = scopes.join(" ");

    let mut url = url::Url::parse(&authorize_endpoint(tenant))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_mode", "query")
        .append_pair("scope", &scopes_str)
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "select_account");
    Ok(url)
}

#[derive(serde::Deserialize)]
struct RedirectQueryParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}
/// Handle for the active loopback redirect listener.
pub struct LoopbackListener {
    /// The port bound on 127.0.0.1.
    pub port: u16,
    /// The redirect URI registered for Entra ID (`http://localhost:{port}`).
    pub redirect_uri: String,
    rx: tokio::sync::oneshot::Receiver<Result<String, SignInError>>,
    shutdown_tx: Arc<tokio::sync::Notify>,
    server_handle: tokio::task::JoinHandle<()>,
}

impl LoopbackListener {
    /// Bind a single-use loopback listener on 127.0.0.1:0.
    pub async fn bind(expected_state: String) -> Result<Self, std::io::Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!("http://localhost:{port}");

        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx_holder = Arc::new(std::sync::Mutex::new(Some(tx)));
        let shutdown_notify = Arc::new(tokio::sync::Notify::new());
        let shutdown_notify_server = Arc::clone(&shutdown_notify);

        let handler = {
            let tx_holder = Arc::clone(&tx_holder);
            let expected_state = expected_state.clone();
            let notify = Arc::clone(&shutdown_notify);
            move |axum::extract::Query(params): axum::extract::Query<RedirectQueryParams>| {
                let tx_holder = Arc::clone(&tx_holder);
                let expected_state = expected_state.clone();
                let notify = Arc::clone(&notify);
                async move {
                    let is_state_valid = params.state.as_deref() == Some(&expected_state);

                    let result = if !is_state_valid {
                        Err(SignInError::StateMismatch)
                    } else if let Some(err_name) = params.error {
                        if err_name == "invalid_scope" {
                            Err(SignInError::InvalidScope)
                        } else {
                            Err(SignInError::TokenEndpoint(TokenEndpointError {
                                error: err_name,
                                aadsts: None,
                            }))
                        }
                    } else if let Some(code) = params.code {
                        Ok(code)
                    } else {
                        Err(SignInError::Internal("missing code or error param".into()))
                    };

                    let status = if !is_state_valid {
                        axum::http::StatusCode::BAD_REQUEST
                    } else {
                        axum::http::StatusCode::OK
                    };

                    let html = if !is_state_valid {
                        "<!DOCTYPE html><html><head><title>Sign-in failed</title></head><body><h2>Authentication failed</h2><p>State parameter mismatch. You can close this window.</p></body></html>"
                    } else {
                        "<!DOCTYPE html><html><head><title>Sign-in complete</title></head><body style=\"font-family: sans-serif; text-align: center; padding: 50px;\"><h2>Authentication complete</h2><p>You can close this window and return to the terminal.</p></body></html>"
                    };

                    if let Ok(mut guard) = tx_holder.lock() {
                        if let Some(sender) = guard.take() {
                            let _ = sender.send(result);
                        }
                    }
                    notify.notify_one();

                    (status, axum::response::Html(html))
                }
            }
        };

        let app = axum::Router::new()
            .route("/", axum::routing::get(handler.clone()))
            .fallback(handler);

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown_notify_server.notified().await;
                })
                .await;
        });

        Ok(Self {
            port,
            redirect_uri,
            rx,
            shutdown_tx: shutdown_notify,
            server_handle,
        })
    }

    /// Wait for the redirect response with timeout and cancellation support.
    pub async fn wait_for_code(self, timeout: Duration) -> Result<String, SignInError> {
        let shutdown = self.shutdown_tx;
        let handle = self.server_handle;
        let rx = self.rx;

        let result = tokio::select! {
            res = rx => {
                match res {
                    Ok(inner) => inner,
                    Err(_) => Err(SignInError::Cancelled),
                }
            }
            _ = tokio::time::sleep(timeout) => Err(SignInError::Timeout),
            _ = tokio::signal::ctrl_c() => Err(SignInError::Cancelled),
        };

        shutdown.notify_one();
        handle.abort();
        result
    }
}

/// Check if the system is running in a headless Linux/BSD environment without a display.
pub fn is_headless() -> bool {
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        false
    }
}

/// Custom launcher closure type for tests.
pub type BrowserLauncher = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Spawn system browser or test launcher command.
pub fn launch_browser(url: &str) -> Result<(), String> {
    #[cfg(debug_assertions)]
    if let Ok(cmd) = std::env::var("DEFENDER_TEST_BROWSER_CMD") {
        if !cmd.trim().is_empty() {
            return spawn_test_browser_cmd(&cmd, url);
        }
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to launch 'open': {e}"))
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to launch 'xdg-open': {e}"))
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to launch rundll32: {e}"))
    }
}

#[cfg(debug_assertions)]
fn spawn_test_browser_cmd(cmd: &str, url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", &format!("{cmd} \"{url}\"")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to spawn test browser: {e}"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("sh")
            .args(["-c", &format!("{cmd} \"{url}\"")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to spawn test browser: {e}"))
    }
}
#[derive(serde::Deserialize)]
struct RawTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

/// Redeem authorization code for tokens at `/token` endpoint without client_secret.
pub async fn redeem_auth_code(
    http_client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &Secret,
) -> Result<(IdTokenClaims, Secret), SignInError> {
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier.expose()),
        ("scope", "openid profile offline_access"),
    ];

    let resp = http_client
        .post(&token_endpoint(tenant))
        .form(&params)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        let err = parse_token_error(&body);
        return Err(SignInError::TokenEndpoint(err));
    }

    let token_resp: RawTokenResponse = serde_json::from_str(&body)
        .map_err(|e| SignInError::Internal(format!("failed to parse token response: {e}")))?;

    let id_token_str = token_resp.id_token.ok_or(SignInError::MissingIdToken)?;
    let claims = super::session::decode_id_token_claims(&id_token_str)?;

    let refresh_token_str = token_resp
        .refresh_token
        .ok_or(SignInError::MissingRefreshToken)?;
    let refresh_token = Secret::new(refresh_token_str);

    Ok((claims, refresh_token))
}

async fn run_browser_attempt(
    http_client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    requested_scopes: &[String],
    launcher: Option<&BrowserLauncher>,
) -> Result<(IdTokenClaims, Secret), SignInError> {
    let pkce = generate_pkce().map_err(|e| SignInError::Internal(e.to_string()))?;
    let state = generate_state().map_err(|e| SignInError::Internal(e.to_string()))?;

    let listener = LoopbackListener::bind(state.clone())
        .await
        .map_err(|e| SignInError::Internal(format!("failed to bind loopback listener: {e}")))?;

    let redirect_uri = listener.redirect_uri.clone();
    let authorize_url = build_authorize_url(
        tenant,
        client_id,
        &redirect_uri,
        requested_scopes,
        &state,
        &pkce.challenge,
    )
    .map_err(|e| SignInError::Internal(format!("failed to build authorize url: {e}")))?;

    let url_str = authorize_url.to_string();
    eprintln!(
        "Sign in to Microsoft Defender MCP: a browser window was opened. If it did not open, visit:\n  {url_str}"
    );

    if let Some(hook) = launcher {
        hook(&url_str).map_err(SignInError::BrowserLaunchFailed)?;
    } else {
        launch_browser(&url_str).map_err(SignInError::BrowserLaunchFailed)?;
    }

    let timeout_secs = crate::constants::BROWSER_SIGN_IN_TIMEOUT_SECS;
    let code = listener.wait_for_code(Duration::from_secs(timeout_secs)).await?;

    redeem_auth_code(
        http_client,
        tenant,
        client_id,
        &code,
        &redirect_uri,
        &pkce.verifier,
    )
    .await
}

/// Execute interactive browser sign-in flow with custom test launcher hook and retry on invalid_scope.
pub async fn run_browser_flow_with_launcher(
    http_client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    requested_scopes: &[String],
    launcher: Option<BrowserLauncher>,
) -> Result<(IdTokenClaims, Secret), SignInError> {
    match run_browser_attempt(
        http_client,
        tenant,
        client_id,
        requested_scopes,
        launcher.as_ref(),
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(SignInError::InvalidScope) if !requested_scopes.is_empty() => {
            eprintln!("Scope invalid on authorize URL; retrying sign-in with standard OIDC scopes...");
            run_browser_attempt(http_client, tenant, client_id, &[], launcher.as_ref()).await
        }
        Err(e) => Err(e),
    }
}

/// Execute interactive browser sign-in flow using the default OS launcher.
pub async fn run_browser_flow(
    http_client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    requested_scopes: &[String],
) -> Result<(IdTokenClaims, Secret), SignInError> {
    run_browser_flow_with_launcher(http_client, tenant, client_id, requested_scopes, None).await
}

#[derive(serde::Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
    message: String,
}

/// Execute interactive device authorization grant flow.
pub async fn run_device_code_flow(
    http_client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
) -> Result<(IdTokenClaims, Secret), SignInError> {
    let params = [
        ("client_id", client_id),
        ("scope", "openid profile offline_access"),
    ];

    let resp = http_client
        .post(&devicecode_endpoint(tenant))
        .form(&params)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        let err = parse_token_error(&body);
        return Err(SignInError::TokenEndpoint(err));
    }

    let dc_resp: DeviceCodeResponse = serde_json::from_str(&body)
        .map_err(|e| SignInError::Internal(format!("failed to parse device code response: {e}")))?;

    // Print the IdP instruction message verbatim on stderr
    eprintln!("{}", dc_resp.message);

    let device_code = Secret::new(dc_resp.device_code);
    let mut interval = Duration::from_secs(dc_resp.interval.unwrap_or(5));
    let expires_in_secs = dc_resp.expires_in.unwrap_or(900);
    let expires_at = tokio::time::Instant::now() + Duration::from_secs(expires_in_secs);

    let slow_down_step = if cfg!(debug_assertions) {
        Duration::from_millis(50)
    } else {
        Duration::from_secs(5)
    };

    loop {
        if tokio::time::Instant::now() >= expires_at {
            return Err(SignInError::ExpiredToken);
        }

        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = tokio::signal::ctrl_c() => return Err(SignInError::Cancelled),
        }

        let poll_params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", client_id),
            ("device_code", device_code.expose()),
        ];

        let poll_resp = http_client
            .post(&token_endpoint(tenant))
            .form(&poll_params)
            .send()
            .await?;

        let poll_status = poll_resp.status();
        let poll_body = poll_resp.text().await?;

        if poll_status.is_success() {
            let token_resp: RawTokenResponse = serde_json::from_str(&poll_body)
                .map_err(|e| SignInError::Internal(format!("failed to parse token response: {e}")))?;

            let id_token_str = token_resp.id_token.ok_or(SignInError::MissingIdToken)?;
            let claims = super::session::decode_id_token_claims(&id_token_str)?;
            let refresh_token_str = token_resp
                .refresh_token
                .ok_or(SignInError::MissingRefreshToken)?;
            return Ok((claims, Secret::new(refresh_token_str)));
        }

        let err = parse_token_error(&poll_body);
        match err.error.as_str() {
            "authorization_pending" => continue,
            "slow_down" => {
                interval += slow_down_step;
                continue;
            }
            "authorization_declined" => return Err(SignInError::AuthorizationDeclined),
            "expired_token" => return Err(SignInError::ExpiredToken),
            "bad_verification_code" => return Err(SignInError::BadVerificationCode),
            _ => return Err(SignInError::TokenEndpoint(err)),
        }
    }
}

/// Result of a successful refresh-token grant.
pub struct RefreshTokenSuccess {
    /// Newly issued access token for the requested audience.
    pub access_token: Secret,
    /// Token lifetime in seconds.
    pub expires_in: u64,
    /// Scopes granted by the IdP response.
    pub scopes: Vec<String>,
    /// Rotated refresh token (if returned by the IdP).
    pub refresh_token: Option<Secret>,
}

/// Errors from refresh token grant attempts.
#[derive(Debug, thiserror::Error)]
pub enum RefreshTokenError {
    /// Token endpoint responded with an error payload.
    #[error("token endpoint error: {0}")]
    Endpoint(#[from] TokenEndpointError),
    /// Network failure.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    /// Unparseable or invalid response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl RefreshTokenError {
    /// Inspect the underlying token endpoint error, if any.
    pub fn as_endpoint_error(&self) -> Option<&TokenEndpointError> {
        match self {
            Self::Endpoint(err) => Some(err),
            _ => None,
        }
    }
}

/// Redeem a refresh token for audience-specific scopes via `grant_type=refresh_token`.
pub async fn refresh_token_grant(
    http_client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    refresh_token: &Secret,
    scopes: &[String],
) -> Result<RefreshTokenSuccess, RefreshTokenError> {
    let scope_str = scopes.join(" ");
    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token.expose()),
        ("scope", &scope_str),
    ];

    let resp = http_client
        .post(&token_endpoint(tenant))
        .form(&params)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        let err = parse_token_error(&body);
        return Err(RefreshTokenError::Endpoint(err));
    }

    let token_resp: RawTokenResponse = serde_json::from_str(&body)
        .map_err(|e| RefreshTokenError::InvalidResponse(format!("failed to parse token response: {e}")))?;

    let access_token_str = token_resp
        .access_token
        .ok_or_else(|| RefreshTokenError::InvalidResponse("missing access_token".into()))?;

    let expires_in = token_resp.expires_in.unwrap_or(3600);
    let granted_scopes = token_resp
        .scope
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    let new_refresh_token = token_resp.refresh_token.map(Secret::new);

    Ok(RefreshTokenSuccess {
        access_token: Secret::new(access_token_str),
        expires_in,
        scopes: granted_scopes,
        refresh_token: new_refresh_token,
    })
}

/// Perform interactive sign-in using the specified flow.
pub async fn interactive_sign_in(
    http_client: &reqwest::Client,
    tenant: &str,
    client_id: &str,
    flow: SignInFlow,
    requested_resource_scopes: &[String],
) -> Result<(IdTokenClaims, Secret), SignInError> {
    match flow {
        SignInFlow::Auto => {
            if is_headless() {
                run_device_code_flow(http_client, tenant, client_id).await
            } else {
                match run_browser_flow(http_client, tenant, client_id, requested_resource_scopes).await {
                    Ok(res) => Ok(res),
                    Err(SignInError::BrowserLaunchFailed(_)) => {
                        run_device_code_flow(http_client, tenant, client_id).await
                    }
                    Err(e) => Err(e),
                }
            }
        }
        SignInFlow::Browser => {
            run_browser_flow(http_client, tenant, client_id, requested_resource_scopes).await
        }
        SignInFlow::DeviceCode => {
            run_device_code_flow(http_client, tenant, client_id).await
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_rfc7636_appendix_b_pkce_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let calculated = compute_s256_challenge(verifier);
        assert_eq!(calculated, expected_challenge);
    }

    #[test]
    fn test_generate_pkce_and_state() {
        let pkce = generate_pkce().expect("generate pkce");
        assert_eq!(pkce.method, "S256");
        assert_eq!(pkce.verifier.expose().len(), 43);
        let challenge = compute_s256_challenge(pkce.verifier.expose());
        assert_eq!(pkce.challenge, challenge);

        let state = generate_state().expect("generate state");
        assert_eq!(state.len(), 43);
    }

    #[test]
    fn test_token_error_parsing() {
        // Format with error_codes array
        let json_with_codes = r#"{"error":"invalid_grant","error_codes":[700082],"error_description":"AADSTS700082: The refresh token has expired"}"#;
        let err1 = parse_token_error(json_with_codes);
        assert_eq!(err1.error, "invalid_grant");
        assert_eq!(err1.aadsts, Some(700082));

        // Format with AADSTS code in error_description prefix
        let json_with_desc = r#"{"error":"invalid_grant","error_description":"AADSTS65001: The user has not consented"}"#;
        let err2 = parse_token_error(json_with_desc);
        assert_eq!(err2.error, "invalid_grant");
        assert_eq!(err2.aadsts, Some(65001));

        // Format with AADSTS code inside text
        let json_inside = r#"{"error":"invalid_grant","error_description":"Error occurred: AADSTS50076 (MFA required)"}"#;
        let err3 = parse_token_error(json_inside);
        assert_eq!(err3.error, "invalid_grant");
        assert_eq!(err3.aadsts, Some(50076));

        // Format with no error codes and no AADSTS
        let json_no_code = r#"{"error":"interaction_required"}"#;
        let err4 = parse_token_error(json_no_code);
        assert_eq!(err4.error, "interaction_required");
        assert_eq!(err4.aadsts, None);

        // Failure reason formatting
        let sign_in_err = SignInError::TokenEndpoint(err1);
        assert_eq!(sign_in_err.failure_reason(), "invalid_grant (AADSTS700082)");
    }

    #[test]
    fn test_build_authorize_url() {
        let requested = vec!["https://api.securitycenter.microsoft.com/Machine.Read".into()];
        let url = build_authorize_url(
            "tenant-123",
            "client-abc",
            "http://localhost:54321",
            &requested,
            "state-xyz",
            "challenge-123",
        )
        .expect("build authorize url");

        assert!(url.to_string().contains("prompt=select_account"));
        assert!(url.to_string().contains("code_challenge_method=S256"));
        assert!(url.to_string().contains("state=state-xyz"));
        assert!(url.to_string().contains("code_challenge=challenge-123"));
        assert!(url.to_string().contains("client_id=client-abc"));
        assert!(url.to_string().contains("redirect_uri=http%3A%2F%2Flocalhost%3A54321"));
        let query = url.query().expect("query");
        assert!(query.contains("scope=openid+profile+offline_access+https%3A%2F%2Fapi.securitycenter.microsoft.com%2FMachine.Read"));
    }

    #[tokio::test]
    async fn test_loopback_listener_state_mismatch_rejected() {
        let expected_state = "correct-state-123".to_string();
        let listener = LoopbackListener::bind(expected_state).await.expect("bind listener");
        let port = listener.port;

        // Make an HTTP GET request with a mismatched state
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/?code=mock-code&state=wrong-state"))
            .send()
            .await
            .expect("send redirect");

        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

        let result = listener.wait_for_code(Duration::from_secs(5)).await;
        assert!(matches!(result, Err(SignInError::StateMismatch)));
    }

    #[tokio::test]
    async fn test_loopback_listener_success() {
        let expected_state = "state-999".to_string();
        let listener = LoopbackListener::bind(expected_state).await.expect("bind listener");
        let port = listener.port;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/?code=auth-code-123&state=state-999"))
            .send()
            .await
            .expect("send redirect");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        let code = listener.wait_for_code(Duration::from_secs(5)).await.expect("wait for code");
        assert_eq!(code, "auth-code-123");
    }

    pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn make_mock_id_token(account: &str, tid: &str) -> String {
        let payload_json = serde_json::json!({
            "preferred_username": account,
            "tid": tid,
            "oid": "mock-oid-123"
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.to_string());
        format!("eyJhbGciOiJub25lIn0.{}.sig", payload_b64)
    }

    async fn start_mock_server(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (base_url, handle)
    }

    #[tokio::test]
    async fn test_device_code_polling_success() {
        let _guard = TEST_ENV_LOCK.lock().unwrap();
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let jwt = make_mock_id_token("alice@contoso.com", "tenant-1");

        let app = axum::Router::new()
            .route(
                "/mock-tenant/oauth2/v2.0/devicecode",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({
                        "device_code": "SENTINEL-DC-1",
                        "user_code": "USER-123",
                        "verification_uri": "http://localhost/device",
                        "expires_in": 60,
                        "interval": 0,
                        "message": "Enter code USER-123"
                    }))
                }),
            )
            .route(
                "/mock-tenant/oauth2/v2.0/token",
                axum::routing::post({
                    let jwt = jwt.clone();
                    move || {
                        let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let jwt = jwt.clone();
                        async move {
                            match count {
                                0 => (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    axum::Json(serde_json::json!({"error": "authorization_pending"})),
                                ),
                                1 => (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    axum::Json(serde_json::json!({"error": "slow_down"})),
                                ),
                                _ => (
                                    axum::http::StatusCode::OK,
                                    axum::Json(serde_json::json!({
                                        "token_type": "Bearer",
                                        "access_token": "SENTINEL-AT-1",
                                        "refresh_token": "SENTINEL-RT-1",
                                        "id_token": jwt,
                                        "expires_in": 3600
                                    })),
                                ),
                            }
                        }
                    }
                }),
            );

        let (base_url, server_handle) = start_mock_server(app).await;
        // SAFETY: Synchronized by TEST_ENV_LOCK across unit tests.
        unsafe {
            std::env::set_var(crate::constants::ENV_AUTHORITY_BASE_URL, &base_url);
        }

        let http_client = reqwest::Client::new();
        let (claims, refresh_token) = run_device_code_flow(&http_client, "mock-tenant", "client-1")
            .await
            .expect("device code flow success");

        assert_eq!(claims.preferred_username.as_deref(), Some("alice@contoso.com"));
        assert_eq!(refresh_token.expose(), "SENTINEL-RT-1");
        assert!(call_count.load(std::sync::atomic::Ordering::SeqCst) >= 3);

        // SAFETY: Cleaning up environment variable.
        unsafe {
            std::env::remove_var(crate::constants::ENV_AUTHORITY_BASE_URL);
        }
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_device_code_polling_expired() {
        let _guard = TEST_ENV_LOCK.lock().unwrap();
        let app = axum::Router::new()
            .route(
                "/mock-tenant/oauth2/v2.0/devicecode",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({
                        "device_code": "SENTINEL-DC-2",
                        "user_code": "USER-456",
                        "expires_in": 60,
                        "interval": 0,
                        "message": "Enter code USER-456"
                    }))
                }),
            )
            .route(
                "/mock-tenant/oauth2/v2.0/token",
                axum::routing::post(|| async {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "expired_token"})),
                    )
                }),
            );

        let (base_url, server_handle) = start_mock_server(app).await;
        // SAFETY: Synchronized by TEST_ENV_LOCK across unit tests.
        unsafe {
            std::env::set_var(crate::constants::ENV_AUTHORITY_BASE_URL, &base_url);
        }

        let http_client = reqwest::Client::new();
        let err = run_device_code_flow(&http_client, "mock-tenant", "client-1")
            .await
            .expect_err("should expire");

        assert!(matches!(err, SignInError::ExpiredToken));

        // SAFETY: Cleaning up environment variable.
        unsafe {
            std::env::remove_var(crate::constants::ENV_AUTHORITY_BASE_URL);
        }
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_browser_flow_end_to_end() {
        let _guard = TEST_ENV_LOCK.lock().unwrap();
        let app = axum::Router::new().route(
            "/mock-tenant/oauth2/v2.0/token",
            axum::routing::post(|body: String| async move {
                assert!(!body.contains("client_secret"));
                assert!(body.contains("grant_type=authorization_code"));
                assert!(body.contains("code=SENTINEL-CODE-99"));
                assert!(body.contains("code_verifier="));

                let jwt = make_mock_id_token("analyst@example.com", "tenant-1");
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "token_type": "Bearer",
                        "access_token": "SENTINEL-AT-2",
                        "refresh_token": "SENTINEL-RT-2",
                        "id_token": jwt,
                        "expires_in": 3600
                    })),
                )
            }),
        );

        let (base_url, server_handle) = start_mock_server(app).await;
        // SAFETY: Synchronized by TEST_ENV_LOCK across unit tests.
        unsafe {
            std::env::set_var(crate::constants::ENV_AUTHORITY_BASE_URL, &base_url);
        }

        let launcher: BrowserLauncher = Arc::new(|url_str: &str| {
            let parsed = url::Url::parse(url_str).map_err(|e| e.to_string())?;
            let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
            assert_eq!(pairs.get("code_challenge_method").map(|s| s.as_str()), Some("S256"));
            assert_eq!(pairs.get("prompt").map(|s| s.as_str()), Some("select_account"));

            let redirect_uri = pairs.get("redirect_uri").expect("redirect_uri").clone();
            let state = pairs.get("state").expect("state").clone();

            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .get(format!("{redirect_uri}?code=SENTINEL-CODE-99&state={state}"))
                    .send()
                    .await;
            });

            Ok(())
        });

        let http_client = reqwest::Client::new();
        let (claims, refresh_token) = run_browser_flow_with_launcher(
            &http_client,
            "mock-tenant",
            "client-1",
            &[],
            Some(launcher),
        )
        .await
        .expect("browser flow should succeed");

        assert_eq!(claims.preferred_username.as_deref(), Some("analyst@example.com"));
        assert_eq!(refresh_token.expose(), "SENTINEL-RT-2");

        // SAFETY: Cleaning up environment variable.
        unsafe {
            std::env::remove_var(crate::constants::ENV_AUTHORITY_BASE_URL);
        }
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_refresh_token_grant() {
        let _guard = TEST_ENV_LOCK.lock().unwrap();
        let app = axum::Router::new().route(
            "/mock-tenant/oauth2/v2.0/token",
            axum::routing::post(|body: String| async move {
                assert!(body.contains("grant_type=refresh_token"));
                assert!(body.contains("refresh_token=SENTINEL-RT-INIT"));
                assert!(body.contains("scope=Machine.Read"));

                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "token_type": "Bearer",
                        "access_token": "SENTINEL-AT-ROTATED",
                        "refresh_token": "SENTINEL-RT-ROTATED",
                        "expires_in": 3600,
                        "scope": "Machine.Read"
                    })),
                )
            }),
        );

        let (base_url, server_handle) = start_mock_server(app).await;
        // SAFETY: Synchronized by TEST_ENV_LOCK across unit tests.
        unsafe {
            std::env::set_var(crate::constants::ENV_AUTHORITY_BASE_URL, &base_url);
        }

        let http_client = reqwest::Client::new();
        let initial_rt = Secret::new("SENTINEL-RT-INIT");
        let res = refresh_token_grant(
            &http_client,
            "mock-tenant",
            "client-1",
            &initial_rt,
            &["Machine.Read".into()],
        )
        .await
        .expect("refresh token grant success");

        assert_eq!(res.access_token.expose(), "SENTINEL-AT-ROTATED");
        assert_eq!(res.refresh_token.as_ref().map(|s| s.expose()), Some("SENTINEL-RT-ROTATED"));
        assert_eq!(res.scopes, vec!["Machine.Read"]);

        // SAFETY: Cleaning up environment variable.
        unsafe {
            std::env::remove_var(crate::constants::ENV_AUTHORITY_BASE_URL);
        }
        server_handle.abort();
    }
}
