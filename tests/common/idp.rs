//! Hermetic mock Entra ID authority fixture for delegated user authentication tests.
//!
//! Serves OAuth2 v2.0 endpoints:
//! - `GET /{tenant}/oauth2/v2.0/authorize`
//! - `POST /{tenant}/oauth2/v2.0/devicecode`
//! - `POST /{tenant}/oauth2/v2.0/token`
//!
//! Provides unsigned fixture ID tokens, sentinel credentials, scriptable audience responses,
//! request counting, and records request parameters for contract assertions.

#![allow(dead_code)]

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use microsoft_defender_mcp_server::auth::Audience;
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

pub const SENTINEL_CODE: &str = "SENTINEL-CODE-0001";
pub const SENTINEL_DC: &str = "SENTINEL-DC-0001";
pub const SENTINEL_UC: &str = "WDVJ-GHJK";
pub const SENTINEL_RT_INIT: &str = "SENTINEL-RT-0001";
pub const SENTINEL_AT_ID: &str = "SENTINEL-AT-ID-0001";
pub const SENTINEL_AT_ENDPOINT: &str = "SENTINEL-AT-ENDPOINT-0001";
pub const SENTINEL_AT_GRAPH: &str = "SENTINEL-AT-GRAPH-0001";
pub const SENTINEL_AT_APP: &str = "SENTINEL-AT-APP-0001";

/// Generate an unsigned fixture ID token JWT (`header.payload.sig`) with base64url claims.
pub fn make_id_token(preferred_username: &str, tid: &str, oid: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload_val = json!({
        "preferred_username": preferred_username,
        "tid": tid,
        "oid": oid,
    });
    let payload = URL_SAFE_NO_PAD.encode(payload_val.to_string());
    format!("{header}.{payload}.sig")
}

/// Recorded parameters from a `GET /{tenant}/oauth2/v2.0/authorize` request.
#[derive(Debug, Clone)]
pub struct RecordedAuthorize {
    pub client_id: Option<String>,
    pub response_type: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_mode: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub raw_query: String,
}

/// Recorded parameters from a `POST /{tenant}/oauth2/v2.0/devicecode` request.
#[derive(Debug, Clone)]
pub struct RecordedDeviceCode {
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub form: HashMap<String, String>,
}

/// Recorded parameters from a `POST /{tenant}/oauth2/v2.0/token` request.
#[derive(Debug, Clone)]
pub struct RecordedTokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub device_code: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub form: HashMap<String, String>,
}

/// Scripted response for per-audience refresh token grants.
#[derive(Debug, Clone)]
pub enum AudienceResponse {
    Success {
        scopes: Vec<String>,
        expires_in: u64,
    },
    Aadsts(u32),
    InteractionRequired,
    CustomError {
        error: String,
        aadsts: Option<u32>,
    },
}

/// Step for scripted device-code polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCodeStep {
    Pending,
    SlowDown,
    Success,
    ExpiredToken,
    AuthorizationDeclined,
    BadVerificationCode,
}

#[derive(Debug)]
struct MockIdpInner {
    preferred_username: String,
    tenant_id: String,
    object_id: String,

    mismatched_state: bool,
    authorize_error: Option<String>,

    device_code_sequence: VecDeque<DeviceCodeStep>,
    device_code_interval: u64,
    device_code_message: String,

    endpoint_responses: VecDeque<AudienceResponse>,
    graph_responses: VecDeque<AudienceResponse>,

    rt_seq: usize,
    at_seq: usize,

    grant_counts: HashMap<String, usize>,
    authorize_count: usize,
    device_code_count: usize,

    recorded_authorizes: Vec<RecordedAuthorize>,
    recorded_device_codes: Vec<RecordedDeviceCode>,
    recorded_tokens: Vec<RecordedTokenRequest>,
}

impl Default for MockIdpInner {
    fn default() -> Self {
        Self {
            preferred_username: "alice@contoso.com".to_string(),
            tenant_id: "00000000-0000-0000-0000-000000000000".to_string(),
            object_id: "22222222-2222-2222-2222-222222222222".to_string(),
            mismatched_state: false,
            authorize_error: None,
            device_code_sequence: VecDeque::new(),
            device_code_interval: 0,
            device_code_message: format!(
                "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code {SENTINEL_UC} to authenticate."
            ),
            endpoint_responses: VecDeque::new(),
            graph_responses: VecDeque::new(),
            rt_seq: 0,
            at_seq: 0,
            grant_counts: HashMap::new(),
            authorize_count: 0,
            device_code_count: 0,
            recorded_authorizes: Vec::new(),
            recorded_device_codes: Vec::new(),
            recorded_tokens: Vec::new(),
        }
    }
}

/// Mock Entra ID authority fixture running on a loopback Axum listener.
pub struct MockIdp {
    pub base_url: String,
    inner: Arc<Mutex<MockIdpInner>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MockIdp {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl MockIdp {
    /// Command string for `DEFENDER_TEST_BROWSER_CMD` that follows the redirect headlessly.
    pub fn browser_cmd() -> &'static str {
        "curl -s -L -o /dev/null"
    }

    /// Command string for `DEFENDER_TEST_BROWSER_CMD` that substitutes a mismatched state parameter.
    pub fn browser_cmd_mismatched_state() -> &'static str {
        "python3 -c \"import sys, urllib.request, urllib.parse\nclass NoRedirect(urllib.request.HTTPRedirectHandler):\n    def redirect_request(self, req, fp, code, msg, hdrs, newurl):\n        return None\nopener = urllib.request.build_opener(NoRedirect)\ntry:\n    r = opener.open(sys.argv[1])\n    loc = r.headers.get('Location')\nexcept urllib.error.HTTPError as e:\n    loc = e.headers.get('Location')\nif loc:\n    parsed = urllib.parse.urlparse(loc)\n    qs = urllib.parse.parse_qs(parsed.query)\n    qs['state'] = ['mismatched-state']\n    new_query = urllib.parse.urlencode(qs, doseq=True)\n    new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))\n    try:\n        urllib.request.urlopen(new_url)\n    except Exception:\n        pass\n\""
    }

    /// Spawn a new mock Entra ID authority on an ephemeral loopback port.
    pub async fn start() -> Self {
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback port for mock idp");
        let base_url = format!("http://{}", std_listener.local_addr().expect("local addr"));
        std_listener.set_nonblocking(true).expect("set nonblocking");

        let inner = Arc::new(Mutex::new(MockIdpInner::default()));
        let inner_state = Arc::clone(&inner);

        let app = Router::new()
            .route("/{tenant}/oauth2/v2.0/authorize", get(handle_authorize))
            .route("/{tenant}/oauth2/v2.0/devicecode", post(handle_devicecode))
            .route("/{tenant}/oauth2/v2.0/token", post(handle_token))
            .with_state(inner_state);

        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("mock idp tokio runtime");
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

        let shutdown_tx = rx.recv().expect("mock idp started");
        MockIdp {
            base_url,
            inner,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    /// Return the authority base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set user identity claims returned in ID tokens.
    pub fn set_user(&self, username: &str, tenant_id: &str, object_id: &str) {
        let mut guard = self.inner.lock().unwrap();
        guard.preferred_username = username.to_string();
        guard.tenant_id = tenant_id.to_string();
        guard.object_id = object_id.to_string();
    }

    /// Configure whether the authorize endpoint returns a mismatched state parameter.
    pub fn set_mismatched_state(&self, mismatched: bool) {
        self.inner.lock().unwrap().mismatched_state = mismatched;
    }

    /// Configure an error returned by the authorize endpoint.
    pub fn set_authorize_error(&self, error: Option<String>) {
        self.inner.lock().unwrap().authorize_error = error;
    }

    /// Queue a scripted response for a specific audience refresh token request.
    pub fn queue_audience_response(&self, audience: Audience, response: AudienceResponse) {
        let mut guard = self.inner.lock().unwrap();
        match audience {
            Audience::Endpoint => guard.endpoint_responses.push_back(response),
            Audience::Graph => guard.graph_responses.push_back(response),
        }
    }

    /// Set an immediate single response for an audience refresh request.
    pub fn set_audience_response(&self, audience: Audience, response: AudienceResponse) {
        let mut guard = self.inner.lock().unwrap();
        match audience {
            Audience::Endpoint => {
                guard.endpoint_responses.clear();
                guard.endpoint_responses.push_back(response);
            }
            Audience::Graph => {
                guard.graph_responses.clear();
                guard.graph_responses.push_back(response);
            }
        }
    }

    /// Set sequence of responses for device code token polling.
    pub fn set_device_code_sequence(&self, steps: Vec<DeviceCodeStep>) {
        let mut guard = self.inner.lock().unwrap();
        guard.device_code_sequence = steps.into();
    }

    /// Set device code polling interval returned in the device code endpoint response.
    pub fn set_device_code_interval(&self, interval: u64) {
        self.inner.lock().unwrap().device_code_interval = interval;
    }

    /// Set message returned in the device code endpoint response.
    pub fn set_device_code_message(&self, message: &str) {
        self.inner.lock().unwrap().device_code_message = message.to_string();
    }

    /// Return total hits to `/{tenant}/oauth2/v2.0/authorize`.
    pub fn authorize_count(&self) -> usize {
        self.inner.lock().unwrap().authorize_count
    }

    /// Return total hits to `/{tenant}/oauth2/v2.0/devicecode`.
    pub fn device_code_count(&self) -> usize {
        self.inner.lock().unwrap().device_code_count
    }

    /// Return total token requests for a specific grant type.
    pub fn grant_count(&self, grant_type: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .grant_counts
            .get(grant_type)
            .copied()
            .unwrap_or(0)
    }

    /// Return total token endpoint requests across all grant types.
    pub fn total_token_requests(&self) -> usize {
        self.inner.lock().unwrap().grant_counts.values().sum()
    }

    /// Cloned list of all recorded authorize requests.
    pub fn recorded_authorizes(&self) -> Vec<RecordedAuthorize> {
        self.inner.lock().unwrap().recorded_authorizes.clone()
    }

    /// Cloned list of all recorded device code requests.
    pub fn recorded_device_codes(&self) -> Vec<RecordedDeviceCode> {
        self.inner.lock().unwrap().recorded_device_codes.clone()
    }

    /// Cloned list of all recorded token requests.
    pub fn recorded_tokens(&self) -> Vec<RecordedTokenRequest> {
        self.inner.lock().unwrap().recorded_tokens.clone()
    }

    /// Most recent recorded authorize request.
    pub fn last_authorize(&self) -> Option<RecordedAuthorize> {
        self.inner
            .lock()
            .unwrap()
            .recorded_authorizes
            .last()
            .cloned()
    }

    /// Most recent recorded token request.
    pub fn last_token(&self) -> Option<RecordedTokenRequest> {
        self.inner.lock().unwrap().recorded_tokens.last().cloned()
    }

    /// All recorded token requests for a specific grant type.
    pub fn tokens_for_grant(&self, grant_type: &str) -> Vec<RecordedTokenRequest> {
        self.inner
            .lock()
            .unwrap()
            .recorded_tokens
            .iter()
            .filter(|t| t.grant_type == grant_type)
            .cloned()
            .collect()
    }

    /// Reset counts and recorded history.
    pub fn reset_history(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.grant_counts.clear();
        guard.authorize_count = 0;
        guard.device_code_count = 0;
        guard.recorded_authorizes.clear();
        guard.recorded_device_codes.clear();
        guard.recorded_tokens.clear();
    }
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    client_id: Option<String>,
    response_type: Option<String>,
    redirect_uri: Option<String>,
    response_mode: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    prompt: Option<String>,
}

async fn handle_authorize(
    State(state): State<Arc<Mutex<MockIdpInner>>>,
    Query(params): Query<AuthorizeQuery>,
    req: axum::extract::Request,
) -> Response {
    let mut inner = state.lock().unwrap();
    inner.authorize_count += 1;
    let raw_query = req.uri().query().unwrap_or("").to_string();
    inner.recorded_authorizes.push(RecordedAuthorize {
        client_id: params.client_id.clone(),
        response_type: params.response_type.clone(),
        redirect_uri: params.redirect_uri.clone(),
        response_mode: params.response_mode.clone(),
        scope: params.scope.clone(),
        state: params.state.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        prompt: params.prompt.clone(),
        raw_query,
    });

    let redirect_base = params
        .redirect_uri
        .unwrap_or_else(|| "http://localhost".to_string());

    if let Some(err) = &inner.authorize_error {
        let url = format!("{redirect_base}?error={err}");
        return Redirect::to(&url).into_response();
    }

    let code = SENTINEL_CODE;
    let state = if inner.mismatched_state {
        "mismatched-state-sentinel".to_string()
    } else {
        params.state.unwrap_or_else(|| "default-state".to_string())
    };

    let url = format!("{redirect_base}?code={code}&state={state}");
    Redirect::to(&url).into_response()
}

async fn handle_devicecode(
    State(state): State<Arc<Mutex<MockIdpInner>>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut inner = state.lock().unwrap();
    inner.device_code_count += 1;
    inner.recorded_device_codes.push(RecordedDeviceCode {
        client_id: form.get("client_id").cloned(),
        scope: form.get("scope").cloned(),
        form: form.clone(),
    });

    let interval = inner.device_code_interval;
    let msg = inner.device_code_message.clone();

    Json(json!({
        "device_code": SENTINEL_DC,
        "user_code": SENTINEL_UC,
        "verification_uri": "https://microsoft.com/devicelogin",
        "expires_in": 900,
        "interval": interval,
        "message": msg,
    }))
    .into_response()
}

async fn handle_token(
    State(state): State<Arc<Mutex<MockIdpInner>>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut inner = state.lock().unwrap();
    let grant_type = form.get("grant_type").cloned().unwrap_or_default();
    *inner.grant_counts.entry(grant_type.clone()).or_insert(0) += 1;

    inner.recorded_tokens.push(RecordedTokenRequest {
        grant_type: grant_type.clone(),
        client_id: form.get("client_id").cloned(),
        client_secret: form.get("client_secret").cloned(),
        code: form.get("code").cloned(),
        redirect_uri: form.get("redirect_uri").cloned(),
        code_verifier: form.get("code_verifier").cloned(),
        device_code: form.get("device_code").cloned(),
        refresh_token: form.get("refresh_token").cloned(),
        scope: form.get("scope").cloned(),
        form: form.clone(),
    });

    match grant_type.as_str() {
        "authorization_code" => {
            let id_token = make_id_token(
                &inner.preferred_username,
                &inner.tenant_id,
                &inner.object_id,
            );
            inner.rt_seq += 1;
            let rt = format!("SENTINEL-RT-{:04}", inner.rt_seq);
            inner.at_seq += 1;
            let at = format!("SENTINEL-AT-ID-{:04}", inner.at_seq);
            Json(json!({
                "token_type": "Bearer",
                "access_token": at,
                "refresh_token": rt,
                "id_token": id_token,
                "expires_in": 3600,
                "scope": "openid profile offline_access"
            }))
            .into_response()
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let step = inner
                .device_code_sequence
                .pop_front()
                .unwrap_or(DeviceCodeStep::Success);
            match step {
                DeviceCodeStep::Pending => {
                    (StatusCode::BAD_REQUEST, Json(json!({"error": "authorization_pending"})))
                        .into_response()
                }
                DeviceCodeStep::SlowDown => {
                    (StatusCode::BAD_REQUEST, Json(json!({"error": "slow_down"}))).into_response()
                }
                DeviceCodeStep::Success => {
                    let id_token =
                        make_id_token(&inner.preferred_username, &inner.tenant_id, &inner.object_id);
                    inner.rt_seq += 1;
                    let rt = format!("SENTINEL-RT-{:04}", inner.rt_seq);
                    inner.at_seq += 1;
                    let at = format!("SENTINEL-AT-ID-{:04}", inner.at_seq);
                    Json(json!({
                        "token_type": "Bearer",
                        "access_token": at,
                        "refresh_token": rt,
                        "id_token": id_token,
                        "expires_in": 3600,
                        "scope": "openid profile offline_access"
                    }))
                    .into_response()
                }
                DeviceCodeStep::ExpiredToken => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "expired_token",
                        "error_description": "AADSTS70020: The provided value for the 'device_code' parameter has expired."
                    })),
                )
                    .into_response(),
                DeviceCodeStep::AuthorizationDeclined => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "authorization_declined"})),
                )
                    .into_response(),
                DeviceCodeStep::BadVerificationCode => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "bad_verification_code"})),
                )
                    .into_response(),
            }
        }
        "refresh_token" => {
            let scope_str = form.get("scope").cloned().unwrap_or_default();
            let is_graph = scope_str.contains("graph.microsoft.com")
                || scope_str.contains("SecurityAlert")
                || scope_str.contains("ThreatHunting");

            let resp_rule = if is_graph {
                inner.graph_responses.pop_front()
            } else {
                inner.endpoint_responses.pop_front()
            };

            let rule = resp_rule.unwrap_or(AudienceResponse::Success {
                scopes: scope_str.split_whitespace().map(String::from).collect(),
                expires_in: 3600,
            });

            match rule {
                AudienceResponse::Success { scopes, expires_in } => {
                    inner.rt_seq += 1;
                    let rt = format!("SENTINEL-RT-{:04}", inner.rt_seq);
                    inner.at_seq += 1;
                    let aud_label = if is_graph { "GRAPH" } else { "ENDPOINT" };
                    let at = format!("SENTINEL-AT-{}-{:04}", aud_label, inner.at_seq);
                    Json(json!({
                        "token_type": "Bearer",
                        "access_token": at,
                        "refresh_token": rt,
                        "expires_in": expires_in,
                        "scope": scopes.join(" ")
                    }))
                    .into_response()
                }
                AudienceResponse::Aadsts(code) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_grant",
                        "error_description": format!("AADSTS{code}: Authentication error")
                    })),
                )
                    .into_response(),
                AudienceResponse::InteractionRequired => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "interaction_required",
                        "error_description": "AADSTS50058: Interaction required"
                    })),
                )
                    .into_response(),
                AudienceResponse::CustomError { error, aadsts } => {
                    let mut desc = format!("Error {error}");
                    if let Some(c) = aadsts {
                        desc = format!("AADSTS{c}: {error}");
                    }
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": error,
                            "error_description": desc
                        })),
                    )
                        .into_response()
                }
            }
        }
        "client_credentials" => Json(json!({
            "token_type": "Bearer",
            "access_token": SENTINEL_AT_APP,
            "expires_in": 3600
        }))
        .into_response(),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unsupported_grant_type"})),
        )
            .into_response(),
    }
}
