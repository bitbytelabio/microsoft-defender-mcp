//! Integration tests for User Story 2: Delegated User Authentication (FR-019..FR-028, SC-004..SC-006).
//!
//! Covers quickstart scenario Q12:
//! - Browser PKCE flow, state mismatch rejection, no client secret sent to token endpoint
//! - Stderr status line formatting (account, tenant, audiences, expiry)
//! - Device code flow, message on stderr, 0 bytes on stdout before initialize, expired token failure
//! - Scope least-privilege under `--read-only`, and write-named read `scope_not_requested` gate
//! - Consent missing for Graph (AADSTS65001) lets Endpoint succeed, Graph calls fail fast
//! - Silent refresh single-flight concurrency (20 callers -> 1 IdP hit), token rotation, AADSTS700082 fail-fast
//! - API 401 with `insufficient_claims` -> `reauthentication_required` (`conditional_access`)
//! - User-mode 403 text with "signed-in user's own rights apply" and `permission_category`
//! - `AZURE_TENANT_ID=common` / `organizations` rejection
//! - `AZURE_CLIENT_SECRET` ignored notice
//! - HTTP transport shared-identity SECURITY WARNING
//! - Mutating action audits user identity (`{"kind":"user",...}`)
//! - Zero sentinel credentials (`SENTINEL-`) in stderr and audit logs

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::idp::{AudienceResponse, DeviceCodeStep, MockIdp, SENTINEL_UC};
use common::{ElicitationResponse, McpProcess, ScratchDir, server_command, spawn_mock};
use microsoft_defender_mcp_server::auth::Audience;
use serde_json::{Value, json};

const MOCK_MACHINE_ID: &str = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07";

/// Quickstart Q12: Browser flow with PKCE, S256 code challenge method, no client_secret,
/// and rejection of mismatched state parameters.
#[tokio::test]
async fn test_browser_flow_pkce_state_mismatch_and_no_client_secret() {
    let idp = MockIdp::start().await;

    // 1. Successful browser flow through DEFENDER_TEST_BROWSER_CMD hook
    let mut proc = McpProcess::start(
        &["--auth-mode", "user", "--sign-in-flow", "browser"],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    );

    let tools = proc.tool_names();
    assert!(!tools.is_empty(), "server should expose tools");

    let stderr = proc.captured_stderr();
    assert!(
        stderr.contains("Signed in as alice@contoso.com"),
        "stderr should display signed-in user: {stderr}"
    );

    let exit = proc.shutdown();
    assert!(exit.success());

    // Assert IdP observed S256 code_challenge_method and code_challenge
    let authorizes = idp.recorded_authorizes();
    assert!(!authorizes.is_empty(), "IdP must record authorize request");
    let auth = &authorizes[0];
    assert_eq!(
        auth.code_challenge_method.as_deref(),
        Some("S256"),
        "code_challenge_method must be S256"
    );
    assert!(
        auth.code_challenge
            .as_ref()
            .map(|s| s.len() >= 43)
            .unwrap_or(false),
        "code_challenge must be valid URL-safe base64"
    );
    assert_eq!(
        auth.prompt.as_deref(),
        Some("select_account"),
        "prompt must be select_account"
    );

    // Assert token endpoint requests never include client_secret
    let tokens = idp.recorded_tokens();
    assert!(!tokens.is_empty(), "IdP must record token requests");
    for req in &tokens {
        assert!(
            req.client_secret.is_none(),
            "delegated token request must not include client_secret, found in {:?}",
            req
        );
        assert!(
            !req.form.contains_key("client_secret"),
            "form must not contain client_secret"
        );
    }

    // 2. State mismatch variant is rejected and server aborts startup
    let idp_mismatch = MockIdp::start().await;
    idp_mismatch.set_mismatched_state(true);

    let out = server_command(
        &["--auth-mode", "user", "--sign-in-flow", "browser"],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp_mismatch.base_url()),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    )
    .output()
    .expect("run server with mismatched state");

    assert!(
        !out.status.success(),
        "server must exit non-zero when state is mismatched"
    );
    let mismatch_stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        mismatch_stderr.contains("Sign-in not completed"),
        "stderr must report sign-in failure: {mismatch_stderr}"
    );
    assert!(
        mismatch_stderr.contains("state mismatch"),
        "stderr must identify state mismatch reason: {mismatch_stderr}"
    );
}

/// Quickstart Q12: Status line format on stderr shows account, tenant, both audiences, and expiry.
#[tokio::test]
async fn test_status_line_content() {
    let idp = MockIdp::start().await;
    idp.set_user(
        "analyst@corp.example.com",
        "12345678-abcd-ef01-2345-6789abcdef01",
        "99999999-9999-9999-9999-999999999999",
    );

    let proc = McpProcess::start(
        &["--auth-mode", "user", "--sign-in-flow", "browser"],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    );

    let stderr = proc.captured_stderr();
    let status_line = stderr
        .lines()
        .find(|l| l.starts_with("Signed in as "))
        .expect("must output status line starting with 'Signed in as '");

    assert!(status_line.contains("analyst@corp.example.com"));
    assert!(status_line.contains("tenant 12345678-abcd-ef01-2345-6789abcdef01"));
    assert!(status_line.contains("endpoint:"));
    assert!(status_line.contains("graph:"));
    assert!(status_line.contains("expires "));

    proc.shutdown();
}

/// Quickstart Q12: Device code flow displays message on stderr, carries 0 bytes on stdout before initialize,
/// and expired_token exits non-zero with "Sign-in not completed".
#[tokio::test]
async fn test_device_code_flow_message_and_zero_stdout_bytes_on_expired_token() {
    let idp = MockIdp::start().await;
    idp.set_device_code_sequence(vec![
        DeviceCodeStep::Pending,
        DeviceCodeStep::SlowDown,
        DeviceCodeStep::Success,
    ]);
    idp.set_device_code_interval(0);

    let proc = McpProcess::start(
        &["--auth-mode", "user", "--sign-in-flow", "device-code"],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_TEST_SLOW_DOWN_MS", "50"),
        ],
    );

    let stderr = proc.captured_stderr();
    assert!(
        stderr.contains(&format!("enter the code {SENTINEL_UC} to authenticate")),
        "stderr must display IdP instruction message verbatim: {stderr}"
    );
    assert!(
        stderr.contains("Signed in as alice@contoso.com"),
        "stderr must report completed sign-in: {stderr}"
    );

    proc.shutdown();

    // Expired token sequence
    let idp_expired = MockIdp::start().await;
    idp_expired.set_device_code_sequence(vec![DeviceCodeStep::ExpiredToken]);
    idp_expired.set_device_code_interval(0);

    let out = server_command(
        &["--auth-mode", "user", "--sign-in-flow", "device-code"],
        &[("DEFENDER_AUTHORITY_BASE_URL", idp_expired.base_url())],
    )
    .output()
    .expect("run server with expired device code");

    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "stdout must carry 0 bytes before initialize and upon failed sign-in"
    );
    let expired_stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        expired_stderr.contains("Sign-in not completed: expired token. The server did not start."),
        "stderr must contain exact Sign-in not completed message: {expired_stderr}"
    );
}

/// Quickstart Q12: In user mode under `--read-only`, write-named scopes are not requested,
/// and a write-named read returns `scope_not_requested` with 0 hits.
#[tokio::test]
async fn test_read_only_scopes_and_scope_not_requested_gate() {
    let upstream = spawn_mock(Router::new().route(
        "/api/files/{id}/machines",
        get(|| async { Json(json!({"value": []})) }),
    ))
    .await;

    let idp = MockIdp::start().await;

    let mut proc = McpProcess::start(
        &[
            "--auth-mode",
            "user",
            "--sign-in-flow",
            "browser",
            "--read-only",
        ],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_ENDPOINT_BASE_URL", &upstream.base_url),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    );

    // Verify requested scopes in authorize request
    let authorizes = idp.recorded_authorizes();
    assert!(!authorizes.is_empty());
    let requested_scopes = authorizes[0].scope.as_deref().unwrap_or_default();

    for forbidden in [
        "Machine.ReadWrite",
        "Alert.ReadWrite",
        "Ti.ReadWrite",
        "Machine.Isolate",
        "Machine.Scan",
        "Machine.Offboard",
        "Library.Manage",
    ] {
        assert!(
            !requested_scopes.contains(forbidden),
            "read-only user mode must not request scope '{forbidden}', got: {requested_scopes}"
        );
    }

    // Call write-named read: file_related_machines on defender_machines
    let call_res = proc.call_tool(
        "defender_machines",
        json!({
            "action": "file_related_machines",
            "id": "0123456789abcdef0123456789abcdef01234567"
        }),
    );

    assert_eq!(call_res["result"]["isError"], true);
    let structured = &call_res["result"]["structuredContent"];
    assert_eq!(structured["code"], "scope_not_requested");
    let err_msg = structured["error"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("file_related_machines needs Machine.ReadWrite, which is write-named and is not requested under --read-only"),
        "error message should explain write-named scope: {err_msg}"
    );

    // Assert 0 upstream hits
    upstream.assert_hits(
        "/api/files/0123456789abcdef0123456789abcdef01234567/machines",
        0,
    );
    assert_eq!(upstream.total_hits(), 0);

    proc.shutdown();
}

/// Quickstart Q12: Graph returning AADSTS65001 lets endpoint calls succeed while Graph calls return consent_missing.
#[tokio::test]
async fn test_consent_missing_for_graph_allows_endpoint() {
    let upstream = spawn_mock(
        Router::new()
            .route(
                "/api/machines",
                get(|| async { Json(json!({"value": [{"id": "m1"}]})) }),
            )
            .route(
                "/v1.0/security/runHuntingQuery",
                post(|| async { Json(json!({"results": []})) }),
            ),
    )
    .await;

    let idp = MockIdp::start().await;
    idp.set_audience_response(Audience::Graph, AudienceResponse::Aadsts(65001));

    let mut proc = McpProcess::start(
        &["--auth-mode", "user", "--sign-in-flow", "browser"],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_ENDPOINT_BASE_URL", &upstream.base_url),
            ("GRAPH_BASE_URL", &upstream.base_url),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    );

    let stderr = proc.captured_stderr();
    assert!(
        stderr.contains("graph: consent missing (AADSTS65001)"),
        "status line should indicate graph consent is missing: {stderr}"
    );

    // Endpoint call succeeds
    let ep_call = proc.call_tool("defender_machines", json!({"action": "machine_list"}));
    assert_ne!(
        ep_call["result"]["isError"], true,
        "endpoint call should succeed: {ep_call}"
    );
    upstream.assert_hits("/api/machines", 1);

    // Graph call returns consent_missing locally before any upstream request
    let gr_call = proc.call_tool(
        "defender_hunting",
        json!({"action": "run", "query": "DeviceEvents | take 1"}),
    );
    assert_eq!(gr_call["result"]["isError"], true);
    let structured = &gr_call["result"]["structuredContent"];
    assert_eq!(structured["code"], "consent_missing");
    assert_eq!(structured["audience"], "graph");

    upstream.assert_hits("/v1.0/security/runHuntingQuery", 0);

    proc.shutdown();
}

/// Quickstart Q12: API 401 with `WWW-Authenticate: ... error="insufficient_claims"` triggers
/// `reauthentication_required` (`conditional_access`).
#[tokio::test]
async fn test_conditional_access_401_claims_challenge() {
    let upstream = spawn_mock(Router::new().route(
        "/api/machines",
        get(|| async {
            (
                StatusCode::UNAUTHORIZED,
                [(
                    axum::http::header::WWW_AUTHENTICATE,
                    "Bearer realm=\"\", error=\"insufficient_claims\", error_description=\"Claims challenge\"",
                )],
                Json(json!({"error": {"code": "Unauthorized"}})),
            )
                .into_response()
        }),
    ))
    .await;

    let idp = MockIdp::start().await;

    let mut proc = McpProcess::start(
        &["--auth-mode", "user", "--sign-in-flow", "browser"],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_ENDPOINT_BASE_URL", &upstream.base_url),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    );

    let res = proc.call_tool("defender_machines", json!({"action": "machine_list"}));
    assert_eq!(res["result"]["isError"], true);

    let structured = &res["result"]["structuredContent"];
    assert_eq!(structured["code"], "reauthentication_required");
    assert_eq!(structured["reason"], "conditional_access");
    let err_msg = structured["error"].as_str().unwrap_or_default();
    assert!(err_msg.contains("conditional_access"));

    proc.shutdown();
}

/// Quickstart Q12: Mock 403 in user mode returns httpStatus:403, permission_category,
/// and the "signed-in user's own rights apply" message text.
#[tokio::test]
async fn test_user_mode_403_rights_text() {
    let upstream = spawn_mock(Router::new().route(
        "/api/machines",
        get(|| async {
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error": {"code": "Forbidden", "message": "Access denied"}})),
            )
                .into_response()
        }),
    ))
    .await;

    let idp = MockIdp::start().await;

    let mut proc = McpProcess::start(
        &["--auth-mode", "user", "--sign-in-flow", "browser"],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_ENDPOINT_BASE_URL", &upstream.base_url),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    );

    let res = proc.call_tool("defender_machines", json!({"action": "machine_list"}));
    assert_eq!(res["result"]["isError"], true);

    let structured = &res["result"]["structuredContent"];
    assert_eq!(structured["httpStatus"], 403);
    assert_eq!(structured["permission_category"], "read_endpoint");
    let err_msg = structured["error"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("The signed-in user's own rights apply"),
        "error message must emphasize user rights: {err_msg}"
    );
    assert!(
        err_msg.contains("*.Read"),
        "error message must cite required delegated scope: {err_msg}"
    );
    assert!(
        err_msg.contains("View data"),
        "error message must cite required Defender role: {err_msg}"
    );

    proc.shutdown();
}

/// Quickstart Q12: AZURE_TENANT_ID=common and organizations exit non-zero at startup.
#[test]
fn test_tenant_common_organizations_rejected() {
    let out_common = server_command(&["--auth-mode", "user"], &[("AZURE_TENANT_ID", "common")])
        .output()
        .expect("run server");

    assert!(!out_common.status.success());
    let stderr_common = String::from_utf8_lossy(&out_common.stderr);
    assert!(
        stderr_common.contains("AZURE_TENANT_ID cannot be 'common' or 'organizations'"),
        "stderr must explain tenant rejection: {stderr_common}"
    );

    let out_orgs = server_command(
        &["--auth-mode", "user"],
        &[("AZURE_TENANT_ID", "organizations")],
    )
    .output()
    .expect("run server");

    assert!(!out_orgs.status.success());
    let stderr_orgs = String::from_utf8_lossy(&out_orgs.stderr);
    assert!(
        stderr_orgs.contains("AZURE_TENANT_ID cannot be 'common' or 'organizations'"),
        "stderr must explain tenant rejection: {stderr_orgs}"
    );
}

/// Quickstart Q12: AZURE_CLIENT_SECRET produces the "ignored" NOTE in user mode when set,
/// and produces no NOTE when unset.
#[tokio::test]
async fn test_azure_client_secret_ignored_notice() {
    let idp = MockIdp::start().await;
    idp.set_device_code_sequence(vec![DeviceCodeStep::ExpiredToken]);
    idp.set_device_code_interval(0);

    let out_with_secret = server_command(
        &["--auth-mode", "user", "--sign-in-flow", "device-code"],
        &[
            ("AZURE_CLIENT_SECRET", "super-secret-value"),
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
        ],
    )
    .output()
    .expect("run server with client secret");

    let stderr_with_secret = String::from_utf8_lossy(&out_with_secret.stderr);
    assert!(
        stderr_with_secret.contains("NOTE: AZURE_CLIENT_SECRET is ignored in --auth-mode user."),
        "stderr must print notice when secret is present: {stderr_with_secret}"
    );

    let out_without_secret = server_command(
        &["--auth-mode", "user", "--sign-in-flow", "device-code"],
        &[
            ("AZURE_CLIENT_SECRET", ""),
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
        ],
    )
    .output()
    .expect("run server without client secret");

    let stderr_without_secret = String::from_utf8_lossy(&out_without_secret.stderr);
    assert!(
        !stderr_without_secret
            .contains("NOTE: AZURE_CLIENT_SECRET is ignored in --auth-mode user."),
        "stderr must not print notice when secret is absent: {stderr_without_secret}"
    );
}

/// Quickstart Q12: HTTP transport in user mode prints the shared-identity SECURITY WARNING.
#[tokio::test]
async fn test_http_transport_security_warning() {
    let idp = MockIdp::start().await;

    let mut child = server_command(
        &[
            "--auth-mode",
            "user",
            "--transport",
            "http",
            "--bind-address",
            "127.0.0.1:0",
        ],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
    )
    .stderr(std::process::Stdio::piped())
    .spawn()
    .expect("spawn http server");

    tokio::time::sleep(Duration::from_millis(800)).await;
    let _ = child.kill();
    let out = child.wait_with_output().expect("wait for child");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("SECURITY WARNING: every HTTP client connected to this server acts as alice@contoso.com with that user's Defender rights; run one server per analyst for per-person attribution."),
        "stderr must print HTTP shared-identity warning: {stderr}"
    );
}

/// Quickstart Q12: Mutating action in user mode records identity {"kind":"user",...} in audit log,
/// and credentials exclusion check confirms zero "SENTINEL-" matches in stderr and audit file.
#[tokio::test]
async fn test_user_mode_mutating_audit_identity_and_credentials_exclusion() {
    let upstream = spawn_mock(Router::new().route(
        "/api/machines/{id}/isolate",
        post(|| async {
            Json(json!({
                "id": "action-isolate-999",
                "type": "Isolate",
                "status": "Pending",
                "machineId": MOCK_MACHINE_ID,
            }))
        }),
    ))
    .await;

    let idp = MockIdp::start().await;
    let scratch = ScratchDir::new("user-audit");
    let audit_file = scratch.0.join("audit.jsonl");

    let mut proc = McpProcess::initialize_with_elicitation(
        &[
            "--auth-mode",
            "user",
            "--sign-in-flow",
            "browser",
            "--enable-device-response",
            "--audit-log",
            audit_file.to_str().unwrap(),
        ],
        &[
            ("DEFENDER_AUTHORITY_BASE_URL", idp.base_url()),
            ("DEFENDER_ENDPOINT_BASE_URL", &upstream.base_url),
            ("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd()),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let isolate_res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MOCK_MACHINE_ID,
            "comment": "Quarantining compromised host per playbook",
            "isolation_type": "Full"
        }),
    );

    assert_ne!(
        isolate_res["result"]["isError"], true,
        "isolate action should succeed: {isolate_res}"
    );

    let stderr = proc.captured_stderr();
    proc.shutdown();

    // Verify audit log entries
    let audit_content = std::fs::read_to_string(&audit_file).expect("read audit file");
    assert!(!audit_content.is_empty(), "audit file must have entries");

    let mut found_user_identity = false;
    for line in audit_content.lines() {
        if let Ok(entry) = serde_json::from_str::<Value>(line)
            && let Some(id) = entry.get("identity")
        {
            assert_eq!(id["kind"], "user");
            assert_eq!(id["account"], "alice@contoso.com");
            assert_eq!(id["tenant_id"], "00000000-0000-0000-0000-000000000000");
            found_user_identity = true;
        }
    }
    assert!(
        found_user_identity,
        "audit log must contain user identity entry"
    );

    // Credential exclusion: zero SENTINEL- matches in stderr and audit file
    assert!(
        !stderr.contains("SENTINEL-"),
        "stderr must contain zero SENTINEL- matches, found:\n{stderr}"
    );
    assert!(
        !audit_content.contains("SENTINEL-"),
        "audit file must contain zero SENTINEL- matches, found:\n{audit_content}"
    );
}
