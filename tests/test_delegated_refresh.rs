//! Dedicated test file for token refresh concurrency and single-flight behavior.
//!
//! Isolated in its own binary to avoid process-wide environment variable races.

mod common;

use std::time::Duration;

use common::idp::{AudienceResponse, MockIdp};
use microsoft_defender_mcp_server::auth::{Audience, TokenManager};
use microsoft_defender_mcp_server::cli::{AuthConfig, ServerConfig, SignInFlow};

/// Quickstart Q12: 20 concurrent calls with expired token trigger exactly 1 refresh request,
/// rotate refresh token, and subsequent invalid_grant AADSTS700082 sets session_expired with no further hits.
#[tokio::test]
async fn test_token_refresh_single_flight_and_session_expired() {
    let idp = MockIdp::start().await;
    // Set initial Endpoint and Graph tokens to expire in 60s so they are immediately considered expired
    idp.set_audience_response(
        Audience::Endpoint,
        AudienceResponse::Success {
            scopes: vec!["https://api.securitycenter.microsoft.com/Machine.Read".to_string()],
            expires_in: 60,
        },
    );
    idp.set_audience_response(
        Audience::Graph,
        AudienceResponse::Success {
            scopes: vec!["https://graph.microsoft.com/ThreatHunting.Read.All".to_string()],
            expires_in: 60,
        },
    );
    let config = ServerConfig {
        transport: microsoft_defender_mcp_server::cli::TransportMode::Stdio,
        bind_address: "127.0.0.1:8000".to_string(),
        read_only: false,
        categories: microsoft_defender_mcp_server::cli::MutationCategories::default(),
        live_response_allowed_commands: None,
        quarantine_dir: std::path::PathBuf::from("./quarantine"),
        audit_log: microsoft_defender_mcp_server::cli::AuditLogSetting::Default(
            std::path::PathBuf::from("./audit.jsonl"),
        ),
        confirm_destructive: false,
        auth: AuthConfig::User {
            flow: SignInFlow::Browser,
        },
    };

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    unsafe {
        std::env::set_var("DEFENDER_AUTHORITY_BASE_URL", idp.base_url());
        std::env::set_var("DEFENDER_TEST_BROWSER_CMD", MockIdp::browser_cmd());
        std::env::set_var("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000");
        std::env::set_var("AZURE_CLIENT_ID", "11111111-1111-1111-1111-111111111111");
    }

    let tm = TokenManager::sign_in_user(&config, SignInFlow::Browser, http)
        .await
        .expect("sign-in should succeed");

    // Clear initial sign-in request counts
    idp.reset_history();

    // Next refresh response returns valid token and rotates refresh token
    idp.set_audience_response(
        Audience::Endpoint,
        AudienceResponse::Success {
            scopes: vec!["https://api.securitycenter.microsoft.com/Machine.Read".to_string()],
            expires_in: 3600,
        },
    );

    // 20 concurrent requests for Audience::Endpoint
    let mut handles = Vec::new();
    for _ in 0..20 {
        let tm_clone = tm.clone();
        handles.push(tokio::spawn(async move {
            tm_clone.get_token(Audience::Endpoint).await
        }));
    }

    for h in handles {
        let res = h.await.unwrap();
        assert!(res.is_ok(), "concurrent token acquisition should succeed");
    }

    // Exactly 1 refresh request was made to the IdP
    assert_eq!(
        idp.grant_count("refresh_token"),
        1,
        "single-flight refresh must make exactly 1 IdP request for 20 concurrent calls"
    );

    // Configure Graph refresh request to fail with AADSTS700082
    idp.set_audience_response(Audience::Graph, AudienceResponse::Aadsts(700082));

    // First call after expiration gets AADSTS700082 -> session_expired
    let err1 = tm.get_token(Audience::Graph).await.unwrap_err();
    let val1 = err1.structured_content.expect("structured error");
    assert_eq!(val1["code"], "reauthentication_required");
    assert_eq!(val1["reason"], "session_expired");

    assert_eq!(
        idp.grant_count("refresh_token"),
        2,
        "second refresh attempt hit IdP"
    );

    // Second call fails fast locally with NO further network requests
    let err2 = tm.get_token(Audience::Endpoint).await.unwrap_err();
    let val2 = err2.structured_content.expect("structured error");
    assert_eq!(val2["code"], "reauthentication_required");
    assert_eq!(val2["reason"], "session_expired");

    assert_eq!(
        idp.grant_count("refresh_token"),
        2,
        "subsequent calls must not produce further IdP hits once reauth is required"
    );

    unsafe {
        std::env::remove_var("DEFENDER_AUTHORITY_BASE_URL");
        std::env::remove_var("DEFENDER_TEST_BROWSER_CMD");
        std::env::remove_var("AZURE_TENANT_ID");
        std::env::remove_var("AZURE_CLIENT_ID");
    }
}
