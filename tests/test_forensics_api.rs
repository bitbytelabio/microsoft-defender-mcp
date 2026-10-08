//! Forensic collection (`defender_response`) and status/SAS retrieval (`defender_forensics`)
//! against a loopback Defender for Endpoint fixture.

mod common;

use axum::{Json, Router, body::Bytes, extract::Request, http::StatusCode, response::IntoResponse};
use common::{base_config, spawn_mock, test_server};
use microsoft_defender_mcp_server::cli::{ServerConfig, ToolMode};
use microsoft_defender_mcp_server::server::{DefenderServer, ForensicsInput, ResponseInput};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::ErrorCode;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

const MACHINE: &str = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07";
const ACTION: &str = "7327b54fd718525cbca07dacde913b5ac3c85673";
const SHA1: &str = "87662bc3d60e4200ceaf7aae249d1c343f4b83c9";

/// Requests seen by the fixture: (method, path, JSON body).
type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

/// Fixture that records every request and answers the Defender endpoints used here.
fn fixture(seen: Seen) -> Router {
    Router::new().fallback(move |req: Request| {
        let seen = seen.clone();
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let body: Bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            let json_body = serde_json::from_slice(&body).unwrap_or(Value::Null);
            seen.lock().await.push((method.clone(), path.clone(), json_body));

            let collect = format!("/api/machines/{MACHINE}/collectInvestigationPackage");
            let quarantine = format!("/api/machines/{MACHINE}/StopAndQuarantineFile");
            let status = format!("/api/machineactions/{ACTION}");
            let package = format!("/api/machineactions/{ACTION}/getPackageUri");
            match (method.as_str(), path.as_str()) {
                ("POST", p) if p == collect => (
                    StatusCode::CREATED,
                    Json(json!({ "id": ACTION, "type": "CollectInvestigationPackage", "status": "Pending" })),
                )
                    .into_response(),
                ("POST", p) if p == quarantine => (
                    StatusCode::CREATED,
                    Json(json!({ "id": ACTION, "type": "StopAndQuarantineFile", "status": "Pending" })),
                )
                    .into_response(),
                ("GET", p) if p == status => {
                    Json(json!({ "id": ACTION, "status": "Succeeded" })).into_response()
                }
                ("GET", p) if p == package => {
                    Json(json!({ "value": "https://contoso.blob.core.windows.net/p.zip?sig=x" }))
                        .into_response()
                }
                _ => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response(),
            }
        }
    })
}

fn server(base_url: &str, live_response_enabled: bool) -> DefenderServer {
    test_server(
        base_url,
        ServerConfig {
            tool_mode: ToolMode::Consolidated,
            live_response_enabled,
            ..base_config()
        },
    )
}

fn collect_input(comment: &str) -> ResponseInput {
    ResponseInput {
        action: "collect_investigation_package".to_string(),
        machine_id: Some(MACHINE.to_string()),
        comment: Some(comment.to_string()),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_collect_investigation_package_posts_comment_and_returns_machine_action() {
    let seen = Seen::default();
    let mock = spawn_mock(fixture(seen.clone())).await;

    let res = server(&mock.base_url, true)
        .defender_response(Parameters(collect_input("Incident 4124 triage collection")))
        .await
        .expect("collection succeeded");

    let action = res.structured_content.expect("machine action");
    assert_eq!(action["id"], ACTION);
    assert_eq!(action["status"], "Pending");
    let seen = seen.lock().await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "POST");
    assert_eq!(
        seen[0].2,
        json!({ "Comment": "Incident 4124 triage collection" })
    );
}

#[tokio::test]
async fn test_short_comment_rejected_before_network() {
    let seen = Seen::default();
    let mock = spawn_mock(fixture(seen.clone())).await;

    let err = server(&mock.base_url, true)
        .defender_response(Parameters(collect_input("too short")))
        .await
        .expect_err("comment under 10 characters must be rejected");

    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(seen.lock().await.is_empty());
}

#[tokio::test]
async fn test_invalid_machine_id_rejected_before_network() {
    let seen = Seen::default();
    let mock = spawn_mock(fixture(seen.clone())).await;
    let mut input = collect_input("Incident 4124 triage collection");
    input.machine_id = Some("../machines".to_string());

    let err = server(&mock.base_url, true)
        .defender_response(Parameters(input))
        .await
        .expect_err("invalid machine id must be rejected");

    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(seen.lock().await.is_empty());
}

#[tokio::test]
async fn test_response_disabled_without_live_response_flag() {
    let seen = Seen::default();
    let mock = spawn_mock(fixture(seen.clone())).await;

    let res = server(&mock.base_url, false)
        .defender_response(Parameters(collect_input("Incident 4124 triage collection")))
        .await
        .expect("tool-level error");

    assert_eq!(res.is_error, Some(true));
    assert!(seen.lock().await.is_empty());
}

#[tokio::test]
async fn test_stop_and_quarantine_file_sends_sha1_and_comment() {
    let seen = Seen::default();
    let mock = spawn_mock(fixture(seen.clone())).await;

    let res = server(&mock.base_url, true)
        .defender_response(Parameters(ResponseInput {
            action: "stop_and_quarantine_file".to_string(),
            machine_id: Some(MACHINE.to_string()),
            sha1: Some(SHA1.to_string()),
            comment: Some("Incident 4124 contain dropper".to_string()),
            ..Default::default()
        }))
        .await
        .expect("quarantine succeeded");

    assert_eq!(
        res.structured_content.expect("action")["type"],
        "StopAndQuarantineFile"
    );
    let seen = seen.lock().await;
    assert_eq!(
        seen[0].2,
        json!({ "Comment": "Incident 4124 contain dropper", "Sha1": SHA1 })
    );
}

#[tokio::test]
async fn test_machine_action_status_and_package_sas_url() {
    let mock = spawn_mock(fixture(Seen::default())).await;
    let server = server(&mock.base_url, false);

    let status = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "machine_action_get_status".to_string(),
            action_id: Some(ACTION.to_string()),
            ..Default::default()
        }))
        .await
        .expect("status succeeded");
    assert_eq!(
        status.structured_content.expect("status")["status"],
        "Succeeded"
    );

    let sas = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "get_investigation_package_sas_url".to_string(),
            action_id: Some(ACTION.to_string()),
            ..Default::default()
        }))
        .await
        .expect("sas url succeeded");
    let sas = sas.structured_content.expect("sas");
    assert_eq!(sas["action_id"], ACTION);
    assert!(sas["value"].as_str().unwrap().starts_with("https://"));
}
