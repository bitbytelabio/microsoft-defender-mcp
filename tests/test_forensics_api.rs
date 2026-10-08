//! Forensic collection (`defender_response`) and status/SAS retrieval (`defender_forensics`)
//! against a loopback Defender for Endpoint fixture.

mod common;

use axum::{Json, Router, body::Bytes, extract::Request, http::StatusCode, response::IntoResponse};
use common::{
    ElicitationResponse, McpProcess, base_config, spawn_mock, test_server, with_token_route,
};
use microsoft_defender_mcp_server::server::ForensicsInput;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

const MACHINE: &str = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07";
const ACTION: &str = "7327b54fd718525cbca07dacde913b5ac3c85673";
const SHA1: &str = "87662bc3d60e4200ceaf7aae249d1c343f4b83c9";

type Seen = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;

fn fixture(seen: Seen) -> Router {
    Router::new().fallback(move |req: Request| {
        let seen = seen.clone();
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
                .await
                .unwrap_or(Bytes::new());
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

            {
                let mut guard = seen.lock().await;
                guard.push((method.clone(), path.clone(), body));
            }

            match (method.as_str(), path.as_str()) {
                ("POST", p)
                    if p == format!("/api/machines/{MACHINE}/collectInvestigationPackage") =>
                {
                    Json(json!({
                        "id": ACTION,
                        "type": "CollectInvestigationPackage",
                        "status": "Pending",
                        "machineId": MACHINE,
                    }))
                    .into_response()
                }
                ("POST", p) if p == format!("/api/machines/{MACHINE}/StopAndQuarantineFile") => {
                    Json(json!({
                        "id": ACTION,
                        "type": "StopAndQuarantineFile",
                        "status": "Pending",
                        "machineId": MACHINE,
                    }))
                    .into_response()
                }
                ("GET", p) if p == format!("/api/machineactions/{ACTION}") => {
                    Json(json!({ "id": ACTION, "status": "Succeeded" })).into_response()
                }
                ("GET", p) if p == format!("/api/machineactions/{ACTION}/getPackageUri") => {
                    Json(json!({ "value": "https://storage.blob.core.windows.net/pkg.zip" }))
                        .into_response()
                }
                ("DELETE", p) if p.starts_with("/api/libraryfiles/") => {
                    StatusCode::NO_CONTENT.into_response()
                }
                ("POST", p) if p.ends_with("/oauth2/v2.0/token") => Json(json!({
                    "token_type": "Bearer",
                    "access_token": common::SENTINEL_APP_TOKEN,
                    "expires_in": 3600
                }))
                .into_response(),
                _ => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response(),
            }
        }
    })
}

#[tokio::test]
async fn test_collect_investigation_package_posts_comment_and_returns_machine_action() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::start_with_elicitation(
        &["--enable-live-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "collect_investigation_package",
            "machine_id": MACHINE,
            "comment": "Incident 4124 triage collection",
        }),
    );

    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    let action = &res["result"]["structuredContent"];
    assert_eq!(action["id"], ACTION);
    assert_eq!(action["status"], "Pending");

    let seen = seen.lock().await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "POST");
    assert_eq!(
        seen[0].2,
        json!({ "Comment": "Incident 4124 triage collection" })
    );

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_short_comment_rejected_before_network() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::start_with_elicitation(
        &["--enable-live-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "collect_investigation_package",
            "machine_id": MACHINE,
            "comment": "too short",
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true));
    let err_str = res.to_string();
    assert!(
        err_str.contains("at least 10 characters") || err_str.contains("invalid_params"),
        "{err_str}"
    );
    assert!(seen.lock().await.is_empty());
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_invalid_machine_id_rejected_before_network() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::start_with_elicitation(
        &["--enable-live-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "collect_investigation_package",
            "machine_id": "../machines",
            "comment": "Incident 4124 triage collection",
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true));
    assert!(seen.lock().await.is_empty());
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_response_disabled_without_live_response_flag() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::start(
        &[],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "collect_investigation_package",
            "machine_id": MACHINE,
            "comment": "Incident 4124 triage collection",
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true));
    assert_eq!(
        res["result"]["structuredContent"]["code"],
        json!("category_disabled")
    );
    assert!(seen.lock().await.is_empty());
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_stop_and_quarantine_file_sends_sha1_and_comment() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::start_with_elicitation(
        &["--enable-live-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "stop_and_quarantine_file",
            "machine_id": MACHINE,
            "sha1": SHA1,
            "comment": "Incident 4124 contain dropper",
        }),
    );

    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    assert_eq!(
        res["result"]["structuredContent"]["type"],
        "StopAndQuarantineFile"
    );

    let seen = seen.lock().await;
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].2,
        json!({ "Comment": "Incident 4124 contain dropper", "Sha1": SHA1 })
    );

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_machine_action_status_and_package_sas_url() {
    let mock = spawn_mock(fixture(Seen::default())).await;
    let server = test_server(&mock.base_url, base_config());

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

// =========================================================================
// T051: library_file_delete (US5)
// =========================================================================

#[tokio::test]
async fn test_library_file_delete_deletes_file_after_confirmation() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::start_with_elicitation(
        &["--enable-live-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "library_file_delete",
            "file_name": "test_script.ps1",
            "comment": "Cleanup decommissioned remediation script",
        }),
    );

    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    let structured = &res["result"]["structuredContent"];
    assert_eq!(structured["status"], "deleted");
    assert_eq!(structured["file_name"], "test_script.ps1");

    let seen = seen.lock().await;
    assert_eq!(seen.len(), 1, "expected exactly 1 upstream request");
    assert_eq!(seen[0].0, "DELETE");
    assert_eq!(seen[0].1, "/api/libraryfiles/test_script.ps1");

    let elicitations = proc.recorded_elicitations();
    assert_eq!(elicitations.len(), 1, "expected 1 confirmation prompt");
    assert!(elicitations[0].contains("library_file_delete"));
    assert!(elicitations[0].contains("test_script.ps1"));

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_library_file_delete_traversal_rejected_locally() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::start_with_elicitation(
        &["--enable-live-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "library_file_delete",
            "file_name": "../x.ps1",
            "comment": "Malicious traversal attempt here",
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true), "traversal must fail");
    let err_str = res.to_string();
    assert!(
        err_str.contains("traversal") || err_str.contains("file_name"),
        "error must mention traversal or file_name: {err_str}"
    );
    assert!(
        seen.lock().await.is_empty(),
        "local rejection must make 0 hits"
    );
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_library_file_delete_declined_prompt_makes_zero_hits() {
    let seen = Seen::default();
    let mock = spawn_mock(with_token_route(fixture(seen.clone()))).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-live-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::Decline,
    );

    let res = proc.call_tool(
        "defender_response",
        json!({
            "action": "library_file_delete",
            "file_name": "legit_script.ps1",
            "comment": "Cleanup decommissioned remediation script",
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true));
    assert_eq!(
        res["result"]["structuredContent"]["code"],
        json!("not_confirmed")
    );

    assert!(
        seen.lock().await.is_empty(),
        "declined confirmation must make 0 hits"
    );
    assert!(proc.shutdown().success());
}
