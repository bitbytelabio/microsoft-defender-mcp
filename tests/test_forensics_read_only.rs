//! Under `--read-only`, initiating collection/quarantine is rejected before any upstream request,
//! while read-only retrieval (status, downloads) keeps working.

mod common;

use axum::{Json, Router, extract::Request};
use common::{ScratchDir, base_config, spawn_mock, test_server};
use microsoft_defender_mcp_server::cli::{ServerConfig, ToolMode};
use microsoft_defender_mcp_server::server::{ForensicsInput, ResponseInput};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MACHINE: &str = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07";
const ACTION: &str = "7327b54fd718525cbca07dacde913b5ac3c85673";

fn counting_fixture(hits: Arc<AtomicUsize>) -> Router {
    Router::new().fallback(move |_req: Request| {
        let hits = hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            Json(json!({ "id": ACTION, "status": "Succeeded" }))
        }
    })
}

fn read_only_config(quarantine: &ScratchDir) -> ServerConfig {
    ServerConfig {
        tool_mode: ToolMode::Consolidated,
        read_only: true,
        // Even if an operator also requested Live Response, read-only must win.
        live_response_enabled: true,
        quarantine_dir: quarantine.0.clone(),
        ..base_config()
    }
}

#[tokio::test]
async fn test_forensic_collection_rejected_under_read_only_with_zero_upstream_calls() {
    let hits = Arc::new(AtomicUsize::new(0));
    let mock = spawn_mock(counting_fixture(hits.clone())).await;
    let quarantine = ScratchDir::new("ro-collect");
    let server = test_server(&mock.base_url, read_only_config(&quarantine));

    for action in ["collect_investigation_package", "stop_and_quarantine_file"] {
        let res = server
            .defender_response(Parameters(ResponseInput {
                action: action.to_string(),
                machine_id: Some(MACHINE.to_string()),
                sha1: Some("87662bc3d60e4200ceaf7aae249d1c343f4b83c9".to_string()),
                comment: Some("Incident 4124 triage collection".to_string()),
                ..Default::default()
            }))
            .await
            .expect("tool-level error");

        assert_eq!(res.is_error, Some(true), "{action}");
        assert_eq!(
            res.structured_content.expect("error body")["code"],
            "read_only_violation",
            "{action}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_status_lookup_still_allowed_under_read_only() {
    let hits = Arc::new(AtomicUsize::new(0));
    let mock = spawn_mock(counting_fixture(hits.clone())).await;
    let quarantine = ScratchDir::new("ro-status");
    let server = test_server(&mock.base_url, read_only_config(&quarantine));

    let res = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "machine_action_get_status".to_string(),
            action_id: Some(ACTION.to_string()),
            ..Default::default()
        }))
        .await
        .expect("status succeeded");

    assert_eq!(
        res.structured_content.expect("status")["status"],
        "Succeeded"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
