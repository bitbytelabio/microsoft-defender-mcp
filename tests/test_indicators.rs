//! Custom Indicators integration tests (US3, T037, quickstart Q9).

mod common;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::Router;
use common::{ElicitationResponse, McpProcess, SENTINEL_APP_TOKEN, ScratchDir, spawn_mock};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const COMMENT: &str = "Threat intelligence indicator sync";

fn make_token_resp() -> Value {
    json!({
        "token_type": "Bearer",
        "access_token": SENTINEL_APP_TOKEN,
        "expires_in": 3600
    })
}

#[derive(Clone, Default)]
struct IndicatorStore {
    indicators: Arc<Mutex<Vec<Value>>>,
    captured_bodies: Arc<Mutex<Vec<(String, String, Value)>>>,
}

fn create_indicator_mock_app(store: IndicatorStore) -> Router {
    Router::new().fallback(move |req: Request| {
        let store = store.clone();
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();

            if method == "POST" && path.ends_with("/oauth2/v2.0/token") {
                return axum::Json(make_token_resp()).into_response();
            }

            if method == "POST" && path == "/api/indicators" {
                let bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap();
                store.captured_bodies.lock().unwrap().push((
                    method.clone(),
                    path.clone(),
                    body.clone(),
                ));

                let val = body["indicatorValue"].as_str().unwrap().to_string();
                let itype = body["indicatorType"].as_str().unwrap().to_string();
                let mut lock = store.indicators.lock().unwrap();
                if let Some(pos) = lock.iter().position(|item| {
                    item["indicatorValue"] == val && item["indicatorType"] == itype
                }) {
                    let mut updated = body.clone();
                    let existing_id = lock[pos]["id"].clone();
                    updated["id"] = existing_id;
                    lock[pos] = updated.clone();
                    return axum::Json(updated).into_response();
                } else {
                    let mut new_item = body.clone();
                    let new_id = format!("ind-{}", lock.len() + 1);
                    new_item["id"] = json!(new_id);
                    lock.push(new_item.clone());
                    return axum::Json(new_item).into_response();
                }
            }

            if method == "GET" && path == "/api/indicators" {
                let lock = store.indicators.lock().unwrap();
                let list: Vec<Value> = lock.clone();
                return axum::Json(json!({ "value": list })).into_response();
            }

            if method == "DELETE" && path.starts_with("/api/indicators/") {
                let id = path.trim_start_matches("/api/indicators/");
                let mut lock = store.indicators.lock().unwrap();
                lock.retain(|item| item["id"] != id);
                return StatusCode::NO_CONTENT.into_response();
            }

            if method == "POST" && path == "/api/indicators/BatchDelete" {
                let bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap();
                store.captured_bodies.lock().unwrap().push((
                    method.clone(),
                    path.clone(),
                    body.clone(),
                ));

                let ids_to_delete: Vec<String> = body["IndicatorIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                let mut lock = store.indicators.lock().unwrap();
                lock.retain(|item| {
                    !ids_to_delete.contains(&item["id"].as_str().unwrap().to_string())
                });
                return StatusCode::NO_CONTENT.into_response();
            }

            StatusCode::NOT_FOUND.into_response()
        }
    })
}

#[tokio::test]
async fn test_indicators_lifecycle_submit_list_update_delete() {
    let store = IndicatorStore::default();
    let mock = spawn_mock(create_indicator_mock_app(store.clone())).await;
    let scratch = ScratchDir::new("indicator-lifecycle");
    let audit_file = scratch.0.join("audit.jsonl");

    let mut proc = McpProcess::initialize_with_elicitation(
        &[
            "--enable-indicators",
            "--audit-log",
            audit_file.to_str().unwrap(),
        ],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let future_exp = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

    // 1. Submit Audit indicator for SHA-256
    let submit_res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": sha256,
            "indicator_type": "FileSha256",
            "indicator_action": "Audit",
            "title": "Suspicious SHA-256 hash",
            "description": "Observed in suspicious execution chain",
            "expiration_time": future_exp,
            "severity": "Low",
            "comment": COMMENT,
        }),
    );
    assert_ne!(
        submit_res["result"]["isError"],
        json!(true),
        "submit failed: {submit_res:?}"
    );
    let ind_id = submit_res["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!ind_id.is_empty());

    // Verify captured body has camelCase keys and generateAlert: true
    {
        let captured = store.captured_bodies.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (method, path, body) = &captured[0];
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/indicators");
        assert_eq!(body["indicatorValue"], json!(sha256));
        assert_eq!(body["indicatorType"], json!("FileSha256"));
        assert_eq!(body["action"], json!("Audit"));
        assert_eq!(body["generateAlert"], json!(true));
        assert_eq!(body["severity"], json!("Low"));
        assert_eq!(body["title"], json!("Suspicious SHA-256 hash"));
        assert_eq!(
            body["description"],
            json!("Observed in suspicious execution chain")
        );
        assert_eq!(body["expirationTime"], json!(future_exp));
    }

    // 2. List indicators via defender_ti custom_indicator_list
    let list_res = proc.call_tool(
        "defender_ti",
        json!({
            "action": "custom_indicator_list"
        }),
    );
    assert_ne!(
        list_res["result"]["isError"],
        json!(true),
        "list failed: {list_res:?}"
    );
    let items = list_res["result"]["structuredContent"]["value"]
        .as_array()
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], json!(ind_id));
    assert_eq!(items[0]["severity"], json!("Low"));

    // 3. Submit again with new severity -> updates it
    let update_res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": sha256,
            "indicator_type": "FileSha256",
            "indicator_action": "Audit",
            "title": "Suspicious SHA-256 hash",
            "description": "Observed in suspicious execution chain",
            "expiration_time": future_exp,
            "severity": "High",
            "comment": "Escalated severity after further triage",
        }),
    );
    assert_ne!(
        update_res["result"]["isError"],
        json!(true),
        "update failed: {update_res:?}"
    );
    assert_eq!(
        update_res["result"]["structuredContent"]["id"],
        json!(ind_id)
    );
    assert_eq!(
        update_res["result"]["structuredContent"]["severity"],
        json!("High")
    );

    // 4. Delete indicator -> 204 maps to {"status":"deleted","indicator_id":..}
    let delete_res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "delete",
            "indicator_id": ind_id,
            "comment": "Cleanup decommissioned test indicator",
        }),
    );
    assert_ne!(
        delete_res["result"]["isError"],
        json!(true),
        "delete failed: {delete_res:?}"
    );
    assert_eq!(
        delete_res["result"]["structuredContent"]["status"],
        json!("deleted")
    );
    assert_eq!(
        delete_res["result"]["structuredContent"]["indicator_id"],
        json!(ind_id)
    );

    // 5. Next list no longer contains it
    let list_after = proc.call_tool(
        "defender_ti",
        json!({
            "action": "custom_indicator_list"
        }),
    );
    assert_ne!(
        list_after["result"]["isError"],
        json!(true),
        "list_after failed: {list_after:?}"
    );
    let items_after = list_after["result"]["structuredContent"]["value"]
        .as_array()
        .unwrap();
    assert!(
        items_after.is_empty(),
        "expected indicator list to be empty after delete, got {items_after:?}"
    );

    assert!(proc.shutdown().success());
}
#[tokio::test]
async fn test_indicators_batch_delete() {
    let store = IndicatorStore::default();
    let mock = spawn_mock(create_indicator_mock_app(store.clone())).await;
    let scratch = ScratchDir::new("indicator-batch-del");
    let audit_file = scratch.0.join("audit.jsonl");

    let mut proc = McpProcess::initialize_with_elicitation(
        &[
            "--enable-indicators",
            "--audit-log",
            audit_file.to_str().unwrap(),
        ],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // Pre-populate 3 indicators in the store
    {
        let mut lock = store.indicators.lock().unwrap();
        lock.push(
            json!({ "id": "ind-1", "indicatorValue": "1.1.1.1", "indicatorType": "IpAddress" }),
        );
        lock.push(
            json!({ "id": "ind-2", "indicatorValue": "2.2.2.2", "indicatorType": "IpAddress" }),
        );
        lock.push(
            json!({ "id": "ind-3", "indicatorValue": "3.3.3.3", "indicatorType": "IpAddress" }),
        );
    }

    let batch_res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "batch_delete",
            "indicator_ids": ["ind-1", "ind-2"],
            "comment": "Batch decommission expired IP indicators",
        }),
    );
    assert_ne!(
        batch_res["result"]["isError"],
        json!(true),
        "batch_delete failed: {batch_res:?}"
    );
    assert_eq!(
        batch_res["result"]["structuredContent"]["status"],
        json!("deleted")
    );
    assert_eq!(batch_res["result"]["structuredContent"]["count"], json!(2));

    // Assert captured request body
    {
        let captured = store.captured_bodies.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (method, path, body) = &captured[0];
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/indicators/BatchDelete");
        assert_eq!(body["IndicatorIds"], json!(["ind-1", "ind-2"]));
    }

    // Verify mock hits and store contents
    mock.assert_hits("/api/indicators/BatchDelete", 1);
    {
        let lock = store.indicators.lock().unwrap();
        assert_eq!(lock.len(), 1);
        assert_eq!(lock[0]["id"], json!("ind-3"));
    }

    assert!(proc.shutdown().success());
}
#[tokio::test]
async fn test_indicators_local_rejections_values_and_dates() {
    let store = IndicatorStore::default();
    let mock = spawn_mock(create_indicator_mock_app(store.clone())).await;
    let scratch = ScratchDir::new("indicator-rejections-val");
    let audit_file = scratch.0.join("audit.jsonl");

    let mut proc = McpProcess::initialize_with_elicitation(
        &[
            "--enable-indicators",
            "--audit-log",
            audit_file.to_str().unwrap(),
        ],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let valid_exp = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    let past_exp = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();

    // 1. 39-hex SHA-1 (40 expected)
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": "1234567890abcdef1234567890abcdef1234567", // 39 hex
            "indicator_type": "FileSha1",
            "indicator_action": "Allowed",
            "title": "Invalid SHA-1",
            "description": "Short SHA-1 test",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_value"),
        "error must name 'indicator_value': {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 2. 999.999.999.999 (invalid IP)
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": "999.999.999.999",
            "indicator_type": "IpAddress",
            "indicator_action": "Allowed",
            "title": "Invalid IP",
            "description": "Out of range IP octets",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_value"),
        "error must name 'indicator_value': {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 3. ftp://x (invalid URL scheme)
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": "ftp://x",
            "indicator_type": "Url",
            "indicator_action": "Allowed",
            "title": "Invalid URL scheme",
            "description": "Non HTTP/HTTPS URL scheme",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_value"),
        "error must name 'indicator_value': {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 4. A domain that parses as an IP
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": "192.168.1.1",
            "indicator_type": "DomainName",
            "indicator_action": "Allowed",
            "title": "Domain that is an IP",
            "description": "IP literal used as domain name",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_value"),
        "error must name 'indicator_value': {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 5. Past expiration_time
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IpAddress",
            "indicator_action": "Allowed",
            "title": "Past expiration",
            "description": "Indicator with past expiry",
            "expiration_time": past_exp,
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("expiration_time"),
        "error must name 'expiration_time': {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 6. Empty title
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": "1.2.3.4",
            "indicator_type": "IpAddress",
            "indicator_action": "Allowed",
            "title": "",
            "description": "Valid description",
            "expiration_time": valid_exp,
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(msg.contains("title"), "error must name 'title': {msg}");
    mock.assert_hits("/api/indicators", 0);

    assert!(proc.shutdown().success());
}
#[tokio::test]
async fn test_indicators_local_rejections_actions_and_batch() {
    let store = IndicatorStore::default();
    let mock = spawn_mock(create_indicator_mock_app(store.clone())).await;
    let scratch = ScratchDir::new("indicator-rejections-act");
    let audit_file = scratch.0.join("audit.jsonl");

    let mut proc = McpProcess::initialize_with_elicitation(
        &[
            "--enable-indicators",
            "--audit-log",
            audit_file.to_str().unwrap(),
        ],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // 1. BlockAndRemediate + Url (BlockAndRemediate is only for file hashes and CertificateThumbprint)
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": "https://example.com/bad",
            "indicator_type": "Url",
            "indicator_action": "BlockAndRemediate",
            "title": "BlockAndRemediate with URL",
            "description": "Invalid action/type combination",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_action"),
        "error must name 'indicator_action': {msg}"
    );
    assert!(
        msg.contains("BlockAndRemediate"),
        "error must mention 'BlockAndRemediate': {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 2. Warn + FileSha256 (Warn is only for IpAddress, DomainName, Url)
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": sha256,
            "indicator_type": "FileSha256",
            "indicator_action": "Warn",
            "title": "Warn with FileSha256",
            "description": "Invalid action/type combination",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_action"),
        "error must name 'indicator_action': {msg}"
    );
    assert!(msg.contains("Warn"), "error must mention 'Warn': {msg}");
    mock.assert_hits("/api/indicators", 0);

    // 3. Legacy AlertAndBlock (reason contains "legacy, unsupported since January 2022")
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": sha256,
            "indicator_type": "FileSha256",
            "indicator_action": "AlertAndBlock",
            "title": "Legacy AlertAndBlock",
            "description": "Unsupported legacy action",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = if let Some(m) = res["result"]["content"][0]["text"].as_str() {
        m.to_string()
    } else {
        res["error"]["message"].as_str().unwrap_or("").to_string()
    };
    assert!(
        msg.contains("legacy, unsupported since January 2022"),
        "error must contain legacy message: {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 4. Audit with generate_alert: false
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "submit",
            "indicator_value": sha256,
            "indicator_type": "FileSha256",
            "indicator_action": "Audit",
            "generate_alert": false,
            "title": "Audit without alert",
            "description": "Audit action requires generate_alert: true",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("generate_alert"),
        "error must name 'generate_alert': {msg}"
    );
    mock.assert_hits("/api/indicators", 0);

    // 5. batch_delete with 0 batch IDs
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "batch_delete",
            "indicator_ids": [],
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_ids"),
        "error must name 'indicator_ids': {msg}"
    );
    mock.assert_hits("/api/indicators/BatchDelete", 0);

    // 6. batch_delete with 501 batch IDs (exceeds 500)
    let ids_501: Vec<String> = (1..=501).map(|i| format!("ind-{i}")).collect();
    let res = proc.call_tool(
        "defender_indicators",
        json!({
            "action": "batch_delete",
            "indicator_ids": ids_501,
            "comment": COMMENT,
        }),
    );
    assert_eq!(res["result"]["isError"], json!(true));
    let msg = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        msg.contains("indicator_ids"),
        "error must name 'indicator_ids': {msg}"
    );
    mock.assert_hits("/api/indicators/BatchDelete", 0);

    assert!(proc.shutdown().success());
}
#[tokio::test]
async fn test_indicators_disabled_catalog_and_read() {
    let store = IndicatorStore::default();
    // Pre-populate an indicator in the store to verify custom_indicator_list can read it
    {
        let mut lock = store.indicators.lock().unwrap();
        lock.push(json!({
            "id": "ind-pre-1",
            "indicatorValue": "10.0.0.1",
            "indicatorType": "IpAddress",
            "action": "Alert",
            "severity": "Low"
        }));
    }

    let mock = spawn_mock(create_indicator_mock_app(store.clone())).await;
    let scratch = ScratchDir::new("indicator-disabled");
    let audit_file = scratch.0.join("audit.jsonl");

    // Start without --enable-indicators
    let mut proc = McpProcess::initialize_with_elicitation(
        &["--audit-log", audit_file.to_str().unwrap()],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // 1. defender_indicators is absent from tools/list
    let tools = proc.tool_names();
    assert!(
        !tools.contains(&"defender_indicators".to_string()),
        "defender_indicators must be absent when --enable-indicators is omitted, got {tools:?}"
    );
    assert!(
        tools.contains(&"defender_ti".to_string()),
        "defender_ti must be present, got {tools:?}"
    );

    // 2. custom_indicator_list on defender_ti still succeeds
    let list_res = proc.call_tool(
        "defender_ti",
        json!({
            "action": "custom_indicator_list"
        }),
    );
    assert_ne!(
        list_res["result"]["isError"],
        json!(true),
        "custom_indicator_list failed: {list_res:?}"
    );
    let items = list_res["result"]["structuredContent"]["value"]
        .as_array()
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], json!("ind-pre-1"));
    assert_eq!(items[0]["indicatorValue"], json!("10.0.0.1"));

    mock.assert_hits("/api/indicators", 1);

    assert!(proc.shutdown().success());
}
