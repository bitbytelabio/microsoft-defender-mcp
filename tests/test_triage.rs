//! Defender triage tool integration tests (US4, T044, Q10).

mod common;

use axum::extract::Request;
use axum::response::IntoResponse;
use common::{ElicitationResponse, McpProcess, SENTINEL_APP_TOKEN, spawn_mock};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct CapturedRequests {
    bodies: Arc<Mutex<Vec<(String, String, Value)>>>,
}

fn create_upstream_app(captured: CapturedRequests) -> axum::Router {
    axum::Router::new().fallback(move |req: Request| {
        let captured = captured.clone();
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();

            if method == "POST" && path.ends_with("/oauth2/v2.0/token") {
                return axum::Json(json!({
                    "token_type": "Bearer",
                    "access_token": SENTINEL_APP_TOKEN,
                    "expires_in": 3600
                }))
                .into_response();
            }

            let bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
                .await
                .unwrap_or_default();
            let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

            captured
                .bodies
                .lock()
                .await
                .push((method.clone(), path.clone(), body));

            if method == "POST" && path == "/api/alerts/batchUpdate" {
                return axum::http::StatusCode::OK.into_response();
            }

            if method == "POST" && (path.contains("/comments") || path.ends_with("/comments")) {
                return (
                    axum::http::StatusCode::CREATED,
                    axum::Json(json!({
                        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#comments",
                        "value": [{
                            "comment": "test comment",
                            "createdDateTime": "2026-03-30T00:00:00Z"
                        }]
                    })),
                )
                    .into_response();
            }

            axum::Json(json!({
                "id": "mock-triage-id",
                "status": "Resolved"
            }))
            .into_response()
        }
    })
}

#[tokio::test]
async fn test_xdr_incident_update_keys_and_tags() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_incident_update",
            "id": "12345",
            "status": "resolved",
            "classification": "truePositive",
            "determination": "malware",
            "assigned_to": "analyst@example.com",
            "tags": ["apt-campaign", "ransomware"],
            "justification": "Valid triage justification for incident update"
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");

    // Assert no elicitation was recorded
    assert!(proc.recorded_elicitations().is_empty());

    mock.assert_hits("/security/incidents/12345", 1);

    let bodies = captured.bodies.lock().await;
    let incident_req = bodies
        .iter()
        .find(|(m, p, _)| m == "PATCH" && p == "/security/incidents/12345")
        .expect("PATCH /security/incidents/12345");
    let body = &incident_req.2;

    // Body should only contain supplied keys, and `tags` as `customTags`
    let obj = body.as_object().expect("body is object");
    assert_eq!(obj.len(), 5);
    assert_eq!(body["status"], json!("resolved"));
    assert_eq!(body["classification"], json!("truePositive"));
    assert_eq!(body["determination"], json!("malware"));
    assert_eq!(body["assignedTo"], json!("analyst@example.com"));
    assert_eq!(body["customTags"], json!(["apt-campaign", "ransomware"]));

    // Justification never appears in upstream body
    assert!(!body.to_string().contains("justification"));
    assert!(!body.to_string().contains("Valid triage justification"));

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_xdr_alert_update_camel_case_enums() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_alert_update",
            "id": "alert-99",
            "status": "inProgress",
            "classification": "falsePositive",
            "determination": "notMalicious",
            "assigned_to": "analyst2@example.com",
            "justification": "Valid triage justification for alert update"
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    assert!(proc.recorded_elicitations().is_empty());

    mock.assert_hits("/security/alerts_v2/alert-99", 1);

    let bodies = captured.bodies.lock().await;
    let alert_req = bodies
        .iter()
        .find(|(m, p, _)| m == "PATCH" && p == "/security/alerts_v2/alert-99")
        .expect("PATCH /security/alerts_v2/alert-99");
    let body = &alert_req.2;

    let obj = body.as_object().expect("body is object");
    assert_eq!(obj.len(), 4);
    assert_eq!(body["status"], json!("inProgress"));
    assert_eq!(body["classification"], json!("falsePositive"));
    assert_eq!(body["determination"], json!("notMalicious"));
    assert_eq!(body["assignedTo"], json!("analyst2@example.com"));

    // Justification never appears in upstream body
    assert!(!body.to_string().contains("justification"));
    assert!(!body.to_string().contains("Valid triage justification"));

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_xdr_comments_post_odata_type() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // 1. xdr_alert_comment
    let res_alert = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_alert_comment",
            "id": "alert-42",
            "comment": "Investigating suspicious beaconing",
            "justification": "Adding analyst comment during triage"
        }),
    );
    assert_ne!(res_alert["result"]["isError"], json!(true), "{res_alert:?}");
    assert!(proc.recorded_elicitations().is_empty());
    mock.assert_hits("/security/alerts_v2/alert-42/comments", 1);

    // 2. xdr_incident_comment
    let res_inc = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_incident_comment",
            "id": "inc-77",
            "comment": "Incident escalated to tier 3",
            "justification": "Escalation comment recorded"
        }),
    );
    assert_ne!(res_inc["result"]["isError"], json!(true), "{res_inc:?}");
    mock.assert_hits("/security/incidents/inc-77/comments", 1);

    let bodies = captured.bodies.lock().await;
    let alert_comment_req = bodies
        .iter()
        .find(|(m, p, _)| m == "POST" && p == "/security/alerts_v2/alert-42/comments")
        .expect("POST alert comment");
    assert_eq!(
        alert_comment_req.2,
        json!({
            "@odata.type": "microsoft.graph.security.alertComment",
            "comment": "Investigating suspicious beaconing"
        })
    );

    let inc_comment_req = bodies
        .iter()
        .find(|(m, p, _)| m == "POST" && p == "/security/incidents/inc-77/comments")
        .expect("POST incident comment");
    assert_eq!(
        inc_comment_req.2,
        json!({
            "@odata.type": "microsoft.graph.security.alertComment",
            "comment": "Incident escalated to tier 3"
        })
    );

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_endpoint_alert_update_pascal_case_and_spellings_with_inline_comment() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // Test notMalicious -> NotMalicious
    let res1 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "da637651030999999999",
            "status": "resolved",
            "classification": "falsePositive",
            "determination": "notMalicious",
            "assigned_to": "analyst@example.com",
            "comment": "Confirmed benign test file",
            "justification": "Closing false positive alert with comment"
        }),
    );
    assert_ne!(res1["result"]["isError"], json!(true), "{res1:?}");
    assert!(proc.recorded_elicitations().is_empty());
    mock.assert_hits("/api/alerts/da637651030999999999", 1);

    // Test confirmedActivity -> ConfirmedActivity
    let res2 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "da637651030999999998",
            "status": "resolved",
            "classification": "informationalExpectedActivity",
            "determination": "confirmedActivity",
            "justification": "Resolving expected activity alert"
        }),
    );
    assert_ne!(res2["result"]["isError"], json!(true), "{res2:?}");
    mock.assert_hits("/api/alerts/da637651030999999998", 1);

    let bodies = captured.bodies.lock().await;
    let req1 = bodies
        .iter()
        .find(|(m, p, _)| m == "PATCH" && p == "/api/alerts/da637651030999999999")
        .expect("PATCH da637651030999999999");
    assert_eq!(req1.2["status"], json!("Resolved"));
    assert_eq!(req1.2["classification"], json!("FalsePositive"));
    assert_eq!(req1.2["determination"], json!("NotMalicious"));
    assert_eq!(req1.2["assignedTo"], json!("analyst@example.com"));
    assert_eq!(req1.2["comment"], json!("Confirmed benign test file"));
    assert!(!req1.2.to_string().contains("justification"));

    let req2 = bodies
        .iter()
        .find(|(m, p, _)| m == "PATCH" && p == "/api/alerts/da637651030999999998")
        .expect("PATCH da637651030999999998");
    assert_eq!(req2.2["status"], json!("Resolved"));
    assert_eq!(
        req2.2["classification"],
        json!("InformationalExpectedActivity")
    );
    assert_eq!(req2.2["determination"], json!("ConfirmedActivity"));

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_endpoint_alert_comment_patch() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_comment",
            "id": "alert-c-1",
            "comment": "Adding an analyst comment via endpoint patch",
            "justification": "Comment recorded during endpoint triage"
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    assert!(proc.recorded_elicitations().is_empty());
    mock.assert_hits("/api/alerts/alert-c-1", 1);

    let bodies = captured.bodies.lock().await;
    let req = bodies
        .iter()
        .find(|(m, p, _)| m == "PATCH" && p == "/api/alerts/alert-c-1")
        .expect("PATCH /api/alerts/alert-c-1");
    assert_eq!(
        req.2,
        json!({
            "comment": "Adding an analyst comment via endpoint patch"
        })
    );

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_endpoint_alert_batch_update_spellings_and_result() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // 1. notMalicious -> Clean, status -> Resolved
    let res1 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_batch_update",
            "ids": ["alert-b1", "alert-b2"],
            "status": "resolved",
            "classification": "falsePositive",
            "determination": "notMalicious",
            "comment": "Batch resolving clean alerts",
            "justification": "Batch resolving clean alerts"
        }),
    );
    assert_ne!(res1["result"]["isError"], json!(true), "{res1:?}");
    assert_eq!(
        res1["result"]["structuredContent"],
        json!({ "status": "ok", "count": 2 })
    );
    assert!(proc.recorded_elicitations().is_empty());

    // 2. confirmedActivity -> ConfirmedUserActivity
    let res2 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_batch_update",
            "ids": ["alert-b3"],
            "status": "resolved",
            "classification": "informationalExpectedActivity",
            "determination": "confirmedActivity",
            "justification": "Batch resolving confirmed user activity"
        }),
    );
    assert_ne!(res2["result"]["isError"], json!(true), "{res2:?}");
    assert_eq!(
        res2["result"]["structuredContent"],
        json!({ "status": "ok", "count": 1 })
    );

    mock.assert_hits("/api/alerts/batchUpdate", 2);

    let bodies = captured.bodies.lock().await;
    let batch_reqs: Vec<_> = bodies
        .iter()
        .filter(|(m, p, _)| m == "POST" && p == "/api/alerts/batchUpdate")
        .collect();
    assert_eq!(batch_reqs.len(), 2);

    let b1 = &batch_reqs[0].2;
    assert_eq!(b1["alertIds"], json!(["alert-b1", "alert-b2"]));
    assert_eq!(b1["status"], json!("Resolved"));
    assert_eq!(b1["classification"], json!("FalsePositive"));
    assert_eq!(b1["determination"], json!("Clean"));
    assert_eq!(b1["comment"], json!("Batch resolving clean alerts"));
    assert!(!b1.to_string().contains("justification"));

    let b2 = &batch_reqs[1].2;
    assert_eq!(b2["alertIds"], json!(["alert-b3"]));
    assert_eq!(b2["status"], json!("Resolved"));
    assert_eq!(b2["classification"], json!("InformationalExpectedActivity"));
    assert_eq!(b2["determination"], json!("ConfirmedUserActivity"));

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_local_rejections_field_named_and_zero_hits() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // 1. falsePositive + malware -> rejected with determination naming and listing notMalicious, notEnoughDataToValidate, other
    let r1 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "a1",
            "classification": "falsePositive",
            "determination": "malware",
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r1["result"]["isError"], json!(true), "{r1:?}");
    let msg1 = r1["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg1.contains("determination"),
        "expected field named determination in: {msg1}"
    );
    assert!(
        msg1.contains("notMalicious"),
        "expected valid list in: {msg1}"
    );
    assert!(
        msg1.contains("notEnoughDataToValidate"),
        "expected valid list in: {msg1}"
    );
    assert!(msg1.contains("other"), "expected valid list in: {msg1}");

    // 2. determination without classification
    let r2 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "a2",
            "status": "inProgress",
            "determination": "malware",
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r2["result"]["isError"], json!(true), "{r2:?}");
    let msg2 = r2["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg2.contains("determination"),
        "expected determination in: {msg2}"
    );
    assert!(
        msg2.contains("classification"),
        "expected classification in: {msg2}"
    );

    // 3. status active on endpoint alert
    let r3 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "a3",
            "status": "active",
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r3["result"]["isError"], json!(true), "{r3:?}");
    let msg3 = r3["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(msg3.contains("status"), "expected status in: {msg3}");

    // 4. new on XDR incident
    let r4 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_incident_update",
            "id": "i4",
            "status": "new",
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r4["result"]["isError"], json!(true), "{r4:?}");
    let msg4 = r4["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(msg4.contains("status"), "expected status in: {msg4}");

    // 5. tags on an alert action
    let r5 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_alert_update",
            "id": "a5",
            "tags": ["tag1"],
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r5["result"]["isError"], json!(true), "{r5:?}");
    let msg5 = r5["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(msg5.contains("tags"), "expected tags in: {msg5}");

    // 6. comment on xdr_alert_update
    let r6 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_alert_update",
            "id": "a6",
            "status": "resolved",
            "comment": "comment not allowed on xdr_alert_update",
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r6["result"]["isError"], json!(true), "{r6:?}");
    let msg6 = r6["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(msg6.contains("comment"), "expected comment in: {msg6}");

    // 7. update with no change fields
    let r7 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "a7",
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r7["result"]["isError"], json!(true), "{r7:?}");
    let msg7 = r7["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(msg7.contains("update"), "expected update error in: {msg7}");

    // 8. assigned_to > 256 chars
    let long_assigned = "a".repeat(257);
    let r8 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "a8",
            "assigned_to": long_assigned,
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r8["result"]["isError"], json!(true), "{r8:?}");
    let msg8 = r8["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg8.contains("assigned_to"),
        "expected assigned_to in: {msg8}"
    );

    // 9. comment > 1000 chars
    let long_comment = "c".repeat(1001);
    let r9 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_comment",
            "id": "a9",
            "comment": long_comment,
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r9["result"]["isError"], json!(true), "{r9:?}");
    let msg9 = r9["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(msg9.contains("comment"), "expected comment in: {msg9}");

    // 10. 501 ids on batch update
    let ids_501: Vec<String> = (0..501).map(|i| format!("alert-{i}")).collect();
    let r10 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_batch_update",
            "ids": ids_501,
            "status": "resolved",
            "justification": "Triage reason long enough"
        }),
    );
    assert_eq!(r10["result"]["isError"], json!(true), "{r10:?}");
    let msg10 = r10["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(msg10.contains("ids"), "expected ids in: {msg10}");
    assert!(
        msg10.contains("server policy"),
        "expected server policy in: {msg10}"
    );

    // 11. justification < 10 chars
    let r11 = proc.call_tool(
        "defender_triage",
        json!({
            "action": "endpoint_alert_update",
            "id": "a11",
            "status": "resolved",
            "justification": "short"
        }),
    );
    assert_eq!(r11["result"]["isError"], json!(true), "{r11:?}");
    let msg11 = r11["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg11.contains("justification"),
        "expected justification in: {msg11}"
    );

    // Verify 0 upstream hits for all rejections
    assert_eq!(
        mock.total_hits(),
        0,
        "all rejections must produce 0 upstream hits"
    );

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_throttling_429_relayed_with_http_status_and_one_hit() {
    let app = axum::Router::new().fallback(|req: Request| async move {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        if method == "POST" && path.ends_with("/oauth2/v2.0/token") {
            return axum::Json(json!({
                "token_type": "Bearer",
                "access_token": SENTINEL_APP_TOKEN,
                "expires_in": 3600
            }))
            .into_response();
        }

        if path == "/security/incidents/inc-429" {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({
                    "error": {
                        "code": "ActivityLimitReached",
                        "message": "Rate limit exceeded"
                    }
                })),
            )
                .into_response();
        }

        axum::http::StatusCode::OK.into_response()
    });

    let mock = spawn_mock(app).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-triage"],
        &[
            ("GRAPH_BASE_URL", &mock.base_url),
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_triage",
        json!({
            "action": "xdr_incident_update",
            "id": "inc-429",
            "status": "resolved",
            "justification": "Closing incident after rate limit test"
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true), "{res:?}");
    let structured = &res["result"]["structuredContent"];
    assert_eq!(structured["httpStatus"], 429);
    mock.assert_hits("/security/incidents/inc-429", 1);

    assert!(proc.shutdown().success());
}
