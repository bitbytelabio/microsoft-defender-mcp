//! Device response tool integration tests (US1, US6, T020, T056, Q4, Q5).

mod common;

use axum::extract::Request;
use axum::response::IntoResponse;
use common::{ElicitationResponse, McpProcess, SENTINEL_APP_TOKEN, spawn_mock};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

const MACHINE: &str = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07";
const ACTION_ID: &str = "7327b54fd718525cbca07dacde913b5ac3c85673";
const COMMENT: &str = "Device containment investigation";

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

            // Return mock MachineAction, Investigation, or Machine based on endpoint
            if path.contains("/startInvestigation") {
                axum::Json(json!({
                    "id": "inv-998877",
                    "state": "Running",
                    "machineId": MACHINE
                }))
                .into_response()
            } else if path.contains("/tags") || path.contains("/setDeviceValue") {
                axum::Json(json!({
                    "id": MACHINE,
                    "computerDnsName": "test-box.corp",
                    "deviceValue": "High"
                }))
                .into_response()
            } else if path.contains("/machineactions/") {
                axum::Json(json!({
                    "id": ACTION_ID,
                    "status": "Cancelled",
                    "type": "Isolate"
                }))
                .into_response()
            } else {
                axum::Json(json!({
                    "id": ACTION_ID,
                    "status": "Pending",
                    "type": "Isolate"
                }))
                .into_response()
            }
        }
    })
}

// -----------------------------------------------------------------------------
// US1: Isolate (default Full), poll_with, and forensics polling (Q4, T020)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_isolate_default_full_and_poll() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    let struct_content = &res["result"]["structuredContent"];
    assert_eq!(struct_content["machineAction"]["id"], ACTION_ID);
    assert_eq!(
        struct_content["poll_with"],
        json!({
            "tool": "defender_forensics",
            "action": "machine_action_get_status",
            "action_id": ACTION_ID
        })
    );

    // Assert mock hit and body
    mock.assert_hits(&format!("/api/machines/{MACHINE}/isolate"), 1);
    {
        let bodies = captured.bodies.lock().await;
        let isolate_req = bodies
            .iter()
            .find(|(m, p, _)| m == "POST" && p == &format!("/api/machines/{MACHINE}/isolate"))
            .expect("isolate request recorded");
        assert_eq!(
            isolate_req.2,
            json!({
                "Comment": COMMENT,
                "IsolationType": "Full"
            })
        );
    }
    // Elicitation assertion
    let elicitations = proc.recorded_elicitations();
    assert_eq!(elicitations.len(), 1);
    assert!(elicitations[0].contains("Tool:    defender_device_response"));
    assert!(elicitations[0].contains("Action:  isolate"));

    // Poll status via defender_forensics machine_action_get_status
    let poll_res = proc.call_tool(
        "defender_forensics",
        json!({
            "action": "machine_action_get_status",
            "action_id": ACTION_ID,
        }),
    );
    assert_ne!(poll_res["result"]["isError"], json!(true), "{poll_res:?}");
    assert_eq!(
        poll_res["result"]["structuredContent"]["status"],
        json!("Cancelled")
    );

    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_unisolate_and_poll() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "unisolate",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    let struct_content = &res["result"]["structuredContent"];
    assert_eq!(struct_content["machineAction"]["id"], ACTION_ID);
    assert_eq!(
        struct_content["poll_with"],
        json!({
            "tool": "defender_forensics",
            "action": "machine_action_get_status",
            "action_id": ACTION_ID
        })
    );

    mock.assert_hits(&format!("/api/machines/{MACHINE}/unisolate"), 1);
    {
        let bodies = captured.bodies.lock().await;
        let req = bodies
            .iter()
            .find(|(m, p, _)| m == "POST" && p == &format!("/api/machines/{MACHINE}/unisolate"))
            .expect("unisolate request recorded");
        assert_eq!(req.2, json!({ "Comment": COMMENT }));
    }

    assert_eq!(proc.recorded_elicitations().len(), 1);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_isolate_selective_and_unmanaged_device() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // Selective
    let res_sel = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "isolation_type": "Selective",
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_sel["result"]["isError"], json!(true), "{res_sel:?}");

    // UnManagedDevice
    let res_unm = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "isolation_type": "UnManagedDevice",
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_unm["result"]["isError"], json!(true), "{res_unm:?}");

    mock.assert_hits(&format!("/api/machines/{MACHINE}/isolate"), 2);
    {
        let bodies = captured.bodies.lock().await;
        let isolate_reqs: Vec<_> = bodies
            .iter()
            .filter(|(m, p, _)| m == "POST" && p == &format!("/api/machines/{MACHINE}/isolate"))
            .collect();
        assert_eq!(isolate_reqs.len(), 2);
        assert_eq!(
            isolate_reqs[0].2,
            json!({ "Comment": COMMENT, "IsolationType": "Selective" })
        );
        assert_eq!(
            isolate_reqs[1].2,
            json!({ "Comment": COMMENT, "IsolationType": "UnManagedDevice" })
        );
    }

    assert_eq!(proc.recorded_elicitations().len(), 2);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_restrict_and_unrestrict_app_execution() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res_res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "restrict_app_execution",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_res["result"]["isError"], json!(true), "{res_res:?}");

    let res_unres = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "unrestrict_app_execution",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_unres["result"]["isError"], json!(true), "{res_unres:?}");

    mock.assert_hits(&format!("/api/machines/{MACHINE}/restrictCodeExecution"), 1);
    mock.assert_hits(
        &format!("/api/machines/{MACHINE}/unrestrictCodeExecution"),
        1,
    );

    {
        let bodies = captured.bodies.lock().await;
        let r_req = bodies
            .iter()
            .find(|(m, p, _)| {
                m == "POST" && p == &format!("/api/machines/{MACHINE}/restrictCodeExecution")
            })
            .expect("restrictCodeExecution hit");
        assert_eq!(r_req.2, json!({ "Comment": COMMENT }));
        let u_req = bodies
            .iter()
            .find(|(m, p, _)| {
                m == "POST" && p == &format!("/api/machines/{MACHINE}/unrestrictCodeExecution")
            })
            .expect("unrestrictCodeExecution hit");
        assert_eq!(u_req.2, json!({ "Comment": COMMENT }));
    }

    assert_eq!(proc.recorded_elicitations().len(), 2);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_run_av_scan_quick_and_full() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res_quick = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "run_av_scan",
            "machine_id": MACHINE,
            "scan_type": "Quick",
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_quick["result"]["isError"], json!(true), "{res_quick:?}");

    let res_full = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "run_av_scan",
            "machine_id": MACHINE,
            "scan_type": "Full",
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_full["result"]["isError"], json!(true), "{res_full:?}");

    mock.assert_hits(&format!("/api/machines/{MACHINE}/runAntiVirusScan"), 2);

    {
        let bodies = captured.bodies.lock().await;
        let scans: Vec<_> = bodies
            .iter()
            .filter(|(m, p, _)| {
                m == "POST" && p == &format!("/api/machines/{MACHINE}/runAntiVirusScan")
            })
            .collect();
        assert_eq!(scans.len(), 2);
        assert_eq!(
            scans[0].2,
            json!({ "Comment": COMMENT, "ScanType": "Quick" })
        );
        assert_eq!(
            scans[1].2,
            json!({ "Comment": COMMENT, "ScanType": "Full" })
        );
    }

    assert_eq!(proc.recorded_elicitations().len(), 2);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_cancel_machine_action() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "cancel_machine_action",
            "action_id": ACTION_ID,
            "comment": COMMENT,
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");

    mock.assert_hits(&format!("/api/machineactions/{ACTION_ID}/cancel"), 1);

    {
        let bodies = captured.bodies.lock().await;
        let req = bodies
            .iter()
            .find(|(m, p, _)| {
                m == "POST" && p == &format!("/api/machineactions/{ACTION_ID}/cancel")
            })
            .expect("cancel request recorded");
        assert_eq!(req.2, json!({ "Comment": COMMENT }));
    }

    assert_eq!(proc.recorded_elicitations().len(), 1);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_400_active_request_already_exists_relayed_with_one_hit() {
    // Mock returns 400 ActiveRequestAlreadyExists on isolate
    let captured = CapturedRequests::default();
    let captured_clone = captured.clone();
    let app = axum::Router::new().fallback(move |req: Request| {
        let captured = captured_clone.clone();
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
            captured.bodies.lock().await.push((method, path, json!({})));
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "error": {
                        "code": "ActiveRequestAlreadyExists",
                        "message": "There is already an active action on machine"
                    }
                })),
            )
                .into_response()
        }
    });
    let mock = spawn_mock(app).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true), "{res:?}");
    let structured = &res["result"]["structuredContent"];
    assert_eq!(structured["httpStatus"], json!(400));

    // Exactly 1 hit (no retries)
    mock.assert_hits(&format!("/api/machines/{MACHINE}/isolate"), 1);
    assert_eq!(proc.recorded_elicitations().len(), 1);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_declined_prompt_zero_hits() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::Decline,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );

    assert_eq!(res["result"]["isError"], json!(true), "{res:?}");
    assert_eq!(
        res["result"]["structuredContent"]["code"],
        json!("not_confirmed")
    );

    // Mock saw 0 hits
    assert_eq!(mock.total_hits(), 0);
    assert_eq!(proc.recorded_elicitations().len(), 1);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_local_rejections_name_field_and_zero_hits() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // 1. Non-40-hex machine_id
    let res_bad_mid = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": "not-a-40-hex-string",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_bad_mid["result"]["isError"], json!(true));
    let err_str = res_bad_mid.to_string();
    assert!(
        err_str.contains("machine_id"),
        "error must name machine_id: {err_str}"
    );

    // 2. Comment shorter than 10 characters
    let res_short_cmt = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "comment": "short",
        }),
    );
    assert_eq!(res_short_cmt["result"]["isError"], json!(true));
    let err_str = res_short_cmt.to_string();
    assert!(
        err_str.contains("comment"),
        "error must name comment: {err_str}"
    );

    // 3. Unknown isolation_type (deserialization rejection names isolation_type)
    let res_bad_iso = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "isolation_type": "SuperFull",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_bad_iso["result"]["isError"], json!(true));
    let err_str = res_bad_iso.to_string();
    assert!(
        err_str.contains("isolation_type"),
        "error must name isolation_type: {err_str}"
    );

    // 4. Field unused by action (for example scan_type on isolate)
    let res_unused = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "isolate",
            "machine_id": MACHINE,
            "scan_type": "Quick",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_unused["result"]["isError"], json!(true));
    let err_str = res_unused.to_string();
    assert!(
        err_str.contains("scan_type"),
        "error must name scan_type: {err_str}"
    );

    // 5. run_av_scan requires scan_type
    let res_no_scan = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "run_av_scan",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_no_scan["result"]["isError"], json!(true));
    let err_str = res_no_scan.to_string();
    assert!(
        err_str.contains("scan_type"),
        "error must name scan_type: {err_str}"
    );

    // Zero hits across all local rejections
    assert_eq!(mock.total_hits(), 0);
    // No elicitation prompts were triggered for local rejections
    assert_eq!(proc.recorded_elicitations().len(), 0);
    assert!(proc.shutdown().success());
}

// -----------------------------------------------------------------------------
// US6: Investigation automation and device lifecycle (T056, Q5)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_start_investigation() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "start_investigation",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    let struct_content = &res["result"]["structuredContent"];
    assert_eq!(struct_content["investigation"]["id"], "inv-998877");
    assert_eq!(
        struct_content["poll_with"],
        json!({
            "tool": "defender_forensics",
            "action": "investigation_get",
            "investigation_id": "inv-998877"
        })
    );

    mock.assert_hits(&format!("/api/machines/{MACHINE}/startInvestigation"), 1);
    {
        let bodies = captured.bodies.lock().await;
        let req = bodies
            .iter()
            .find(|(m, p, _)| {
                m == "POST" && p == &format!("/api/machines/{MACHINE}/startInvestigation")
            })
            .expect("startInvestigation hit");
        assert_eq!(req.2, json!({ "Comment": COMMENT }));
    }

    assert_eq!(proc.recorded_elicitations().len(), 1);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_tag_add_and_remove() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res_add = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "tag_add",
            "machine_id": MACHINE,
            "tag": "isolated-compromised",
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_add["result"]["isError"], json!(true), "{res_add:?}");

    let res_rem = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "tag_remove",
            "machine_id": MACHINE,
            "tag": "isolated-compromised",
            "comment": COMMENT,
        }),
    );
    assert_ne!(res_rem["result"]["isError"], json!(true), "{res_rem:?}");

    // Tags returns Machine object unchanged
    assert_eq!(res_add["result"]["structuredContent"]["id"], MACHINE);
    assert_eq!(res_rem["result"]["structuredContent"]["id"], MACHINE);

    mock.assert_hits(&format!("/api/machines/{MACHINE}/tags"), 2);
    {
        let bodies = captured.bodies.lock().await;
        let tags: Vec<_> = bodies
            .iter()
            .filter(|(m, p, _)| m == "POST" && p == &format!("/api/machines/{MACHINE}/tags"))
            .collect();
        assert_eq!(tags.len(), 2);
        // Must send Value and Action: Add|Remove with no Comment
        assert_eq!(
            tags[0].2,
            json!({ "Value": "isolated-compromised", "Action": "Add" })
        );
        assert_eq!(
            tags[1].2,
            json!({ "Value": "isolated-compromised", "Action": "Remove" })
        );
        assert!(!tags[0].2.to_string().contains("Comment"));
        assert!(!tags[1].2.to_string().contains("Comment"));
    }

    // Short justification still rejected with 0 hits
    let res_short = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "tag_add",
            "machine_id": MACHINE,
            "tag": "isolated-compromised",
            "comment": "short",
        }),
    );
    assert_eq!(res_short["result"]["isError"], json!(true));
    assert!(res_short.to_string().contains("comment"));
    mock.assert_hits(&format!("/api/machines/{MACHINE}/tags"), 2);

    assert_eq!(proc.recorded_elicitations().len(), 2);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_set_device_value() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "set_device_value",
            "machine_id": MACHINE,
            "device_value": "High",
            "comment": COMMENT,
        }),
    );
    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    assert_eq!(res["result"]["structuredContent"]["id"], MACHINE);

    mock.assert_hits(&format!("/api/machines/{MACHINE}/setDeviceValue"), 1);
    {
        let bodies = captured.bodies.lock().await;
        let req = bodies
            .iter()
            .find(|(m, p, _)| {
                m == "POST" && p == &format!("/api/machines/{MACHINE}/setDeviceValue")
            })
            .expect("setDeviceValue hit");
        // Must send DeviceValue with no Comment
        assert_eq!(req.2, json!({ "DeviceValue": "High" }));
        assert!(!req.2.to_string().contains("Comment"));
    }

    assert_eq!(proc.recorded_elicitations().len(), 1);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_lifecycle_local_rejections_and_zero_hits() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    // 1. Empty tag
    let res_empty_tag = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "tag_add",
            "machine_id": MACHINE,
            "tag": "",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_empty_tag["result"]["isError"], json!(true));
    assert!(res_empty_tag.to_string().contains("tag"));

    // 2. Tag > 200 chars
    let long_tag = "a".repeat(201);
    let res_long_tag = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "tag_add",
            "machine_id": MACHINE,
            "tag": long_tag,
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_long_tag["result"]["isError"], json!(true));
    assert!(res_long_tag.to_string().contains("tag"));

    // 3. Tag with control character
    let res_ctrl_tag = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "tag_add",
            "machine_id": MACHINE,
            "tag": "bad\ntag",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_ctrl_tag["result"]["isError"], json!(true));
    assert!(res_ctrl_tag.to_string().contains("tag"));

    // 4. device_value: "Critical" (only Low, Normal, High accepted)
    let res_crit = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "set_device_value",
            "machine_id": MACHINE,
            "device_value": "Critical",
            "comment": COMMENT,
        }),
    );
    assert_eq!(res_crit["result"]["isError"], json!(true));

    assert_eq!(mock.total_hits(), 0);
    assert_eq!(proc.recorded_elicitations().len(), 0);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_offboard_without_enable_offboarding_rejected_with_zero_hits() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    // Start only with --enable-device-response, without --enable-offboarding
    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "offboard",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );

    assert_eq!(res["error"]["code"], json!(-32602), "{res:?}");
    let err_str = res["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err_str.contains("Unknown action 'offboard'"),
        "must report unknown action: {err_str}"
    );
    assert!(
        err_str.contains("offboard requires --enable-offboarding"),
        "must hint offboard requires --enable-offboarding: {err_str}"
    );

    assert_eq!(mock.total_hits(), 0);
    assert_eq!(proc.recorded_elicitations().len(), 0);
    assert!(proc.shutdown().success());
}

#[tokio::test]
async fn test_offboard_with_enable_offboarding_returns_warning_and_poll() {
    let captured = CapturedRequests::default();
    let mock = spawn_mock(create_upstream_app(captured.clone())).await;

    let mut proc = McpProcess::initialize_with_elicitation(
        &["--enable-device-response", "--enable-offboarding"],
        &[
            ("DEFENDER_ENDPOINT_BASE_URL", &mock.base_url),
            ("DEFENDER_AUTHORITY_BASE_URL", &mock.base_url),
        ],
        ElicitationResponse::AcceptConfirm,
    );

    let res = proc.call_tool(
        "defender_device_response",
        json!({
            "action": "offboard",
            "machine_id": MACHINE,
            "comment": COMMENT,
        }),
    );

    assert_ne!(res["result"]["isError"], json!(true), "{res:?}");
    let struct_content = &res["result"]["structuredContent"];
    assert_eq!(struct_content["machineAction"]["id"], ACTION_ID);
    assert_eq!(
        struct_content["poll_with"],
        json!({
            "tool": "defender_forensics",
            "action": "machine_action_get_status",
            "action_id": ACTION_ID
        })
    );
    let expected_warning = "Offboarding cannot be undone remotely; the device stops reporting until re-onboarded. On Windows the API stops the sensor service but does not remove onboarding registry data.";
    assert_eq!(struct_content["warning"], json!(expected_warning));

    mock.assert_hits(&format!("/api/machines/{MACHINE}/offboard"), 1);
    {
        let bodies = captured.bodies.lock().await;
        let req = bodies
            .iter()
            .find(|(m, p, _)| m == "POST" && p == &format!("/api/machines/{MACHINE}/offboard"))
            .expect("offboard hit");
        assert_eq!(req.2, json!({ "Comment": COMMENT }));
    }

    assert_eq!(proc.recorded_elicitations().len(), 1);
    assert!(proc.shutdown().success());
}
