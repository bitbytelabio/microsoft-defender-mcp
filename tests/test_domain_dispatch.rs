//! Domain dispatchers route each action to its upstream API with the action's validation rules.

mod common;

use axum::{
    Json, Router,
    extract::{Query, Request},
    http::StatusCode,
    routing::{get, post},
};
use common::{McpProcess, base_config, spawn_mock as spawn_test_server, test_server};
use microsoft_defender_mcp_server::cli::{MutationCategories, ServerConfig};
use microsoft_defender_mcp_server::server::{
    DefenderServer, FORENSICS_ACTIONS, ForensicsInput, HuntingInput, INCIDENTS_ALERTS_ACTIONS,
    IncidentsAlertsInput, MACHINES_ACTIONS, MachinesInput, RESPONSE_ACTIONS, TI_ACTIONS,
    ThreatIntelInput, VULNERABILITIES_ACTIONS, VulnerabilitiesInput,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ErrorCode};
use serde_json::json;
use std::collections::HashMap;

/// Server with Live Response enabled so every action is reachable.
fn create_test_server(base_url: &str) -> DefenderServer {
    test_server(
        base_url,
        ServerConfig {
            categories: MutationCategories {
                live_response: true,
                ..MutationCategories::default()
            },
            ..base_config()
        },
    )
}

fn structured(res: CallToolResult) -> serde_json::Value {
    assert_ne!(res.is_error, Some(true), "unexpected tool error: {res:?}");
    res.structured_content.expect("structured content")
}

#[tokio::test]
async fn test_defender_hunting_parametric_dispatch() {
    let app = Router::new().route(
        "/security/runHuntingQuery",
        post(|Json(body): Json<serde_json::Value>| async move {
            assert_eq!(body["Query"], "DeviceProcessEvents | take 5");
            assert_eq!(body["Timespan"], "P7D");
            Json(json!({ "results": [{ "FileName": "powershell.exe" }] }))
        }),
    );
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    let res = server
        .defender_hunting(Parameters(HuntingInput {
            action: "run".to_string(),
            query: "DeviceProcessEvents | take 5".to_string(),
            timespan: Some("P7D".to_string()),
        }))
        .await
        .expect("hunting query succeeded");

    assert_eq!(structured(res)["results"][0]["FileName"], "powershell.exe");
}

#[tokio::test]
async fn test_defender_hunting_defaults_timespan_to_p30d() {
    let app = Router::new().route(
        "/security/runHuntingQuery",
        post(|Json(body): Json<serde_json::Value>| async move { Json(body) }),
    );
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    let res = server
        .defender_hunting(Parameters(HuntingInput {
            action: "run".to_string(),
            query: "DeviceInfo | take 1".to_string(),
            timespan: None,
        }))
        .await
        .expect("hunting query succeeded");

    assert_eq!(structured(res)["Timespan"], "P30D");
}

#[tokio::test]
async fn test_defender_ti_host_reputation_dispatch() {
    let app = Router::new().route(
        "/security/threatIntelligence/hosts/contoso.com/reputation",
        get(|| async { Json(json!({ "score": 85, "classification": "suspicious" })) }),
    );
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    let res = server
        .defender_ti(Parameters(ThreatIntelInput {
            action: "host_reputation_get".to_string(),
            hostname: Some("contoso.com".to_string()),
            ..Default::default()
        }))
        .await
        .expect("ti query succeeded");

    assert_eq!(structured(res)["score"], 85);
}

#[tokio::test]
async fn test_defender_ti_vulnerability_maps_id_to_cve() {
    let app = Router::new().route(
        "/security/threatIntelligence/vulnerabilities/CVE-2021-44228",
        get(|| async { Json(json!({ "id": "CVE-2021-44228" })) }),
    );
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    let res = server
        .defender_ti(Parameters(ThreatIntelInput {
            action: "vulnerability_get".to_string(),
            id: Some("CVE-2021-44228".to_string()),
            ..Default::default()
        }))
        .await
        .expect("vulnerability lookup succeeded");

    assert_eq!(structured(res)["id"], "CVE-2021-44228");
}

#[tokio::test]
async fn test_defender_incidents_alerts_preserves_odata_count() {
    let app = Router::new().route(
        "/security/alerts_v2",
        get(|Query(query): Query<HashMap<String, String>>| async move {
            assert_eq!(query.get("$count").map(String::as_str), Some("true"));
            assert_eq!(query.get("$top").map(String::as_str), Some("10"));
            Json(json!({ "@odata.count": 1, "value": [{ "id": "alert-123" }] }))
        }),
    );
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    let res = server
        .defender_incidents_alerts(Parameters(IncidentsAlertsInput {
            action: "xdr_alert_list".to_string(),
            top: Some(10),
            count: Some(true),
            ..Default::default()
        }))
        .await
        .expect("alert list succeeded");

    let val = structured(res);
    assert_eq!(val["value"][0]["id"], "alert-123");
    assert_eq!(val["@odata.count"], 1);
}

#[tokio::test]
async fn test_defender_incidents_alerts_ip_related_validates_ip_before_network() {
    let guard = spawn_test_server(Router::new()).await;
    let server = create_test_server(&guard.base_url);

    let err = server
        .defender_incidents_alerts(Parameters(IncidentsAlertsInput {
            action: "ip_related_alerts".to_string(),
            id: Some("999.999.999.999".to_string()),
            ..Default::default()
        }))
        .await
        .expect_err("invalid IP must be rejected");

    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("ip_address"), "{}", err.message);
}

#[tokio::test]
async fn test_defender_machines_machine_get_dispatch() {
    let app = Router::new().route(
        "/api/machines/1e5bc9d7e413ddd7902c2932e418702b84d0cc07",
        get(|| async { Json(json!({ "computerDnsName": "laptop-01" })) }),
    );
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    let res = server
        .defender_machines(Parameters(MachinesInput {
            action: "machine_get".to_string(),
            machine_id: Some("1e5bc9d7e413ddd7902c2932e418702b84d0cc07".to_string()),
            ..Default::default()
        }))
        .await
        .expect("machine get succeeded");

    assert_eq!(structured(res)["computerDnsName"], "laptop-01");
}

#[tokio::test]
async fn test_defender_vulnerabilities_get_by_cve_dispatch() {
    let app = Router::new().route(
        "/api/vulnerabilities/CVE-2024-1234",
        get(|| async { Json(json!({ "severity": "High" })) }),
    );
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    let res = server
        .defender_vulnerabilities(Parameters(VulnerabilitiesInput {
            action: "vulnerability_get_by_cve".to_string(),
            id: Some("CVE-2024-1234".to_string()),
            ..Default::default()
        }))
        .await
        .expect("vulnerability get succeeded");

    assert_eq!(structured(res)["severity"], "High");
}

#[tokio::test]
async fn test_unsupported_field_for_action_is_rejected() {
    let guard = spawn_test_server(Router::new()).await;
    let server = create_test_server(&guard.base_url);

    // article_indicators_list does not support $filter; it must not be silently dropped.
    let err = server
        .defender_ti(Parameters(ThreatIntelInput {
            action: "article_indicators_list".to_string(),
            id: Some("a272d5ab".to_string()),
            filter: Some("x eq 1".to_string()),
            ..Default::default()
        }))
        .await
        .expect_err("unsupported field must be rejected");

    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("filter"), "{}", err.message);
}

#[tokio::test]
async fn test_unknown_action_returns_invalid_params_listing_valid_actions() {
    let guard = spawn_test_server(Router::new()).await;
    let server = create_test_server(&guard.base_url);

    let err = server
        .defender_machines(Parameters(MachinesInput {
            action: "machine_isolate".to_string(),
            ..Default::default()
        }))
        .await
        .expect_err("unknown action must be rejected");

    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(err.message.contains("Unknown action 'machine_isolate'"));
    assert!(err.message.contains("machine_list"));
}

/// Every action advertised in a dispatcher's catalog must be routed (never "Unknown action").
#[tokio::test]
async fn test_every_catalog_action_is_routed() {
    let app = Router::new().fallback(|_req: Request| async { (StatusCode::OK, Json(json!({}))) });
    let guard = spawn_test_server(app).await;
    let server = create_test_server(&guard.base_url);

    fn assert_routed(tool: &str, action: &str, result: Result<CallToolResult, rmcp::ErrorData>) {
        if let Err(e) = result {
            assert!(
                !e.message.contains("Unknown action"),
                "{tool} action '{action}' is advertised but not routed"
            );
        }
    }

    for action in TI_ACTIONS {
        let input = ThreatIntelInput {
            action: action.to_string(),
            ..Default::default()
        };
        assert_routed(
            "defender_ti",
            action,
            server.defender_ti(Parameters(input)).await,
        );
    }
    for action in INCIDENTS_ALERTS_ACTIONS {
        let input = IncidentsAlertsInput {
            action: action.to_string(),
            ..Default::default()
        };
        let res = server.defender_incidents_alerts(Parameters(input)).await;
        assert_routed("defender_incidents_alerts", action, res);
    }
    for action in MACHINES_ACTIONS {
        let input = MachinesInput {
            action: action.to_string(),
            ..Default::default()
        };
        let res = server.defender_machines(Parameters(input)).await;
        assert_routed("defender_machines", action, res);
    }
    for action in VULNERABILITIES_ACTIONS {
        let input = VulnerabilitiesInput {
            action: action.to_string(),
            ..Default::default()
        };
        let res = server.defender_vulnerabilities(Parameters(input)).await;
        assert_routed("defender_vulnerabilities", action, res);
    }
    for action in FORENSICS_ACTIONS {
        let input = ForensicsInput {
            action: action.to_string(),
            ..Default::default()
        };
        let res = server.defender_forensics(Parameters(input)).await;
        assert_routed("defender_forensics", action, res);
    }
    let mut proc = common::McpProcess::start_with_elicitation(&["--enable-live-response"], &[]);
    for action in RESPONSE_ACTIONS {
        let res = proc.call_tool("defender_response", json!({ "action": action }));
        let err_str = res.to_string();
        assert!(
            !err_str.contains("Unknown action"),
            "defender_response action '{action}' is advertised but not routed: {err_str}"
        );
    }
    assert!(proc.shutdown().success());
}

// =========================================================================
// T050: pivots_ tests (US5, quickstart Q11)
// =========================================================================

#[tokio::test]
async fn pivots_find_by_ip_sends_path_and_normalizes_timestamp() {
    let now = chrono::Utc::now();
    let input_dt = now - chrono::Duration::days(5);
    let input_ts = input_dt.to_rfc3339();
    let expected_utc_ts = input_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let expected_path =
        format!("/api/machines/findbyip(ip='10.1.2.3',timestamp={expected_utc_ts})");

    let app = Router::new().fallback(|_: Request| async move {
        (
            StatusCode::OK,
            Json(json!({ "value": [{ "id": "m-123", "ip": "10.1.2.3" }] })),
        )
    });
    let guard = spawn_test_server(app).await;
    let server = test_server(
        &guard.base_url,
        ServerConfig {
            read_only: true,
            ..base_config()
        },
    );

    let res = server
        .defender_machines(Parameters(MachinesInput {
            action: "find_by_ip".to_string(),
            id: Some("10.1.2.3".to_string()),
            timestamp: Some(input_ts),
            ..Default::default()
        }))
        .await
        .expect("find_by_ip succeeds under read_only");

    let val = structured(res);
    assert_eq!(val["value"][0]["id"], "m-123");
    guard.assert_hits(&expected_path, 1);
}

#[tokio::test]
async fn pivots_find_by_ip_local_rejections() {
    let app = Router::new().fallback(|_req: Request| async { (StatusCode::OK, Json(json!({}))) });
    let guard = spawn_test_server(app).await;
    let server = test_server(
        &guard.base_url,
        ServerConfig {
            read_only: true,
            ..base_config()
        },
    );

    // 1. Timestamp 31 days old
    let old_ts = (chrono::Utc::now() - chrono::Duration::days(31)).to_rfc3339();
    let err_old = server
        .defender_machines(Parameters(MachinesInput {
            action: "find_by_ip".to_string(),
            id: Some("10.1.2.3".to_string()),
            timestamp: Some(old_ts),
            ..Default::default()
        }))
        .await
        .expect_err("31-day-old timestamp must be rejected");
    assert_eq!(err_old.code, ErrorCode::INVALID_PARAMS);
    assert!(err_old.message.contains("timestamp"));

    // 2. Future timestamp
    let future_ts = (chrono::Utc::now() + chrono::Duration::days(2)).to_rfc3339();
    let err_future = server
        .defender_machines(Parameters(MachinesInput {
            action: "find_by_ip".to_string(),
            id: Some("10.1.2.3".to_string()),
            timestamp: Some(future_ts),
            ..Default::default()
        }))
        .await
        .expect_err("future timestamp must be rejected");
    assert_eq!(err_future.code, ErrorCode::INVALID_PARAMS);
    assert!(err_future.message.contains("timestamp"));

    // 3. Invalid IP
    let valid_ts = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
    let err_ip = server
        .defender_machines(Parameters(MachinesInput {
            action: "find_by_ip".to_string(),
            id: Some("999.999.999.999".to_string()),
            timestamp: Some(valid_ts),
            ..Default::default()
        }))
        .await
        .expect_err("invalid IP must be rejected");
    assert_eq!(err_ip.code, ErrorCode::INVALID_PARAMS);

    // 0 hits
    assert_eq!(
        guard.total_hits(),
        0,
        "rejected calls must produce 0 upstream hits"
    );
}

#[tokio::test]
async fn pivots_read_actions_hit_path_under_read_only() {
    let machine_id = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07";
    let seen_queries =
        std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::<String, String>::new()));
    let seen_queries_clone = seen_queries.clone();

    let app = Router::new().fallback(move |req: Request| {
        let seen = seen_queries_clone.clone();
        async move {
            let path = req.uri().path().to_string();
            let query = req.uri().query().unwrap_or_default().to_string();
            seen.lock().await.insert(path, query);
            (
                StatusCode::OK,
                Json(json!({ "value": [{ "status": "ok" }] })),
            )
        }
    });
    let guard = spawn_test_server(app).await;
    let server = test_server(
        &guard.base_url,
        ServerConfig {
            read_only: true,
            ..base_config()
        },
    );

    // machine_alerts
    let res_alerts = server
        .defender_machines(Parameters(MachinesInput {
            action: "machine_alerts".to_string(),
            machine_id: Some(machine_id.to_string()),
            ..Default::default()
        }))
        .await
        .expect("machine_alerts succeeds under read_only");
    assert_ne!(res_alerts.is_error, Some(true));
    guard.assert_hits(&format!("/api/machines/{machine_id}/alerts"), 1);

    // machine_vulnerabilities (with top, skip, filter)
    let res_vulns = server
        .defender_machines(Parameters(MachinesInput {
            action: "machine_vulnerabilities".to_string(),
            machine_id: Some(machine_id.to_string()),
            top: Some(10),
            skip: Some(20),
            filter: Some("severity eq 'High'".to_string()),
            ..Default::default()
        }))
        .await
        .expect("machine_vulnerabilities succeeds under read_only");
    assert_ne!(res_vulns.is_error, Some(true));
    let vulns_path = format!("/api/machines/{machine_id}/vulnerabilities");
    guard.assert_hits(&vulns_path, 1);
    {
        let q = seen_queries
            .lock()
            .await
            .get(&vulns_path)
            .cloned()
            .unwrap_or_default();
        assert!(q.contains("%24top=10") || q.contains("$top=10"));
        assert!(q.contains("%24skip=20") || q.contains("$skip=20"));
        assert!(q.contains("severity"));
    }

    // machine_missing_kbs
    let res_kbs = server
        .defender_machines(Parameters(MachinesInput {
            action: "machine_missing_kbs".to_string(),
            machine_id: Some(machine_id.to_string()),
            ..Default::default()
        }))
        .await
        .expect("machine_missing_kbs succeeds under read_only");
    assert_ne!(res_kbs.is_error, Some(true));
    guard.assert_hits(&format!("/api/machines/{machine_id}/getmissingkbs"), 1);

    // investigation_list (with top, skip, filter)
    let res_inv_list = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "investigation_list".to_string(),
            top: Some(5),
            skip: Some(15),
            filter: Some("status eq 'Running'".to_string()),
            ..Default::default()
        }))
        .await
        .expect("investigation_list succeeds under read_only");
    assert_ne!(res_inv_list.is_error, Some(true));
    guard.assert_hits("/api/investigations", 1);
    {
        let q = seen_queries
            .lock()
            .await
            .get("/api/investigations")
            .cloned()
            .unwrap_or_default();
        assert!(q.contains("%24top=5") || q.contains("$top=5"));
        assert!(q.contains("%24skip=15") || q.contains("$skip=15"));
        assert!(q.contains("Running"));
    }

    // investigation_get (an ID containing '/' and '=' is percent-encoded into one segment)
    let res_inv_get = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "investigation_get".to_string(),
            investigation_id: Some("inv/123=abc".to_string()),
            ..Default::default()
        }))
        .await
        .expect("investigation_get succeeds under read_only");
    assert_ne!(res_inv_get.is_error, Some(true));
    guard.assert_hits("/api/investigations/inv%2F123%3Dabc", 1);

    // library_file_list
    let res_lib = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "library_file_list".to_string(),
            ..Default::default()
        }))
        .await
        .expect("library_file_list succeeds under read_only");
    assert_ne!(res_lib.is_error, Some(true));
    guard.assert_hits("/api/libraryfiles", 1);
}

#[tokio::test]
async fn pivots_library_file_list_rejects_any_field() {
    let app = Router::new().fallback(|_req: Request| async { (StatusCode::OK, Json(json!({}))) });
    let guard = spawn_test_server(app).await;
    let server = test_server(
        &guard.base_url,
        ServerConfig {
            read_only: true,
            ..base_config()
        },
    );

    let err1 = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "library_file_list".to_string(),
            top: Some(10),
            ..Default::default()
        }))
        .await
        .expect_err("library_file_list must reject top");
    assert_eq!(err1.code, ErrorCode::INVALID_PARAMS);
    assert!(err1.message.contains("top"));

    let err2 = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "library_file_list".to_string(),
            filter: Some("name eq 'x'".to_string()),
            ..Default::default()
        }))
        .await
        .expect_err("library_file_list must reject filter");
    assert_eq!(err2.code, ErrorCode::INVALID_PARAMS);
    assert!(err2.message.contains("filter"));

    let err3 = server
        .defender_forensics(Parameters(ForensicsInput {
            action: "library_file_list".to_string(),
            action_id: Some("act-123".to_string()),
            ..Default::default()
        }))
        .await
        .expect_err("library_file_list must reject action_id");
    assert_eq!(err3.code, ErrorCode::INVALID_PARAMS);
    assert!(err3.message.contains("action_id"));

    assert_eq!(guard.total_hits(), 0, "rejected calls make 0 hits");
}

#[test]
fn pivots_tools_list_advertises_actions_in_descriptions_under_read_only() {
    let mut proc = McpProcess::start(&["--read-only"], &[]);
    let tools = proc.tools();

    let machines_tool = tools
        .iter()
        .find(|t| t["name"] == "defender_machines")
        .expect("defender_machines tool present");
    let machines_desc = machines_tool["description"]
        .as_str()
        .expect("description string");
    assert!(
        machines_desc.contains("find_by_ip"),
        "missing find_by_ip in defender_machines desc: {machines_desc}"
    );
    assert!(
        machines_desc.contains("machine_alerts"),
        "missing machine_alerts in defender_machines desc: {machines_desc}"
    );
    assert!(
        machines_desc.contains("machine_vulnerabilities"),
        "missing machine_vulnerabilities in defender_machines desc: {machines_desc}"
    );
    assert!(
        machines_desc.contains("machine_missing_kbs"),
        "missing machine_missing_kbs in defender_machines desc: {machines_desc}"
    );

    let forensics_tool = tools
        .iter()
        .find(|t| t["name"] == "defender_forensics")
        .expect("defender_forensics tool present");
    let forensics_desc = forensics_tool["description"]
        .as_str()
        .expect("description string");
    assert!(
        forensics_desc.contains("investigation_list"),
        "missing investigation_list in defender_forensics desc: {forensics_desc}"
    );
    assert!(
        forensics_desc.contains("investigation_get"),
        "missing investigation_get in defender_forensics desc: {forensics_desc}"
    );
    assert!(
        forensics_desc.contains("library_file_list"),
        "missing library_file_list in defender_forensics desc: {forensics_desc}"
    );

    assert!(proc.shutdown().success());
}
