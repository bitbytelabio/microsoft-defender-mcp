//! Consolidated dispatchers route each action to the same upstream API as its granular tool.

mod common;

use axum::{
    Json, Router,
    extract::{Query, Request},
    http::StatusCode,
    routing::{get, post},
};
use common::{base_config, spawn_mock as spawn_test_server, test_server};
use microsoft_defender_mcp_server::cli::{ServerConfig, ToolMode};
use microsoft_defender_mcp_server::server::{
    DefenderServer, FORENSICS_ACTIONS, ForensicsInput, HuntingInput, INCIDENTS_ALERTS_ACTIONS,
    IncidentsAlertsInput, MACHINES_ACTIONS, MachinesInput, RESPONSE_ACTIONS, ResponseInput,
    TI_ACTIONS, ThreatIntelInput, VULNERABILITIES_ACTIONS, VulnerabilitiesInput,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ErrorCode};
use serde_json::json;
use std::collections::HashMap;

/// Consolidated mode with Live Response enabled so every action is reachable.
fn create_test_server(base_url: &str) -> DefenderServer {
    test_server(
        base_url,
        ServerConfig {
            tool_mode: ToolMode::Consolidated,
            live_response_enabled: true,
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
    for action in RESPONSE_ACTIONS {
        let input = ResponseInput {
            action: action.to_string(),
            ..Default::default()
        };
        let res = server.defender_response(Parameters(input)).await;
        assert_routed("defender_response", action, res);
    }
}
