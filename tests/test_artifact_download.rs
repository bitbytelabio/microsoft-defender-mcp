//! Investigation package / quarantined file download into the local staging directory.

mod common;

use axum::{
    Json, Router,
    extract::Request,
    http::{StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use common::{ScratchDir, base_config, spawn_mock, test_server};
use microsoft_defender_mcp_server::cli::{ServerConfig, ToolMode};
use microsoft_defender_mcp_server::server::{DefenderServer, ForensicsInput};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::ErrorCode;
use serde_json::json;
use sha2::{Digest, Sha256};

const ACTION: &str = "7327b54fd718525cbca07dacde913b5ac3c85673";
const SHA1: &str = "87662BC3D60E4200CEAF7AAE249D1C343F4B83C9";
const PAYLOAD: &[u8] = b"PK\x03\x04 forensic archive bytes";

/// Defender API + blob fixture. `package_status` is what `getPackageUri` reports via the
/// action status (`Succeeded` serves the SAS URL; anything else returns 404).
fn fixture(package_status: &'static str) -> Router {
    Router::new().fallback(move |req: Request| async move {
        let path = req.uri().path().to_string();
        let base = format!(
            "http://{}",
            req.headers()["host"].to_str().expect("host header")
        );
        if path == format!("/api/machineactions/{ACTION}/getPackageUri") {
            return if package_status == "Succeeded" {
                Json(json!({ "value": format!("{base}/blob/package.zip?sig=abc") })).into_response()
            } else {
                (StatusCode::NOT_FOUND, Json(json!({ "error": "not ready" }))).into_response()
            };
        }
        if path
            == format!("/api/machineactions/{ACTION}/GetLiveResponseResultDownloadLink(index=0)")
        {
            return Json(json!({ "value": format!("{base}/blob/getfile.zip?sig=abc") }))
                .into_response();
        }
        if path == format!("/api/machineactions/{ACTION}") {
            return Json(json!({ "id": ACTION, "status": package_status })).into_response();
        }
        if path.starts_with("/blob/") {
            // SAS URLs are self-authorizing; a bearer token must never be forwarded to storage.
            if req.headers().contains_key(AUTHORIZATION) {
                return StatusCode::BAD_REQUEST.into_response();
            }
            return PAYLOAD.into_response();
        }
        (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
    })
}

fn server(base_url: &str, quarantine: &ScratchDir) -> DefenderServer {
    test_server(
        base_url,
        ServerConfig {
            tool_mode: ToolMode::Consolidated,
            quarantine_dir: quarantine.0.clone(),
            ..base_config()
        },
    )
}

fn forensics(action: &str) -> ForensicsInput {
    ForensicsInput {
        action: action.to_string(),
        action_id: Some(ACTION.to_string()),
        ..Default::default()
    }
}

fn expected_sha256() -> String {
    format!("{:x}", Sha256::digest(PAYLOAD))
}

#[tokio::test]
async fn test_download_investigation_package_stages_file_with_digest() {
    let mock = spawn_mock(fixture("Succeeded")).await;
    let quarantine = ScratchDir::new("package");

    let res = server(&mock.base_url, &quarantine)
        .defender_forensics(Parameters(forensics("download_investigation_package")))
        .await
        .expect("download succeeded");

    assert_ne!(res.is_error, Some(true), "{res:?}");
    let artifact = res.structured_content.expect("artifact");
    let path = std::path::PathBuf::from(artifact["file_path"].as_str().unwrap());
    assert_eq!(
        path.file_name().unwrap(),
        format!("investigation_package_{ACTION}.zip").as_str()
    );
    assert_eq!(std::fs::read(&path).unwrap(), PAYLOAD);
    assert_eq!(artifact["status"], "Downloaded");
    assert_eq!(artifact["file_size_bytes"], PAYLOAD.len());
    assert_eq!(artifact["sha256"], expected_sha256());
    assert_eq!(artifact["source_action_id"], ACTION);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&quarantine.0)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }
}

#[tokio::test]
async fn test_package_not_ready_reports_current_status_and_writes_nothing() {
    let mock = spawn_mock(fixture("InProgress")).await;
    let quarantine = ScratchDir::new("pending");

    let res = server(&mock.base_url, &quarantine)
        .defender_forensics(Parameters(forensics("download_investigation_package")))
        .await
        .expect("tool-level error");

    assert_eq!(res.is_error, Some(true));
    let err = res.structured_content.expect("error body");
    assert_eq!(err["httpStatus"], 404);
    assert_eq!(err["status"], "InProgress");
    assert!(err["error"].as_str().unwrap().contains("retry"));
    assert!(
        !quarantine
            .0
            .join(format!("investigation_package_{ACTION}.zip"))
            .exists()
    );
}

#[tokio::test]
async fn test_download_quarantined_file_names_archive_by_lowercase_sha1() {
    let mock = spawn_mock(fixture("Succeeded")).await;
    let quarantine = ScratchDir::new("quarantine");

    let res = server(&mock.base_url, &quarantine)
        .defender_forensics(Parameters(ForensicsInput {
            sha1: Some(SHA1.to_string()),
            destination_dir: Some("case-4124".to_string()),
            ..forensics("download_quarantined_file")
        }))
        .await
        .expect("download succeeded");

    let artifact = res.structured_content.expect("artifact");
    let expected = quarantine
        .0
        .join("case-4124")
        .join(format!("quarantine_{}.zip", SHA1.to_ascii_lowercase()));
    assert_eq!(
        std::fs::canonicalize(&expected).unwrap().to_string_lossy(),
        artifact["file_path"].as_str().unwrap()
    );
    assert_eq!(artifact["sha256"], expected_sha256());
    assert_eq!(artifact["source_sha1"], SHA1.to_ascii_lowercase());
}

#[tokio::test]
async fn test_destination_dir_cannot_escape_quarantine_directory() {
    let mock = spawn_mock(fixture("Succeeded")).await;
    let quarantine = ScratchDir::new("escape");
    let server = server(&mock.base_url, &quarantine);

    for dir in ["../outside", "/tmp/outside", "a/../../outside"] {
        let err = server
            .defender_forensics(Parameters(ForensicsInput {
                destination_dir: Some(dir.to_string()),
                ..forensics("download_investigation_package")
            }))
            .await
            .expect_err("escaping destination_dir must be rejected");
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{dir}");
    }
    assert!(
        !quarantine.0.exists(),
        "nothing may be created on rejection"
    );
}

#[tokio::test]
async fn test_action_id_with_path_characters_rejected() {
    let mock = spawn_mock(fixture("Succeeded")).await;
    let quarantine = ScratchDir::new("action-id");

    let err = server(&mock.base_url, &quarantine)
        .defender_forensics(Parameters(ForensicsInput {
            action_id: Some("../../etc/passwd".to_string()),
            ..forensics("download_investigation_package")
        }))
        .await
        .expect_err("traversal in action_id must be rejected");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
}
