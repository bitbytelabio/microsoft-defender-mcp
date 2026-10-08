//! Append-only JSON Lines audit log for mutating actions (fail-closed).
//!
//! Every mutating attempt is logged according to the lifecycle in `contracts/audit-log.md`.
//! Each line is a single UTF-8 JSON object ending in `\n`.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::auth::IdentitySnapshot;

/// Audit log record phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    /// Pre-network intention record written after confirmation and validation pass.
    Intent,
    /// Post-network outcome record written after upstream response or transport error.
    Outcome,
    /// Final record written for requests rejected locally before upstream contact.
    Final,
}

impl AuditPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Outcome => "outcome",
            Self::Final => "final",
        }
    }
}

/// Confirmation outcome recorded for the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationOutcome {
    Accepted,
    Declined,
    Unavailable,
    TurnedOff,
    NotApplicable,
}

impl ConfirmationOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Declined => "declined",
            Self::Unavailable => "unavailable",
            Self::TurnedOff => "turned_off",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Reason for local rejection before network contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    ReadOnly,
    CategoryDisabled,
    Validation,
    ConfirmationUnavailable,
    NotConfirmed,
    AuditUnavailable,
}

impl RejectReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::CategoryDisabled => "category_disabled",
            Self::Validation => "validation",
            Self::ConfirmationUnavailable => "confirmation_unavailable",
            Self::NotConfirmed => "not_confirmed",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }
}

/// Kinds of targets identified in mutating actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTargetKind {
    MachineId,
    MachineActionId,
    IndicatorId,
    IndicatorValue,
    AlertId,
    IncidentId,
    FileName,
    Sha1,
}

/// Target entity of a mutating action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTarget {
    pub kind: AuditTargetKind,
    pub value: String,
}

impl AuditTarget {
    pub fn new(kind: AuditTargetKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    pub fn machine_id(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::MachineId, value)
    }

    pub fn machine_action_id(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::MachineActionId, value)
    }

    pub fn indicator_id(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::IndicatorId, value)
    }

    pub fn indicator_value(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::IndicatorValue, value)
    }

    pub fn alert_id(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::AlertId, value)
    }

    pub fn incident_id(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::IncidentId, value)
    }

    pub fn file_name(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::FileName, value)
    }

    pub fn sha1(value: impl Into<String>) -> Self {
        Self::new(AuditTargetKind::Sha1, value)
    }
}

/// Result of an attempt recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditResult {
    Pending,
    Submitted {
        http_status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        tracking_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        upstream_status: Option<String>,
    },
    UpstreamError {
        http_status: u16,
        message: String,
    },
    TransportError {
        message: String,
    },
    Rejected {
        reason: RejectReason,
    },
    Declined,
}

impl AuditResult {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted { .. } => "submitted",
            Self::UpstreamError { .. } => "upstream_error",
            Self::TransportError { .. } => "transport_error",
            Self::Rejected { .. } => "rejected",
            Self::Declined => "declined",
        }
    }
}

/// An audit record entry written to the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: DateTime<Utc>,
    pub attempt_id: String,
    pub phase: AuditPhase,
    pub tool: String,
    pub action: String,
    pub targets: Vec<AuditTarget>,
    pub parameters: serde_json::Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    pub identity: IdentitySnapshot,
    pub confirmation: ConfirmationOutcome,
    pub result: AuditResult,
}
impl AuditRecord {
    /// Print a single summary line to stderr matching contracts/audit-log.md.
    pub fn print_stderr_summary(&self) {
        let status_part = match &self.result {
            AuditResult::Submitted { http_status, .. }
            | AuditResult::UpstreamError { http_status, .. } => {
                format!(" status={http_status}")
            }
            _ => String::new(),
        };

        let id_part = match &self.result {
            AuditResult::Submitted {
                tracking_id: Some(id),
                ..
            } => format!(" id={id}"),
            _ => String::new(),
        };

        eprintln!(
            "AUDIT {} {}.{} targets={} identity={} confirmation={} result={}{}{}",
            self.ts.to_rfc3339(),
            self.tool,
            self.action,
            self.targets.len(),
            self.identity.display_summary(),
            self.confirmation.as_str(),
            self.result.kind_str(),
            status_part,
            id_part,
        );
    }
}

/// Generates a new 16-byte cryptographically random attempt ID, encoded as 32 hex characters.
pub fn new_attempt_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom must succeed");
    let mut hex = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    hex
}

/// Thread-safe append-only sink for the mutation audit log.
pub struct AuditSink {
    path: PathBuf,
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl AuditSink {
    /// Opens the audit log at `path`, creating the parent directory with mode 0700 and
    /// the file with mode 0600 on Unix.
    pub async fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let parent_existed = parent.exists();
            let mut builder = tokio::fs::DirBuilder::new();
            builder.recursive(true);
            builder.create(parent).await?;
            #[cfg(unix)]
            {
                if !parent_existed {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                        .await?;
                }
            }
        }

        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let file = options.open(&path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
        }

        Ok(Self {
            path,
            file: tokio::sync::Mutex::new(file),
        })
    }

    /// Returns the path to the audit log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends an audit record to the log, flushes to disk, and prints a summary to stderr.
    pub async fn append(&self, record: &AuditRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');

        {
            let mut file = self.file.lock().await;
            file.write_all(&line).await?;
            file.flush().await?;
        }

        record.print_stderr_summary();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attempt_id_format() {
        let id = new_attempt_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_audit_record_wire_format() {
        let now = Utc::now();
        let record = AuditRecord {
            ts: now,
            attempt_id: "0123456789abcdef0123456789abcdef".to_string(),
            phase: AuditPhase::Intent,
            tool: "defender_device_response".to_string(),
            action: "isolate".to_string(),
            targets: vec![AuditTarget::machine_id("1a2b3c4d")],
            parameters: {
                let mut map = serde_json::Map::new();
                map.insert(
                    "isolation_type".to_string(),
                    Value::String("Full".to_string()),
                );
                map
            },
            justification: Some("Ransomware beaconing".to_string()),
            identity: IdentitySnapshot::App {
                client_id: "app-client-id".to_string(),
            },
            confirmation: ConfirmationOutcome::Accepted,
            result: AuditResult::Pending,
        };

        let json_val = serde_json::to_value(&record).expect("serialize record");
        assert_eq!(json_val["attempt_id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(json_val["phase"], "intent");
        assert_eq!(json_val["tool"], "defender_device_response");
        assert_eq!(json_val["action"], "isolate");
        assert_eq!(json_val["targets"][0]["kind"], "machine_id");
        assert_eq!(json_val["targets"][0]["value"], "1a2b3c4d");
        assert_eq!(json_val["parameters"]["isolation_type"], "Full");
        assert_eq!(json_val["justification"], "Ransomware beaconing");
        assert_eq!(json_val["identity"]["kind"], "app");
        assert_eq!(json_val["identity"]["client_id"], "app-client-id");
        assert_eq!(json_val["confirmation"], "accepted");
        assert_eq!(json_val["result"]["kind"], "pending");
    }

    #[tokio::test]
    async fn test_audit_sink_permissions_and_append() {
        let temp_dir = std::env::temp_dir().join(format!("test_audit_{}", new_attempt_id()));
        let audit_dir = temp_dir.join("audit_subdir");
        let audit_file = audit_dir.join("audit.jsonl");

        let sink: AuditSink = AuditSink::open(&audit_file).await.expect("open audit sink");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_meta = std::fs::metadata(&audit_dir).expect("dir metadata");
            assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);

            let file_meta = std::fs::metadata(&audit_file).expect("file metadata");
            assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
        }

        let record1 = AuditRecord {
            ts: Utc::now(),
            attempt_id: new_attempt_id(),
            phase: AuditPhase::Intent,
            tool: "defender_response".to_string(),
            action: "live_response_run".to_string(),
            targets: vec![],
            parameters: serde_json::Map::new(),
            justification: Some("test comment 1".to_string()),
            identity: IdentitySnapshot::App {
                client_id: "client-1".to_string(),
            },
            confirmation: ConfirmationOutcome::Accepted,
            result: AuditResult::Pending,
        };

        let record2 = AuditRecord {
            ts: Utc::now(),
            attempt_id: record1.attempt_id.clone(),
            phase: AuditPhase::Outcome,
            tool: "defender_response".to_string(),
            action: "live_response_run".to_string(),
            targets: vec![],
            parameters: serde_json::Map::new(),
            justification: Some("test comment 1".to_string()),
            identity: IdentitySnapshot::App {
                client_id: "client-1".to_string(),
            },
            confirmation: ConfirmationOutcome::Accepted,
            result: AuditResult::Submitted {
                http_status: 201,
                tracking_id: Some("action-guid-1".to_string()),
                upstream_status: Some("Pending".to_string()),
            },
        };

        sink.append(&record1).await.expect("append record1");
        sink.append(&record2).await.expect("append record2");

        let content = std::fs::read_to_string(&audit_file).expect("read audit file");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed1: Value = serde_json::from_str(lines[0]).expect("parse line 1");
        let parsed2: Value = serde_json::from_str(lines[1]).expect("parse line 2");
        assert_eq!(parsed1["phase"], "intent");
        assert_eq!(parsed2["phase"], "outcome");
        assert_eq!(parsed1["attempt_id"], parsed2["attempt_id"]);
        assert_eq!(parsed2["result"]["tracking_id"], "action-guid-1");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
