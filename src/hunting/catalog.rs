//! The Microsoft Defender XDR Advanced Hunting tables this server knows, from Microsoft's schema
//! reference: each table's kind, event-time column, tags and entity columns.
//!
//! A reference, not a statement of what a tenant has: which tables hold data depends on the
//! Defender products deployed, and a tenant can have custom tables. A query that reads a table not
//! listed here gets a warning, not a refusal; Microsoft Graph refuses tables that do not exist.

use serde_json::{Value, json};

/// One Advanced Hunting table.
pub struct Table {
    pub name: &'static str,
    /// `raw_event`, `alert` or `inventory`.
    pub kind: &'static str,
    /// The event-time column; `None` for state tables without one.
    pub time: Option<&'static str>,
    pub tags: &'static [&'static str],
    /// Entity kind and the column that holds it (`("device", "DeviceName")`).
    pub entities: &'static [(&'static str, &'static str)],
}

impl Table {
    /// The table as JSON for tool results.
    pub fn to_json(&self) -> Value {
        let entities: serde_json::Map<String, Value> = self
            .entities
            .iter()
            .map(|(k, c)| ((*k).to_string(), json!(c)))
            .collect();
        json!({
            "name": self.name,
            "kind": self.kind,
            "timeColumn": self.time,
            "tags": self.tags,
            "entities": entities,
        })
    }
}

const fn ev(
    name: &'static str,
    tags: &'static [&'static str],
    entities: &'static [(&'static str, &'static str)],
) -> Table {
    Table {
        name,
        kind: "raw_event",
        time: Some("Timestamp"),
        tags,
        entities,
    }
}

const fn alert(name: &'static str, entities: &'static [(&'static str, &'static str)]) -> Table {
    Table {
        name,
        kind: "alert",
        time: Some("Timestamp"),
        tags: &["alert"],
        entities,
    }
}

const fn state(
    name: &'static str,
    time: Option<&'static str>,
    tags: &'static [&'static str],
    entities: &'static [(&'static str, &'static str)],
) -> Table {
    Table {
        name,
        kind: "inventory",
        time,
        tags,
        entities,
    }
}

const DEVICE: (&str, &str) = ("device", "DeviceName");

/// Every known table, grouped by product area.
pub const TABLES: &[Table] = &[
    // Endpoints
    ev(
        "DeviceEvents",
        &["endpoint", "process", "security_event"],
        &[
            DEVICE,
            ("user", "InitiatingProcessAccountUpn"),
            ("file_hash", "SHA256"),
            ("ip", "RemoteIP"),
        ],
    ),
    ev(
        "DeviceFileCertificateInfo",
        &["endpoint", "file", "certificate"],
        &[DEVICE, ("file_hash", "SHA1")],
    ),
    ev(
        "DeviceFileEvents",
        &["endpoint", "file"],
        &[
            DEVICE,
            ("user", "InitiatingProcessAccountUpn"),
            ("file_hash", "SHA256"),
        ],
    ),
    ev(
        "DeviceImageLoadEvents",
        &["endpoint", "module", "process"],
        &[
            DEVICE,
            ("user", "InitiatingProcessAccountUpn"),
            ("file_hash", "SHA256"),
        ],
    ),
    ev(
        "DeviceLogonEvents",
        &["endpoint", "logon", "authentication"],
        &[DEVICE, ("user", "AccountName"), ("ip", "RemoteIP")],
    ),
    ev(
        "DeviceNetworkEvents",
        &["endpoint", "network"],
        &[
            DEVICE,
            ("user", "InitiatingProcessAccountUpn"),
            ("ip", "RemoteIP"),
            ("url", "RemoteUrl"),
        ],
    ),
    ev(
        "DeviceProcessEvents",
        &["endpoint", "process"],
        &[
            DEVICE,
            ("user", "AccountUpn"),
            ("file_hash", "SHA256"),
            ("process", "FileName"),
        ],
    ),
    ev(
        "DeviceRegistryEvents",
        &["endpoint", "registry"],
        &[DEVICE, ("user", "InitiatingProcessAccountUpn")],
    ),
    state(
        "DeviceInfo",
        Some("Timestamp"),
        &["endpoint", "inventory", "device"],
        &[DEVICE],
    ),
    state(
        "DeviceNetworkInfo",
        Some("Timestamp"),
        &["endpoint", "inventory", "network"],
        &[DEVICE],
    ),
    // Vulnerability management (mostly current state, no event time)
    state(
        "DeviceTvmSoftwareInventory",
        None,
        &["vulnerability", "inventory", "software"],
        &[DEVICE],
    ),
    state(
        "DeviceTvmSoftwareVulnerabilities",
        None,
        &["vulnerability", "inventory", "cve"],
        &[DEVICE],
    ),
    state(
        "DeviceTvmSoftwareVulnerabilitiesKB",
        None,
        &["vulnerability", "knowledge_base", "cve"],
        &[],
    ),
    state(
        "DeviceTvmSecureConfigurationAssessment",
        Some("Timestamp"),
        &["vulnerability", "configuration"],
        &[DEVICE],
    ),
    state(
        "DeviceTvmSecureConfigurationAssessmentKB",
        None,
        &["vulnerability", "knowledge_base", "configuration"],
        &[],
    ),
    // Alerts and behaviours
    alert(
        "AlertEvidence",
        &[
            DEVICE,
            ("user", "AccountUpn"),
            ("ip", "RemoteIP"),
            ("file_hash", "SHA256"),
            ("url", "RemoteUrl"),
        ],
    ),
    alert("AlertInfo", &[]),
    alert(
        "BehaviorEntities",
        &[DEVICE, ("user", "AccountUpn"), ("ip", "RemoteIP")],
    ),
    alert("BehaviorInfo", &[]),
    // Email and collaboration
    ev(
        "EmailAttachmentInfo",
        &["email", "file"],
        &[("email", "RecipientEmailAddress"), ("file_hash", "SHA256")],
    ),
    ev(
        "EmailEvents",
        &["email"],
        &[("email", "RecipientEmailAddress")],
    ),
    ev(
        "EmailPostDeliveryEvents",
        &["email"],
        &[("email", "RecipientEmailAddress")],
    ),
    ev("EmailUrlInfo", &["email", "url"], &[("url", "Url")]),
    ev(
        "UrlClickEvents",
        &["email", "url"],
        &[("user", "AccountUpn"), ("url", "Url"), ("ip", "IPAddress")],
    ),
    // Identity
    ev(
        "IdentityDirectoryEvents",
        &["identity", "directory"],
        &[("user", "AccountUpn"), DEVICE, ("ip", "IPAddress")],
    ),
    state(
        "IdentityInfo",
        Some("Timestamp"),
        &["identity", "inventory"],
        &[("user", "AccountUpn")],
    ),
    ev(
        "IdentityLogonEvents",
        &["identity", "logon", "authentication"],
        &[("user", "AccountUpn"), DEVICE, ("ip", "IPAddress")],
    ),
    ev(
        "IdentityQueryEvents",
        &["identity", "directory", "query"],
        &[("user", "AccountUpn"), DEVICE, ("ip", "IPAddress")],
    ),
    ev(
        "AADSignInEventsBeta",
        &["identity", "logon", "cloud"],
        &[("user", "AccountUpn"), ("ip", "IPAddress")],
    ),
    ev(
        "AADSpnSignInEventsBeta",
        &["identity", "logon", "cloud", "service_principal"],
        &[("ip", "IPAddress")],
    ),
    ev(
        "EntraIdSignInEvents",
        &["identity", "logon", "cloud"],
        &[("user", "AccountUpn"), ("ip", "IPAddress")],
    ),
    ev(
        "EntraIdSpnSignInEvents",
        &["identity", "logon", "cloud", "service_principal"],
        &[("ip", "IPAddress")],
    ),
    // Cloud apps and workloads
    ev(
        "CloudAppEvents",
        &["cloud", "saas"],
        &[("user", "AccountObjectId"), ("ip", "IPAddress")],
    ),
    ev(
        "CloudAuditEvents",
        &["cloud", "audit"],
        &[("ip", "IPAddress")],
    ),
    ev(
        "CloudProcessEvents",
        &["cloud", "process", "container"],
        &[("process", "FileName")],
    ),
    // Exposure management
    state("ExposureGraphEdges", None, &["exposure", "graph"], &[]),
    state("ExposureGraphNodes", None, &["exposure", "graph"], &[]),
];

/// The table with exactly this name (KQL table names are case-sensitive).
pub fn find(name: &str) -> Option<&'static Table> {
    TABLES.iter().find(|t| t.name == name)
}

/// The table whose name matches ignoring case, to suggest the right spelling.
pub fn find_ignoring_case(name: &str) -> Option<&'static Table> {
    TABLES.iter().find(|t| t.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_identifiers_and_kinds_are_known() {
        let mut seen = std::collections::HashSet::new();
        for t in TABLES {
            assert!(
                t.name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "{}",
                t.name
            );
            assert!(seen.insert(t.name), "duplicate {}", t.name);
            assert!(["raw_event", "alert", "inventory"].contains(&t.kind));
            for (k, _) in t.entities {
                assert!(
                    [
                        "device",
                        "user",
                        "ip",
                        "url",
                        "file_hash",
                        "process",
                        "email"
                    ]
                    .contains(k),
                    "{k}"
                );
            }
        }
        assert_eq!(find("AlertInfo").unwrap().kind, "alert");
        assert!(find("DeviceTvmSoftwareInventory").unwrap().time.is_none());
        assert!(find("deviceinfo").is_none());
        assert_eq!(find_ignoring_case("deviceinfo").unwrap().name, "DeviceInfo");
        let j = find("DeviceNetworkEvents").unwrap().to_json();
        assert_eq!(j["entities"]["url"], "RemoteUrl");
        assert_eq!(j["timeColumn"], "Timestamp");
    }
}
