//! Advanced Hunting for `defender_hunting`: KQL checked on its parse tree before Microsoft Graph
//! sees it, rows bounded, answers made compact, and table schemas cached.
//!
//! The checks come from [`kql_parser::policy`]: outside data, other clusters, outbound plugins,
//! `set`, unscoped `search`/`find`, wildcard tables and management commands are refused, and the
//! query must end with a tabular expression so `| take` can bound it. On top of that this module
//! requires at least one table and warns about tables the [`catalog`] does not list (a tenant can
//! have custom tables; Graph refuses tables that do not exist).

pub mod catalog;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kql_parser::Analysis;
use kql_parser::policy::{self, Code};
use serde_json::{Map, Value, json};

/// Rows `run` returns when the caller does not say (`maxRows`).
pub const DEFAULT_MAX_ROWS: u32 = 1000;

/// The largest `maxRows`: Microsoft Graph returns at most 100,000 rows per query, and `run` asks for
/// one row more than `maxRows` to tell a cut answer from a complete one.
pub const MAX_MAX_ROWS: u32 = 99_999;

/// How long a table schema stays cached in the process.
pub const SCHEMA_TTL: Duration = Duration::from_secs(60 * 60);

/// Default `timespan` for `run` and `validate`.
pub const DEFAULT_TIMESPAN: &str = "P30D";

/// One finding about a query. An `error` stops `run`; a `warning` does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub code: &'static str,
    pub severity: &'static str,
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl Finding {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: "error",
            message: message.into(),
            line: None,
            column: None,
        }
    }

    fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "warning",
            ..Self::error(code, message)
        }
    }

    pub fn is_error(&self) -> bool {
        self.severity == "error"
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("code".into(), json!(self.code));
        m.insert("severity".into(), json!(self.severity));
        m.insert("message".into(), json!(self.message));
        if let (Some(line), Some(column)) = (self.line, self.column) {
            m.insert("line".into(), json!(line));
            m.insert("column".into(), json!(column));
        }
        Value::Object(m)
    }
}

impl From<policy::Problem> for Finding {
    fn from(p: policy::Problem) -> Self {
        Self {
            code: p.code.as_str(),
            severity: "error",
            message: p.message,
            line: p.position.map(|p| p.line),
            column: p.position.map(|p| p.column),
        }
    }
}

/// What `validate` found: the analysis when the query parsed, and every finding.
#[derive(Debug)]
pub struct Validation {
    pub analysis: Option<Analysis>,
    pub findings: Vec<Finding>,
}

impl Validation {
    /// No error: `run` may send the query.
    pub fn is_valid(&self) -> bool {
        !self.findings.iter().any(Finding::is_error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.is_error())
    }

    pub fn findings_json(&self) -> Value {
        Value::Array(self.findings.iter().map(Finding::to_json).collect())
    }

    /// The `validate` answer: tables, columns, operators, shape and findings.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("valid".into(), json!(self.is_valid()));
        if let Some(a) = &self.analysis {
            m.insert("tables".into(), json!(a.tables));
            m.insert("columns".into(), json!(a.columns()));
            m.insert("operators".into(), json!(a.operator_keywords()));
            m.insert("rowLimited".into(), json!(a.row_limited()));
            m.insert("timeNarrowed".into(), json!(a.time_narrowed()));
            m.insert("ungroupedAggregate".into(), json!(a.ungrouped_aggregate));
        }
        m.insert("problems".into(), self.findings_json());
        Value::Object(m)
    }
}

/// Check a query: the parser's policy, at least one table, and the tables against the catalog.
pub fn validate(query: &str) -> Validation {
    let (analysis, mut findings) = match policy::check_query(query) {
        Ok(a) => (Some(a), Vec::new()),
        Err(problems) => {
            // Policy refusals still have a parse tree worth reporting; parse errors do not.
            let parsed = !problems
                .iter()
                .any(|p| matches!(p.code, Code::ParseError | Code::ManagementCommand));
            let analysis = parsed.then(|| kql_parser::analyze(query).ok()).flatten();
            (analysis, problems.into_iter().map(Finding::from).collect())
        }
    };
    if let Some(a) = &analysis {
        if a.tables.is_empty() {
            findings.push(Finding::error(
                "no_table",
                "the query reads no table: name an Advanced Hunting table (action `tables` lists them)",
            ));
        }
        for t in &a.tables {
            if catalog::find(t).is_some() {
                continue;
            }
            let message = match catalog::find_ignoring_case(t) {
                Some(known) => format!(
                    "`{t}` is not an Advanced Hunting table: table names are case-sensitive, did you mean `{}`?",
                    known.name
                ),
                None => format!(
                    "`{t}` is not a known Advanced Hunting table: a custom table works, a missing one is refused by Defender"
                ),
            };
            findings.push(Finding::warning("unknown_table", message));
        }
        if a.ungrouped_aggregate {
            findings.push(Finding::warning(
                "ungrouped_aggregate",
                "an ungrouped `summarize`/`count` returns one row whether or not anything matched: group by an entity, or return the events",
            ));
        }
    }
    Validation { analysis, findings }
}

/// A Graph `runHuntingQuery` answer made compact: column names and types once, rows as arrays,
/// at most `max_rows` of them, and `truncated` when more came back.
pub fn compact(answer: &Value, max_rows: u32) -> Value {
    let results: &[Value] = answer
        .get("results")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    let mut columns: Vec<(String, Option<String>)> = answer
        .get("schema")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| {
            let name = c.get("name").or_else(|| c.get("Name"))?.as_str()?;
            let ty = c
                .get("type")
                .or_else(|| c.get("Type"))
                .and_then(Value::as_str);
            Some((name.to_string(), ty.map(str::to_string)))
        })
        .collect();
    if columns.is_empty()
        && let Some(Value::Object(first)) = results.first()
    {
        columns = first.keys().map(|k| (k.clone(), None)).collect();
    }
    let limit = max_rows as usize;
    let rows: Vec<Value> = results
        .iter()
        .take(limit)
        .map(|r| match r {
            Value::Object(o) => Value::Array(
                columns
                    .iter()
                    .map(|(n, _)| o.get(n).cloned().unwrap_or(Value::Null))
                    .collect(),
            ),
            other => other.clone(),
        })
        .collect();
    let truncated = results.len() > limit;
    let mut m = Map::new();
    m.insert(
        "columns".into(),
        Value::Array(
            columns
                .iter()
                .map(|(n, t)| match t {
                    Some(t) => json!({ "name": n, "type": t }),
                    None => json!({ "name": n }),
                })
                .collect(),
        ),
    );
    m.insert("rowCount".into(), json!(rows.len()));
    m.insert("truncated".into(), json!(truncated));
    m.insert("maxRows".into(), json!(max_rows));
    if truncated {
        m.insert(
            "note".into(),
            json!(format!(
                "more than {max_rows} rows matched: this answer is cut and is not the complete result; summarize, narrow the query or raise maxRows"
            )),
        );
    }
    m.insert("rows".into(), Value::Array(rows));
    Value::Object(m)
}

/// A table name safe to splice into `T | getschema`: a plain KQL identifier.
pub fn is_table_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name.len() <= 256
}

/// The query that lists a table's columns.
pub fn schema_query(table: &str) -> String {
    format!("{table}\n| getschema\n| project ColumnName, ColumnType")
}

/// The `schema` answer from a `getschema` result: the table, its catalog facts and its columns.
pub fn schema_answer(table: &str, answer: &Value) -> Value {
    let columns: Vec<Value> = answer
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let name = r.get("ColumnName")?.as_str()?;
            let ty = r.get("ColumnType").and_then(Value::as_str).unwrap_or("");
            Some(json!({ "name": name, "type": ty }))
        })
        .collect();
    let mut m = match catalog::find(table).map(catalog::Table::to_json) {
        Some(Value::Object(m)) => m,
        _ => {
            let mut m = Map::new();
            m.insert("name".into(), json!(table));
            m.insert("known".into(), json!(false));
            m
        }
    };
    m.remove("tags");
    m.insert("columns".into(), Value::Array(columns));
    Value::Object(m)
}

/// The `tables` answer: every catalog table, optionally only those with a tag or kind.
pub fn tables_answer(filter: Option<&str>) -> Value {
    let tables: Vec<Value> = catalog::TABLES
        .iter()
        .filter(|t| filter.is_none_or(|f| t.kind == f || t.tags.contains(&f)))
        .map(catalog::Table::to_json)
        .collect();
    json!({
        "tables": tables,
        "note": "Microsoft's schema reference; which tables hold data depends on the Defender products deployed. Use action `schema` for a table's columns in this tenant.",
    })
}

/// Table schemas already fetched, for [`SCHEMA_TTL`]. Clones share the cache.
#[derive(Clone, Default)]
pub struct SchemaCache(Arc<Mutex<HashMap<String, (Instant, Value)>>>);

impl SchemaCache {
    /// The cached schema of `table`, when it is fresh.
    pub fn get(&self, table: &str) -> Option<Value> {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.get(table)
            .filter(|(at, _)| at.elapsed() < SCHEMA_TTL)
            .map(|(_, v)| v.clone())
    }

    pub fn put(&self, table: &str, schema: Value) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (at, _)| at.elapsed() < SCHEMA_TTL);
        map.insert(table.to_string(), (Instant::now(), schema));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(v: &Validation) -> Vec<&str> {
        v.findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn accepts_a_hunting_query_and_describes_it() {
        let v = validate(
            "DeviceProcessEvents\n| where Timestamp > ago(1d) and FileName =~ 'powershell.exe'\n| project Timestamp, DeviceName, ProcessCommandLine",
        );
        assert!(v.is_valid(), "{:?}", v.findings);
        let j = v.to_json();
        assert_eq!(j["valid"], true);
        assert_eq!(j["tables"], json!(["DeviceProcessEvents"]));
        assert_eq!(
            j["columns"],
            json!(["DeviceName", "FileName", "ProcessCommandLine", "Timestamp"])
        );
        assert_eq!(j["operators"], json!(["project", "where"]));
        assert_eq!(
            (
                &j["rowLimited"],
                &j["timeNarrowed"],
                &j["ungroupedAggregate"]
            ),
            (&json!(false), &json!(true), &json!(false))
        );
        assert_eq!(j["problems"], json!([]));
    }

    #[test]
    fn refuses_the_policy_and_keeps_the_analysis() {
        let v = validate("set notruncation;\nDeviceInfo | take 1");
        assert!(!v.is_valid());
        assert_eq!(codes(&v), ["set_statement"]);
        assert_eq!(v.to_json()["tables"], json!(["DeviceInfo"]));
        let v = validate("externaldata (x:string) [@'https://e.example/x']");
        assert_eq!(codes(&v), ["external_data", "no_table"]);
        assert_eq!(
            codes(&validate("union Device* | take 1")),
            ["wildcard_table", "no_table"]
        );
    }

    #[test]
    fn refuses_management_commands_and_parse_errors_with_positions() {
        for q in [
            ".drop table foo",
            "  .alter cluster foo  ",
            ".create table bar (x: string)",
        ] {
            let v = validate(q);
            assert_eq!(codes(&v), ["management_command"], "{q}");
            assert!(v.analysis.is_none());
        }
        let v = validate("DeviceInfo\n| frobnicate");
        assert_eq!(codes(&v), ["parse_error"]);
        let p = &v.findings_json()[0];
        assert_eq!((&p["line"], &p["column"]), (&json!(2), &json!(3)));
        assert!(v.to_json().get("tables").is_none());
    }

    #[test]
    fn literals_and_comments_are_not_keywords() {
        for q in [
            r#"DeviceProcessEvents | where ProcessCommandLine contains "update package""#,
            "// DROP TABLE foo\nDeviceProcessEvents | take 10",
            r#"DeviceEvents | where AdditionalFields has "DROP TABLE""#,
            r#"DeviceNetworkEvents | where RemoteUrl contains "externaldata(""#,
        ] {
            assert!(validate(q).is_valid(), "{q}");
        }
    }

    #[test]
    fn requires_a_table_and_warns_about_unknown_ones() {
        assert_eq!(codes(&validate("print x = 1")), ["no_table"]);
        let v = validate("deviceprocessevents | take 1");
        assert!(v.is_valid());
        assert_eq!(codes(&v), ["unknown_table"]);
        assert!(v.findings[0].message.contains("DeviceProcessEvents"));
        let v = validate("MyCustomTable_CL | take 1");
        assert!(v.is_valid() && v.findings[0].message.contains("custom table"));
        let v = validate("DeviceInfo | summarize count()");
        assert!(v.is_valid());
        assert_eq!(codes(&v), ["ungrouped_aggregate"]);
        assert_eq!(codes(&validate("let x = 1;")), ["not_tabular", "no_table"]);
    }

    #[test]
    fn compacts_rows_and_marks_truncation() {
        let answer = json!({
            "schema": [{ "name": "DeviceName", "type": "String" }, { "name": "Count", "type": "Int64" }],
            "results": [
                { "DeviceName": "a", "Count": 1 },
                { "Count": 2, "DeviceName": "b" },
                { "DeviceName": "c" },
            ],
        });
        let c = compact(&answer, 2);
        assert_eq!(
            c["columns"],
            json!([{ "name": "DeviceName", "type": "String" }, { "name": "Count", "type": "Int64" }])
        );
        assert_eq!(c["rows"], json!([["a", 1], ["b", 2]]));
        assert_eq!((&c["rowCount"], &c["truncated"]), (&json!(2), &json!(true)));
        assert!(
            c["note"]
                .as_str()
                .unwrap()
                .contains("not the complete result")
        );

        let c = compact(&answer, 3);
        assert_eq!(c["rows"][2], json!(["c", null]));
        assert_eq!(c["truncated"], false);
        assert!(c.get("note").is_none());

        // No schema: the columns come from the first row.
        let c = compact(&json!({ "results": [{ "A": 1 }] }), 10);
        assert_eq!(c["columns"], json!([{ "name": "A" }]));
        let c = compact(&json!({}), 10);
        assert_eq!((&c["rowCount"], &c["rows"]), (&json!(0), &json!([])));
    }

    #[test]
    fn schema_and_tables_answers() {
        assert!(is_table_name("DeviceInfo") && is_table_name("My_Table_CL"));
        for bad in ["", "1x", "DeviceInfo | take 1", "a-b", "T;", "Device*"] {
            assert!(!is_table_name(bad), "{bad}");
        }
        let s = schema_answer(
            "DeviceInfo",
            &json!({ "results": [{ "ColumnName": "Timestamp", "ColumnType": "datetime" }] }),
        );
        assert_eq!(s["kind"], "inventory");
        assert_eq!(
            s["columns"],
            json!([{ "name": "Timestamp", "type": "datetime" }])
        );
        let s = schema_answer("Custom_CL", &json!({ "results": [] }));
        assert_eq!(
            (&s["name"], &s["known"]),
            (&json!("Custom_CL"), &json!(false))
        );

        let all = tables_answer(None);
        assert_eq!(
            all["tables"].as_array().unwrap().len(),
            catalog::TABLES.len()
        );
        let alerts = tables_answer(Some("alert"));
        assert!(
            alerts["tables"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["kind"] == "alert")
        );
        let process = tables_answer(Some("process"));
        assert!(
            process["tables"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["name"] == "DeviceProcessEvents")
        );
    }

    #[test]
    fn schema_cache_shares_and_expires() {
        let cache = SchemaCache::default();
        let other = cache.clone();
        assert!(cache.get("DeviceInfo").is_none());
        other.put("DeviceInfo", json!({ "columns": [] }));
        assert!(cache.get("DeviceInfo").is_some());
        if let Some(stale) = Instant::now().checked_sub(SCHEMA_TTL + Duration::from_secs(1)) {
            cache.0.lock().unwrap().get_mut("DeviceInfo").unwrap().0 = stale;
            assert!(cache.get("DeviceInfo").is_none());
        }
    }
}
