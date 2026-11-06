//! A safety policy for services that run KQL written by someone else (often a language model)
//! against a read-only store, and bound the rows it returns.
//!
//! [`check`] looks at an [`Analysis`] and reports what such a service should refuse: reading
//! outside the data in scope (`externaldata`, `external_table()`, `cluster()`, `database()`,
//! plugins that call outside services), changing query options (`set`), searching every table
//! (`search`/`find` without `in (...)`) and wildcard table names. [`check_query`] adds what only
//! the text shows: management commands, text that does not parse, and a last statement that is
//! not a tabular expression. [`bounded`] appends a row bound one above the caller's limit, so a
//! truncated answer can be told from a complete one.
//!
//! The checks are pure (no I/O) and decided on the parse tree, so a keyword inside a string literal
//! or a comment is never mistaken for an operator. They narrow what a query may ask for; they are
//! not a substitute for read-only credentials on the store itself.

use std::fmt;

use crate::{Analysis, Rule, analyze_query, last_statement, parse};

/// Plugins that reach a service outside the data being queried.
pub const EXTERNAL_PLUGINS: &[&str] = &[
    "http_request",
    "http_request_post",
    "sql_request",
    "mysql_request",
    "postgresql_request",
    "cosmosdb_sql_request",
    "azure_digital_twins_query_request",
];

/// What a [`Problem`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// The text is not KQL the grammar understands.
    ParseError,
    /// A management command (`.show`, `.create`, `.drop`...): not a query.
    ManagementCommand,
    /// `externaldata` or `external_table()`: data from outside the store.
    ExternalData,
    /// `cluster()` or `database()`: another cluster or database.
    CrossCluster,
    /// An `evaluate` plugin that calls an outside service ([`EXTERNAL_PLUGINS`]).
    ExternalPlugin,
    /// A `set` statement: query options belong to the service.
    SetStatement,
    /// `search` or `find` without `in (...)`: every table in scope.
    UnscopedSearch,
    /// A wildcard table name (`union Device*`).
    WildcardTable,
    /// The last statement is not a tabular expression, so its rows cannot be bounded.
    NotTabular,
}

impl Code {
    /// The code as a stable `snake_case` identifier, for wire formats.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::ParseError => "parse_error",
            Code::ManagementCommand => "management_command",
            Code::ExternalData => "external_data",
            Code::CrossCluster => "cross_cluster",
            Code::ExternalPlugin => "external_plugin",
            Code::SetStatement => "set_statement",
            Code::UnscopedSearch => "unscoped_search",
            Code::WildcardTable => "wildcard_table",
            Code::NotTabular => "not_tabular",
        }
    }

    /// The query would read data from outside the store it is sent to.
    pub fn is_external_access(self) -> bool {
        matches!(
            self,
            Code::ExternalData | Code::CrossCluster | Code::ExternalPlugin
        )
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A place in the query text (1-based line and column, in characters).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

/// One reason to refuse a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub code: Code,
    /// What is wrong and how to fix it, for the query's author.
    pub message: String,
    /// Where, when the parse tree or the parser knows it.
    pub position: Option<Position>,
}

impl Problem {
    fn new(code: Code, message: impl Into<String>) -> Problem {
        Problem {
            code,
            message: message.into(),
            position: None,
        }
    }

    fn at(mut self, position: Position) -> Problem {
        self.position = Some(position);
        self
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(p) => write!(
                f,
                "{} (line {}, column {}): {}",
                self.code, p.line, p.column, self.message
            ),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

/// What the analysis shows a read-only service should refuse. Empty when the query may run.
pub fn check(a: &Analysis) -> Vec<Problem> {
    let mut out = Vec::new();
    if a.cross_cluster {
        out.push(Problem::new(
            Code::CrossCluster,
            "`cluster()`/`database()` are not allowed: the query must read only the data in scope",
        ));
    }
    if a.external_data {
        out.push(Problem::new(
            Code::ExternalData,
            "`externaldata`/`external_table()` are not allowed: the query must not read outside data",
        ));
    }
    for p in &a.plugins {
        if EXTERNAL_PLUGINS.contains(&p.as_str()) {
            out.push(Problem::new(
                Code::ExternalPlugin,
                format!("`evaluate {p}` is not allowed: it calls an external service"),
            ));
        }
    }
    if a.unscoped_search {
        out.push(Problem::new(
            Code::UnscopedSearch,
            "`search`/`find` must name its tables with `in (...)`",
        ));
    }
    for p in &a.table_patterns {
        out.push(Problem::new(
            Code::WildcardTable,
            format!("wildcard table name `{p}` is not allowed: name each table"),
        ));
    }
    for o in &a.set_options {
        out.push(Problem::new(
            Code::SetStatement,
            format!("`set {o}` is not allowed: the service sets the query options and bounds"),
        ));
    }
    out
}

/// Parse and check a query for a read-only, row-bounded service: management commands, parse
/// errors, everything [`check`] reports, and a last statement that is not a tabular expression.
/// The analysis when nothing is wrong.
pub fn check_query(text: &str) -> Result<Analysis, Vec<Problem>> {
    if let Some(at) = leading_dot(text) {
        return Err(vec![management_command().at(at)]);
    }
    let query = match parse(text) {
        Ok(q) => q,
        Err(e) => {
            let at = Position {
                line: e.line,
                column: e.column,
            };
            let problem = if dot_statement_at(text, at) {
                management_command()
            } else {
                Problem::new(Code::ParseError, e.message)
            };
            return Err(vec![problem.at(at)]);
        }
    };
    let tabular = is_tabular(last_statement(query.clone()));
    let a = analyze_query(query);
    let mut out = check(&a);
    if !tabular {
        out.push(Problem::new(
            Code::NotTabular,
            "the query must end with a tabular expression: its rows are bounded with `| take`",
        ));
    }
    if out.is_empty() { Ok(a) } else { Err(out) }
}

/// The last statement is a tabular expression, so `| take` can be appended to it. False when the
/// text does not parse.
pub fn ends_tabular(text: &str) -> bool {
    parse(text).is_ok_and(|q| is_tabular(last_statement(q)))
}

/// The query with a row bound of `max_rows + 1` appended (`| take N`), so that an answer with more
/// than `max_rows` rows shows the query was cut rather than complete. Trailing `;`, whitespace and
/// comments after the last statement are dropped first. Check [`ends_tabular`] (or
/// [`check_query`]) before: a bound after a `let` statement does not parse.
pub fn bounded(text: &str, max_rows: u32) -> String {
    let body = parse(text)
        .ok()
        .and_then(last_statement)
        .map(|s| &text[..statement_end(text, &s)])
        .unwrap_or_else(|| text.trim_end_matches(|c: char| c == ';' || c.is_whitespace()));
    format!("{body}\n| take {}", u64::from(max_rows) + 1)
}

/// The byte offset just after a statement's last token. A pair's span can run on over the
/// whitespace and comments that follow it, so the end is found from its last leaf token: after
/// that only punctuation (closing brackets), whitespace and `//` comments can follow. String
/// literals are leaf tokens themselves, so a `//` there always opens a comment.
fn statement_end(text: &str, stmt: &pest::iterators::Pair<'_, Rule>) -> usize {
    let span = stmt.as_span();
    let last_leaf = stmt
        .clone()
        .into_inner()
        .flatten()
        .filter(|p| p.clone().into_inner().next().is_none())
        .map(|p| p.as_span().end())
        .max()
        .unwrap_or_else(|| span.start());
    let mut end = last_leaf;
    let mut offset = last_leaf;
    for line in text[last_leaf..span.end()].split_inclusive('\n') {
        let code = line.find("//").map_or(line, |i| &line[..i]).trim_end();
        if !code.is_empty() {
            end = offset + code.len();
        }
        offset += line.len();
    }
    end
}

fn is_tabular(last: Option<pest::iterators::Pair<'_, Rule>>) -> bool {
    last.is_some_and(|s| s.as_rule() == Rule::pipe_expr)
}

fn management_command() -> Problem {
    Problem::new(
        Code::ManagementCommand,
        "management commands (`.show`, `.create`, `.drop`...) are not queries and are not allowed",
    )
}

/// Where the text starts with `.` once whitespace and `//` comments are skipped.
fn leading_dot(text: &str) -> Option<Position> {
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with('.') {
            let column = line.chars().count() - trimmed.chars().count() + 1;
            return Some(Position {
                line: i + 1,
                column,
            });
        }
        return None;
    }
    None
}

/// The parser stopped at a `.` that opens a statement (`T | take 1; .show tables`).
fn dot_statement_at(text: &str, at: Position) -> bool {
    byte_offset(text, at)
        .is_some_and(|o| text[o..].starts_with('.') && text[..o].trim_end().ends_with(';'))
}

/// The byte offset of a 1-based line and character column.
fn byte_offset(text: &str, at: Position) -> Option<usize> {
    let mut start = 0;
    for (i, line) in text.split('\n').enumerate() {
        if i + 1 == at.line {
            return line
                .char_indices()
                .nth(at.column.saturating_sub(1))
                .map(|(b, _)| start + b);
        }
        start += line.len() + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(q: &str) -> Vec<Code> {
        check_query(q)
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.code)
            .collect()
    }

    #[test]
    fn accepts_a_read_only_query() {
        let a = check_query(
            "DeviceProcessEvents // externaldata in a comment is fine\n| where X == 'cluster(\"a\")'\n| take 5",
        )
        .unwrap();
        assert!(a.tables.contains("DeviceProcessEvents"));
        // A column that merely contains the word is fine.
        assert!(check_query("DeviceInfo | project ClusterName, DatabaseName").is_ok());
        assert!(check_query("let n = 5;\nDeviceInfo | take n;").is_ok());
    }

    #[test]
    fn refuses_outside_access() {
        assert_eq!(
            codes("externaldata (x:string) [@'https://e.example/x']"),
            [Code::ExternalData]
        );
        assert_eq!(codes("external_table('t') | take 1"), [Code::ExternalData]);
        assert_eq!(
            codes("cluster('x').database('y').T | take 1"),
            [Code::CrossCluster]
        );
        assert_eq!(
            codes("print x = 1 | evaluate http_request('https://x')"),
            [Code::ExternalPlugin]
        );
        assert_eq!(
            codes("print x = 1 | evaluate sql_request('cs', 'select 1')"),
            [Code::ExternalPlugin]
        );
        // Other plugins are not outside access.
        assert!(check_query("DeviceInfo | evaluate bag_unpack(AdditionalFields)").is_ok());
        assert!(codes("cluster('x').database('y').T | take 1")[0].is_external_access());
    }

    #[test]
    fn refuses_options_searches_and_wildcards() {
        assert_eq!(
            codes("set notruncation;\nDeviceInfo | take 1"),
            [Code::SetStatement]
        );
        assert_eq!(codes("search \"mimikatz\""), [Code::UnscopedSearch]);
        assert_eq!(codes("find 'x'"), [Code::UnscopedSearch]);
        assert!(check_query("search in (DeviceProcessEvents) \"mimikatz\"").is_ok());
        assert_eq!(codes("union Device* | take 1"), [Code::WildcardTable]);
        let p = &check_query("union Device* | take 1").unwrap_err()[0];
        assert!(p.message.contains("Device*"), "{p}");
    }

    #[test]
    fn refuses_management_commands_with_their_position() {
        let p = &check_query(".show tables").unwrap_err()[0];
        assert_eq!(p.code, Code::ManagementCommand);
        assert_eq!(p.position, Some(Position { line: 1, column: 1 }));
        let p = &check_query("// list them\n  .drop table T").unwrap_err()[0];
        assert_eq!(p.code, Code::ManagementCommand);
        assert_eq!(p.position, Some(Position { line: 2, column: 3 }));
        assert_eq!(
            codes("DeviceInfo | take 1;\n.show tables"),
            [Code::ManagementCommand]
        );
        // A `.` elsewhere is a parse error.
        assert_eq!(codes("DeviceInfo | where .x == 1"), [Code::ParseError]);
    }

    #[test]
    fn reports_parse_errors_with_their_position() {
        let p = &check_query("DeviceInfo\n| where X == 1\n| frobnicate").unwrap_err()[0];
        assert_eq!(p.code, Code::ParseError);
        assert_eq!(p.position.map(|p| p.line), Some(3));
        assert!(p.message.contains("frobnicate"), "{p}");
        assert!(
            p.to_string()
                .starts_with("parse_error (line 3, column 3): "),
            "{p}"
        );
    }

    #[test]
    fn requires_a_tabular_last_statement() {
        assert_eq!(codes("let x = 1;"), [Code::NotTabular]);
        assert_eq!(
            codes("set querytrace;"),
            [Code::SetStatement, Code::NotTabular]
        );
        assert!(ends_tabular("DeviceInfo | take 1;"));
        assert!(!ends_tabular("let x = DeviceInfo;"));
        assert!(!ends_tabular("DeviceInfo | where"));
    }

    #[test]
    fn bounds_rows_one_above_the_limit() {
        let b = bounded("DeviceInfo | where a == 1;\n\n", 200);
        assert_eq!(b, "DeviceInfo | where a == 1\n| take 201");
        assert!(parse(&b).is_ok());
        // A trailing comment, even after `;`, does not swallow the bound.
        assert_eq!(bounded("DeviceInfo; // last\n", 1), "DeviceInfo\n| take 2");
        assert_eq!(bounded("DeviceInfo // c", 1), "DeviceInfo\n| take 2");
        assert_eq!(
            bounded("T | where x in (\"a//b\" // c\n ) // d\n", 1),
            "T | where x in (\"a//b\" // c\n )\n| take 2"
        );
        assert_eq!(
            bounded("T | where Url has 'http://x' // c", 1),
            "T | where Url has 'http://x'\n| take 2"
        );
        assert!(parse(&bounded("let n = 1;\nDeviceInfo | take n // c\n;", 9)).is_ok());
        // Text that does not parse is trimmed, not rewritten.
        assert_eq!(
            bounded("DeviceInfo | frob ;; ", 4),
            "DeviceInfo | frob\n| take 5"
        );
        assert_eq!(
            bounded("T", u32::MAX),
            format!("T\n| take {}", u64::from(u32::MAX) + 1)
        );
    }
}
