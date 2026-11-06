//! KQL (Kusto Query Language) parsing and analysis.
//!
//! [`parse`] runs the pest grammar in `kql.pest`, which is derived from Microsoft's Kusto.Language
//! parser (see NOTICE). [`analyze`] walks the parse tree for what a caller needs to know before it
//! sends a query anywhere: which tables it reads, which columns and operators it uses, whether it
//! reaches outside the data in scope (`cluster()`, `database()`, `externaldata`,
//! `external_table()`), which plugins it evaluates and which `set` options it changes.
//! [`policy`] turns that analysis into the problems a read-only query service refuses, and bounds
//! a query's rows.
//!
//! The grammar covers queries, not management commands, and not every operator: text it does not
//! understand is a [`ParseError`], never a partial result.
//!
//! ```
//! let a = kql_parser::analyze("DeviceProcessEvents | where FileName =~ 'cmd.exe' | take 10").unwrap();
//! assert!(a.tables.contains("DeviceProcessEvents"));
//! assert!(a.row_limited());
//! assert!(kql_parser::policy::check(&a).is_empty());
//! ```

pub mod policy;

use std::collections::BTreeSet;

use pest::Parser;
use pest::error::LineColLocation;
use pest::iterators::Pair;
use pest_derive::Parser;

/// The pest parser generated from `kql.pest`; [`Rule`] names the grammar's rules.
#[derive(Parser)]
#[grammar = "kql.pest"]
pub struct KqlParser;

/// Where and why a query did not parse (1-based line and column).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {}, column {}: {}",
            self.line, self.column, self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// Parse a whole query (statements separated by `;`). The pair is the `query` rule.
pub fn parse(text: &str) -> Result<Pair<'_, Rule>, ParseError> {
    match KqlParser::parse(Rule::query, text) {
        Ok(mut pairs) => Ok(pairs.next().expect("query rule")),
        Err(e) => {
            let (line, column) = match e.line_col {
                LineColLocation::Pos(p) => p,
                LineColLocation::Span(p, _) => p,
            };
            let rest: String = text
                .lines()
                .nth(line.saturating_sub(1))
                .map(|l| l.chars().skip(column.saturating_sub(1)).take(40).collect())
                .unwrap_or_default();
            let near = if rest.trim().is_empty() {
                "the end of the line".to_string()
            } else {
                format!("`{}`", rest.trim_end())
            };
            Err(ParseError {
                line,
                column,
                message: format!("unsupported or invalid KQL near {near}"),
            })
        }
    }
}

/// What a query reads and does, as far as bounding it is concerned.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Analysis {
    /// Names used as the source of a pipe, a join/lookup/union operand or `table('x')`; let-bound
    /// names are excluded.
    pub tables: BTreeSet<String>,
    /// Wildcard table names (`union Device*`).
    pub table_patterns: BTreeSet<String>,
    /// Every function called, as written (`ago`, `tolower`, `cluster`, a let-defined function...).
    pub functions: BTreeSet<String>,
    /// Plugins run by `evaluate`, lower-cased.
    pub plugins: BTreeSet<String>,
    /// Functions run by `invoke`.
    pub invoked: BTreeSet<String>,
    /// `cluster()` or `database()` appears: the query names another cluster or database.
    pub cross_cluster: bool,
    /// `externaldata` / `external_table()`: the query reads outside the cluster.
    pub external_data: bool,
    /// `find` or `search` without an `in (...)` list: every table in scope.
    pub unscoped_search: bool,
    /// `set` statements (option names).
    pub set_options: BTreeSet<String>,
    /// Names bound by `let`.
    pub let_names: BTreeSet<String>,
    /// Query operators used (grammar rule names, e.g. `where_op`, `join_op`).
    pub operators: BTreeSet<String>,
    /// Names read as values (columns, let-bound scalars): every `name_ref` that is neither the source
    /// table of a pipe nor a called function. Member names (`AdditionalFields.Foo`) are not included.
    pub names: BTreeSet<String>,
    /// Names the query introduces: `extend X =`, `project X =`, `summarize X =`, `parse ... X:type`,
    /// `project-rename X =`, `range X`, `as X`...
    pub declared: BTreeSet<String>,
    /// A `summarize` without `by`, or `count`: it returns a row whether or not anything matched, so
    /// a row count says nothing about matches.
    pub ungrouped_aggregate: bool,
    /// `datetime(...)`/`date(...)` literals: the query names its own points in time.
    pub time_literals: bool,
}

/// Parse a query and collect its [`Analysis`].
pub fn analyze(text: &str) -> Result<Analysis, ParseError> {
    Ok(analyze_query(parse(text)?))
}

/// The [`Analysis`] of a parsed `query` pair.
fn analyze_query(query: Pair<'_, Rule>) -> Analysis {
    let mut a = Analysis::default();
    for p in query.into_inner() {
        walk(p, true, &mut a);
    }
    for n in &a.let_names {
        a.tables.remove(n);
    }
    a
}

/// The last statement of a parsed `query` pair (`let`, `set` or a pipe expression).
fn last_statement(query: Pair<'_, Rule>) -> Option<Pair<'_, Rule>> {
    query
        .into_inner()
        .filter(|p| p.as_rule() != Rule::EOI)
        .last()
}

/// Operators that cap the number of rows a query returns.
const ROW_LIMIT_OPERATORS: &[&str] = &[
    "take_op",
    "top_op",
    "top_hitters_op",
    "sample_op",
    "sample_distinct_op",
];

/// Functions whose value is a point in time relative to the query's run (`ago(7d)`, `now()`).
const TIME_FUNCTIONS: &[&str] = &[
    "ago",
    "now",
    "startofday",
    "startofweek",
    "startofmonth",
    "startofyear",
    "endofday",
    "endofweek",
    "endofmonth",
    "endofyear",
    "datetime_add",
];

/// Aggregation functions whose default output column is `<function>_<argument>` (`count_`,
/// `dcount_DeviceId`).
const AGGREGATE_PREFIXES: &[&str] = &[
    "count",
    "dcount",
    "sum",
    "avg",
    "min",
    "max",
    "any",
    "take_any",
    "arg_max",
    "arg_min",
    "make_set",
    "make_list",
    "make_bag",
    "countif",
    "dcountif",
    "sumif",
    "avgif",
    "minif",
    "maxif",
    "percentile",
    "percentiles",
    "stdev",
    "variance",
    "hll",
    "tdigest",
];

/// Names KQL makes up rather than reads: `$left`/`$right`, default expression and aggregate column
/// names (`Column1`, `print_0`, `count_`, `dcount_DeviceId`).
fn is_generated_name(n: &str) -> bool {
    let numbered = |prefix: &str| {
        n.strip_prefix(prefix)
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    };
    n.starts_with('$')
        || numbered("Column")
        || numbered("print_")
        || AGGREGATE_PREFIXES
            .iter()
            .any(|p| n.strip_prefix(p).is_some_and(|rest| rest.starts_with('_')))
}

impl Analysis {
    /// A row-limiting operator appears (`take`, `limit`, `top`, `top-hitters`, `sample`,
    /// `sample-distinct`).
    pub fn row_limited(&self) -> bool {
        self.operators
            .iter()
            .any(|o| ROW_LIMIT_OPERATORS.contains(&o.as_str()))
    }

    /// The query names its own time range: a `datetime(...)` literal or a relative time function
    /// such as `ago()` or `now()`.
    pub fn time_narrowed(&self) -> bool {
        self.time_literals
            || self
                .functions
                .iter()
                .any(|f| TIME_FUNCTIONS.contains(&f.to_ascii_lowercase().as_str()))
    }

    /// Names read as columns of the tables: [`Analysis::names`] without the names the query
    /// declares or binds with `let`, the tables and the names KQL generates (`count_`, `$left`).
    /// An approximation: a column that the query both reads and redeclares
    /// (`extend FileName = tolower(FileName)`) is left out.
    pub fn columns(&self) -> BTreeSet<String> {
        self.names
            .iter()
            .filter(|n| {
                !self.declared.contains(*n)
                    && !self.let_names.contains(*n)
                    && !self.tables.contains(*n)
                    && !is_generated_name(n)
            })
            .cloned()
            .collect()
    }

    /// The query operators used, spelled as in KQL (`where`, `summarize`, `mv-expand`).
    pub fn operator_keywords(&self) -> BTreeSet<String> {
        self.operators
            .iter()
            .map(|o| o.trim_end_matches("_op").replace('_', "-"))
            .collect()
    }
}

/// The text of a string literal without its quotes and prefixes (escapes are left as written).
pub fn unquote(s: &str) -> String {
    let s = s.trim_start_matches(['h', 'H']).trim_start_matches('@');
    for q in ["```", "~~~"] {
        if let Some(inner) = s.strip_prefix(q).and_then(|x| x.strip_suffix(q)) {
            return inner.to_string();
        }
    }
    let mut c = s.chars();
    c.next();
    c.next_back();
    c.as_str().to_string()
}

fn name_text(p: Pair<'_, Rule>) -> String {
    match p.as_rule() {
        Rule::name_ref | Rule::name_decl => match p.into_inner().next() {
            Some(inner) => name_text(inner),
            None => String::new(),
        },
        Rule::bracket_name => p
            .into_inner()
            .next()
            .map(|s| unquote(s.as_str()))
            .unwrap_or_default(),
        _ => p.as_str().to_string(),
    }
}

enum Head<'a> {
    Name(String),
    Paren(Pair<'a, Rule>),
    Other,
}

/// Follow single-child nodes from an expression down to a bare name or a parenthesized pipe.
fn head_of(p: Pair<'_, Rule>) -> Head<'_> {
    let mut cur = p;
    loop {
        match cur.as_rule() {
            Rule::name_ref => return Head::Name(name_text(cur)),
            Rule::paren_pipe => return Head::Paren(cur),
            _ => {}
        }
        let mut inner = cur.clone().into_inner();
        match (inner.next(), inner.next()) {
            (Some(only), None) => cur = only,
            _ => return Head::Other,
        }
    }
}

/// Expression operators (`==`, `<`, `+`, `has`, `in`...): their rule names end in `_op` too, but
/// they are not query operators.
const EXPRESSION_OPERATORS: &[Rule] = &[
    Rule::eq_op,
    Rule::rel_op,
    Rule::add_op,
    Rule::mul_op,
    Rule::unary_op,
    Rule::in_op,
    Rule::between_op,
    Rule::str_op,
];

/// `tabular`: the pipe's source is read as a table even without operators (statements, let values,
/// join/lookup/union operands). Elsewhere (a function argument, an `in` list) only a pipe with
/// operators makes its source a table.
fn walk(p: Pair<'_, Rule>, tabular: bool, a: &mut Analysis) {
    match p.as_rule() {
        Rule::let_stmt => {
            let mut inner = p.into_inner();
            inner.next(); // kw_let
            if let Some(n) = inner.next() {
                a.let_names.insert(name_text(n));
            }
            for c in inner {
                walk(c, true, a);
            }
            return;
        }
        Rule::set_stmt => {
            if let Some(o) = p.into_inner().find(|c| c.as_rule() == Rule::option_name) {
                a.set_options.insert(o.as_str().to_string());
            }
            return;
        }
        Rule::fn_param => return,
        Rule::name_ref => {
            a.names.insert(name_text(p));
            return;
        }
        Rule::name_decl => {
            a.declared.insert(name_text(p));
            return;
        }
        Rule::pipe_expr => {
            let mut inner = p.into_inner();
            let Some(head) = inner.next() else { return };
            let ops: Vec<Pair<'_, Rule>> = inner.collect();
            let source_is_table = tabular || !ops.is_empty();
            match head_of(head.clone()) {
                Head::Name(n) if source_is_table => {
                    a.tables.insert(n);
                }
                Head::Paren(pp) if source_is_table => {
                    for c in pp.into_inner() {
                        walk(c, true, a);
                    }
                }
                _ => walk(head, false, a),
            }
            for op in ops {
                walk(op, false, a);
            }
            return;
        }
        Rule::tabular_operand | Rule::find_source => {
            for c in p.into_inner() {
                match c.as_rule() {
                    Rule::paren_pipe => {
                        for x in c.into_inner() {
                            walk(x, true, a);
                        }
                    }
                    Rule::table_pattern => {
                        a.table_patterns.insert(c.as_str().to_string());
                    }
                    Rule::postfix => match head_of(c.clone()) {
                        Head::Name(n) => {
                            a.tables.insert(n);
                        }
                        _ => walk(c, false, a),
                    },
                    _ => walk(c, true, a),
                }
            }
            return;
        }
        Rule::table_pattern => {
            a.table_patterns.insert(p.as_str().to_string());
            return;
        }
        Rule::find_op | Rule::search_op => {
            if !p.clone().into_inner().any(|c| c.as_rule() == Rule::kw_in) {
                a.unscoped_search = true;
            }
        }
        Rule::externaldata_op => a.external_data = true,
        Rule::count_op => a.ungrouped_aggregate = true,
        Rule::summarize_op => {
            if !p.clone().into_inner().any(|c| c.as_rule() == Rule::kw_by) {
                a.ungrouped_aggregate = true;
            }
        }
        Rule::typed_literal => {
            let t = p.as_str().trim_start().to_ascii_lowercase();
            if t.starts_with("datetime") || t.starts_with("date(") || t.starts_with("date ") {
                a.time_literals = true;
            }
            return;
        }
        Rule::plugin_call => {
            if let Some(n) = p.clone().into_inner().next() {
                a.plugins.insert(name_text(n).to_ascii_lowercase());
            }
        }
        Rule::invoke_op => {
            if let Some(post) = p
                .clone()
                .into_inner()
                .find(|c| c.as_rule() == Rule::postfix)
                && let Some(n) = post
                    .into_inner()
                    .next()
                    .filter(|n| n.as_rule() == Rule::name_ref)
            {
                a.invoked.insert(name_text(n));
            }
        }
        Rule::postfix => {
            call_facts(&p, a);
            // A callee is a function, not a column: walk everything but `name(...)` heads.
            let parts: Vec<Pair<'_, Rule>> = p.into_inner().collect();
            for (i, part) in parts.iter().enumerate() {
                let callee = part.as_rule() == Rule::name_ref
                    && parts
                        .get(i + 1)
                        .is_some_and(|n| n.as_rule() == Rule::call_args);
                if !callee {
                    walk(part.clone(), false, a);
                }
            }
            return;
        }
        _ => {}
    }
    let rule = format!("{:?}", p.as_rule());
    if rule.ends_with("_op") && !EXPRESSION_OPERATORS.contains(&p.as_rule()) {
        a.operators.insert(rule);
    }
    for c in p.into_inner() {
        walk(c, false, a);
    }
}

/// Function calls in a postfix chain: `name(args)`, `cluster('c').database('d').T`, `table('T')`.
fn call_facts(p: &Pair<'_, Rule>, a: &mut Analysis) {
    let parts: Vec<Pair<'_, Rule>> = p.clone().into_inner().collect();
    for (i, part) in parts.iter().enumerate() {
        if part.as_rule() != Rule::call_args || i == 0 {
            continue;
        }
        let callee = &parts[i - 1];
        let name = match callee.as_rule() {
            Rule::name_ref => name_text(callee.clone()),
            Rule::member => callee
                .clone()
                .into_inner()
                .next()
                .map(|n| name_text(n))
                .unwrap_or_default(),
            _ => continue,
        };
        match name.as_str() {
            "cluster" | "database" => a.cross_cluster = true,
            "external_table" => a.external_data = true,
            "table" => {
                let arg = part.clone().into_inner().next().map(head_of_string);
                if let Some(Some(t)) = arg {
                    a.tables.insert(t);
                }
            }
            _ => {}
        }
        a.functions.insert(name);
    }
}

/// The value of an argument that is a single string literal.
fn head_of_string(p: Pair<'_, Rule>) -> Option<String> {
    let mut cur = p;
    loop {
        if cur.as_rule() == Rule::string_lit {
            return Some(unquote(cur.as_str()));
        }
        let mut inner = cur.clone().into_inner();
        match (inner.next(), inner.next()) {
            (Some(only), None) => cur = only,
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_used_and_declared_names() {
        let a = analyze(
            "let lookback = 7d;\nDeviceProcessEvents\n| where Timestamp > ago(lookback) and ProcessCommandLine has \"-enc\"\n\
             | extend Lower = tolower(ProcessCommandLine), Extra = AdditionalFields.Foo\n\
             | join kind=inner (DeviceInfo | project DeviceId, OSPlatform) on $left.DeviceId == $right.DeviceId\n\
             | project-rename Host = DeviceName\n| summarize Hits = count() by Host, bin(Timestamp, 1h)",
        )
        .unwrap();
        for n in [
            "Timestamp",
            "ProcessCommandLine",
            "DeviceId",
            "OSPlatform",
            "DeviceName",
            "Host",
            "lookback",
            "AdditionalFields",
        ] {
            assert!(a.names.contains(n), "{n} in {:?}", a.names);
        }
        for f in ["ago", "tolower", "count", "bin"] {
            assert!(!a.names.contains(f), "{f} is a function");
        }
        assert!(!a.names.contains("Foo"), "member names are not columns");
        assert!(!a.names.contains("DeviceProcessEvents") && !a.names.contains("DeviceInfo"));
        for d in ["Lower", "Extra", "Host", "Hits"] {
            assert!(a.declared.contains(d), "{d} in {:?}", a.declared);
        }
    }

    #[test]
    fn flags_ungrouped_aggregates_and_time_literals() {
        let g = analyze("DeviceProcessEvents | summarize n = count() by DeviceName").unwrap();
        assert!(!g.ungrouped_aggregate && !g.time_literals);
        assert!(
            analyze("DeviceProcessEvents | summarize count()")
                .unwrap()
                .ungrouped_aggregate
        );
        assert!(
            analyze("DeviceProcessEvents | count")
                .unwrap()
                .ungrouped_aggregate
        );
        let t = analyze("DeviceProcessEvents | where Timestamp > datetime(2026-11-01) | take 5")
            .unwrap();
        assert!(t.time_literals && t.operators.contains("take_op"));
        assert!(
            !analyze("DeviceInfo | extend d = todatetime('x')")
                .unwrap()
                .time_literals
        );
    }

    #[test]
    fn reports_shape_columns_and_operators() {
        let a = analyze(
            "DeviceProcessEvents\n| where Timestamp > ago(1d) and FileName =~ 'cmd.exe'\n\
             | summarize count(), Hosts = dcount(DeviceId) by AccountName\n| project-away count_\n| top 5 by Hosts desc",
        )
        .unwrap();
        assert!(a.row_limited() && a.time_narrowed() && !a.ungrouped_aggregate);
        let cols: Vec<String> = a.columns().into_iter().collect();
        assert_eq!(cols, ["AccountName", "DeviceId", "FileName", "Timestamp"]);
        let ops: Vec<String> = a.operator_keywords().into_iter().collect();
        assert_eq!(ops, ["project-away", "summarize", "top", "where"]);
        let b = analyze("DeviceInfo | where OSPlatform == 'Linux' | distinct DeviceName").unwrap();
        assert!(!b.row_limited() && !b.time_narrowed());
        assert!(
            analyze("DeviceInfo | where Timestamp > datetime(2026-01-01)")
                .unwrap()
                .time_narrowed()
        );
        assert!(analyze("DeviceInfo | limit 3").unwrap().row_limited());
    }

    #[test]
    fn unquotes_every_string_form() {
        assert_eq!(unquote("'a'"), "a");
        assert_eq!(unquote("@\"C:\\x\""), "C:\\x");
        assert_eq!(unquote("h'secret'"), "secret");
        assert_eq!(unquote("```multi\nline```"), "multi\nline");
    }
}
