//! MCP resources: the KQL hunting skill, served as markdown under a `skill://` URI so that agent
//! runtimes which resolve skills from MCP resources can load it by name.

use rmcp::model::{ReadResourceResult, Resource, ResourceContents};

/// URI of the KQL hunting skill.
pub const KQL_HUNTING_URI: &str = "skill://ms-defender/kql-hunting";

/// The KQL hunting skill: how to use `defender_hunting`, its policy, and hunting shapes.
pub const KQL_HUNTING: &str = include_str!("resources/kql_hunting.md");

const MARKDOWN: &str = "text/markdown";

/// Every resource this server serves.
pub fn list() -> Vec<Resource> {
    vec![
        Resource::new(KQL_HUNTING_URI, "kql-hunting")
            .with_title("KQL hunting skill for Microsoft Defender XDR")
            .with_description(
                "How to hunt with defender_hunting (validate, run, schema, tables): the query policy, \
                 row bounds and truncation, timespan, entity columns, hunting shapes and Defender \
                 pitfalls. Read it before the first query.",
            )
            .with_mime_type(MARKDOWN)
            .with_size(KQL_HUNTING.len() as u64),
    ]
}

/// The contents of the resource at `uri`, if this server has it.
pub fn read(uri: &str) -> Option<ReadResourceResult> {
    (uri == KQL_HUNTING_URI).then(|| {
        ReadResourceResult::new(vec![
            ResourceContents::text(KQL_HUNTING, KQL_HUNTING_URI).with_mime_type(MARKDOWN),
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fenced KQL blocks of the skill.
    fn kql_blocks(md: &str) -> Vec<String> {
        let mut blocks = Vec::new();
        let mut current: Option<Vec<&str>> = None;
        for line in md.lines() {
            match (&mut current, line.trim()) {
                (None, "```kql") => current = Some(Vec::new()),
                (Some(lines), "```") => {
                    blocks.push(lines.join("\n"));
                    current = None;
                }
                (Some(lines), _) => lines.push(line),
                (None, _) => {}
            }
        }
        blocks
    }

    #[test]
    fn every_example_passes_validate() {
        let blocks = kql_blocks(KQL_HUNTING);
        assert!(blocks.len() >= 6, "found {} KQL examples", blocks.len());
        for q in blocks {
            let v = crate::hunting::validate(&q);
            assert!(v.is_valid(), "{:?}\n---\n{q}", v.findings);
            let unknown: Vec<_> = v
                .findings
                .iter()
                .filter(|f| f.code == "unknown_table")
                .collect();
            assert!(unknown.is_empty(), "{unknown:?}\n---\n{q}");
        }
    }

    #[test]
    fn lists_and_reads_the_skill() {
        let listed = list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].uri, KQL_HUNTING_URI);
        let read = read(KQL_HUNTING_URI).expect("skill resource");
        match &read.contents[0] {
            ResourceContents::TextResourceContents {
                text, mime_type, ..
            } => {
                assert!(text.contains("defender_hunting"));
                assert_eq!(mime_type.as_deref(), Some(MARKDOWN));
            }
            other => panic!("unexpected contents {other:?}"),
        }
        assert!(super::read("skill://ms-defender/other").is_none());
    }
}
