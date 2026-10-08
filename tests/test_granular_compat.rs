//! Default granular mode keeps the 88-tool contract and its safety annotations.

mod common;

use common::{base_config, test_server};

const MUTATING: [&str; 2] = [
    "defender_endpoint_live_response_run",
    "defender_library_file_upload",
];

#[test]
fn test_backward_compatibility_88_tools() {
    let tools = test_server("http://127.0.0.1:9", base_config()).list_tools_for_config();
    assert_eq!(tools.len(), 88);

    let mut mutating = Vec::new();
    for tool in &tools {
        let name = tool.name.as_ref();
        let a = tool.annotations.as_ref().expect("annotations");
        let is_mutating = MUTATING.contains(&name);
        if is_mutating {
            mutating.push(name);
        }
        assert_eq!(a.read_only_hint, Some(!is_mutating), "{name} readOnlyHint");
        assert_eq!(
            a.destructive_hint,
            Some(is_mutating),
            "{name} destructiveHint"
        );
        assert_eq!(
            a.idempotent_hint,
            Some(!is_mutating),
            "{name} idempotentHint"
        );
        assert_eq!(a.open_world_hint, Some(true), "{name} openWorldHint");
    }
    mutating.sort_unstable();
    assert_eq!(mutating, MUTATING);
}

#[test]
fn test_granular_read_only_listing_omits_both_mutators() {
    let config = microsoft_defender_mcp_server::cli::ServerConfig {
        read_only: true,
        ..base_config()
    };
    let tools = test_server("http://127.0.0.1:9", config).list_tools_for_config();
    assert_eq!(tools.len(), 86);
    assert!(tools.iter().all(|t| !MUTATING.contains(&t.name.as_ref())));
}
