//! Accessibility tree snapshot: fetch AX tree and format as indented text.

use std::collections::HashMap;

use chromiumoxide::cdp::browser_protocol::accessibility::{AxNode, GetFullAxTreeParams};
use chromiumoxide::Page;

use super::types::{ActionOutput, SnapshotResult};

/// Take an accessibility tree snapshot of the current page.
pub(crate) async fn do_snapshot(
    page: &Page,
    label: Option<&str>,
) -> Result<ActionOutput, String> {
    let params = GetFullAxTreeParams::builder().build();
    let result = page
        .execute(params)
        .await
        .map_err(|e| format!("snapshot: {e}"))?;

    let nodes = result.result.nodes;

    // Build node_id -> index lookup for O(1) child resolution (avoids O(n^2)
    // from nodes.iter().position() on pages with many nodes).
    let id_to_idx: HashMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.node_id.as_ref().to_owned(), i))
        .collect();

    // Find root (no parent)
    let root_idx = nodes
        .iter()
        .position(|n| n.parent_id.is_none())
        .unwrap_or(0);

    // Recursively format tree
    let mut out = String::new();
    format_node(&nodes, &id_to_idx, root_idx, 0, &mut out);

    let label = label.unwrap_or("snapshot").to_owned();
    Ok(ActionOutput::Snapshot(SnapshotResult { label, tree: out }))
}

fn format_node(
    nodes: &[AxNode],
    id_to_idx: &HashMap<String, usize>,
    idx: usize,
    depth: usize,
    out: &mut String,
) {
    let node = &nodes[idx];
    if node.ignored {
        // Still recurse into ignored nodes' children
        if let Some(child_ids) = &node.child_ids {
            for cid in child_ids {
                if let Some(&ci) = id_to_idx.get(cid.as_ref()) {
                    format_node(nodes, id_to_idx, ci, depth, out);
                }
            }
        }
        return;
    }

    let role = node
        .role
        .as_ref()
        .and_then(|v| v.value.as_ref())
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Skip structurally noisy nodes deep in the tree
    if depth > 2 && matches!(role, "generic" | "none" | "unknown") {
        if let Some(child_ids) = &node.child_ids {
            for cid in child_ids {
                if let Some(&ci) = id_to_idx.get(cid.as_ref()) {
                    format_node(nodes, id_to_idx, ci, depth, out);
                }
            }
        }
        return;
    }

    let name = node
        .name
        .as_ref()
        .and_then(|v| v.value.as_ref())
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    out.push_str(&"  ".repeat(depth));
    out.push_str("- ");
    out.push_str(role);
    if let Some(n) = name {
        out.push_str(" \"");
        out.push_str(n);
        out.push('"');
    }
    out.push('\n');

    if let Some(child_ids) = &node.child_ids {
        for cid in child_ids {
            if let Some(&ci) = id_to_idx.get(cid.as_ref()) {
                format_node(nodes, id_to_idx, ci, depth + 1, out);
            }
        }
    }
}
