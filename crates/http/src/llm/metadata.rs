//! Metadata header building for LLM-optimized output.
//!
//! Produces `> ` prefixed lines with URL, title, author, etc.
//! Omits empty/zero fields to minimize token waste.
//!
//! Ported from webclaw `crates/webclaw-core/src/llm/metadata.rs` (MIT),
//! adapted to ox-browser's [`ReadOutput`] type.

use crate::content::ReadOutput;

pub(crate) fn build_metadata_header(out: &mut String, result: &ReadOutput) {
    if !result.url.is_empty() {
        out.push_str(&format!("> URL: {}\n", result.url));
    }
    if !result.title.is_empty() {
        out.push_str(&format!("> Title: {}\n", result.title));
    }
    if !result.excerpt.is_empty() {
        out.push_str(&format!("> Description: {}\n", result.excerpt));
    }
    if !result.author.is_empty() {
        out.push_str(&format!("> Author: {}\n", result.author));
    }
    if !result.published_at.is_empty() {
        out.push_str(&format!("> Published: {}\n", result.published_at));
    }
    if !result.site_name.is_empty() {
        out.push_str(&format!("> Site: {}\n", result.site_name));
    }
    if !result.language.is_empty() {
        out.push_str(&format!("> Language: {}\n", result.language));
    }
    if result.length > 0 {
        out.push_str(&format!("> Length: {}\n", result.length));
    }
}
