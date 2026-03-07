//! CSP header string parser — thin wrapper around `content_security_policy` crate.

use content_security_policy::{CspList, PolicyDisposition, PolicySource};

use super::CspDirective;

/// Parse a raw CSP header using the spec-compliant W3C CSP Level 3 parser.
/// Returns a `CspList` for advanced checks (e.g. `should_request_be_blocked`).
pub fn parse_csp_list(raw: &str) -> CspList {
    CspList::parse(raw, PolicySource::Header, PolicyDisposition::Enforce)
}

/// Parse a CSP header into our `CspDirective` structs for compatibility
/// with existing checks. Extracts directives from the first policy only
/// (single-policy headers). For multi-policy, use `parse_csp_list`.
pub fn parse_csp(raw: &str) -> Vec<CspDirective> {
    let csp_list = parse_csp_list(raw);
    csp_list
        .0
        .first()
        .map(|policy| {
            policy
                .directive_set
                .iter()
                .map(|d| CspDirective {
                    name: d.name.clone(),
                    values: d.value.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Count total policies in a CSP header (comma-separated).
pub fn policy_count(raw: &str) -> usize {
    parse_csp_list(raw).0.len()
}

pub fn get_directive_values<'a>(
    directives: &'a [CspDirective],
    name: &str,
) -> Option<&'a Vec<String>> {
    directives.iter().find(|d| d.name == name).map(|d| &d.values)
}

pub fn get_script_src_values<'a>(
    directives: &'a [CspDirective],
) -> Option<&'a Vec<String>> {
    get_directive_values(directives, "script-src")
        .or_else(|| get_directive_values(directives, "default-src"))
}

pub fn has_value(values: &[String], val: &str) -> bool {
    values.iter().any(|v| v == val)
}

pub fn has_nonce_or_hash(values: &[String]) -> bool {
    values.iter().any(|v| {
        v.starts_with("'nonce-")
            || v.starts_with("'sha256-")
            || v.starts_with("'sha384-")
            || v.starts_with("'sha512-")
    })
}
