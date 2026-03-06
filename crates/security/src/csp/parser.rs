//! CSP header string parser.

use super::CspDirective;

/// Parse a CSP header string into directives.
/// CSP format: "directive1 value1 value2; directive2 value3"
pub fn parse_csp(raw: &str) -> Vec<CspDirective> {
    raw.split(';')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut tokens = trimmed.split_whitespace();
            let name = tokens.next()?.to_lowercase();
            let values: Vec<String> = tokens.map(|t| t.to_string()).collect();
            Some(CspDirective { name, values })
        })
        .collect()
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
