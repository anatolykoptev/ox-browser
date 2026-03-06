//! Cookie security analyzer.

use psl;
use serde::Serialize;

use super::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct CookieReport {
    pub cookies: Vec<CookieInfo>,
    pub findings: Vec<CookieFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub host_prefix: bool,
    pub secure_prefix: bool,
    pub is_session: bool,
    pub is_tracker: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieFinding {
    pub cookie: String,
    pub description: String,
    pub severity: Severity,
}

const SESSION_PATTERNS: &[&str] = &[
    "sess", "sid", "token", "auth", "login", "phpsessid",
    "jsessionid", "asp.net_sessionid", "connect.sid",
    "laravel_session", "wp-settings",
];

const TRACKER_NAMES: &[&str] = &[
    "_ga", "_gid", "_fbp", "_fbc", "__gads", "__gpi",
    "_gcl_au", "IDE", "NID", "fr",
];

fn is_session_cookie(name: &str) -> bool {
    let lower = name.to_lowercase();
    SESSION_PATTERNS.iter().any(|p| lower.contains(p))
}

fn is_tracker_cookie(name: &str) -> bool {
    TRACKER_NAMES.contains(&name)
}

fn parse_cookie(header: &str) -> CookieInfo {
    let parts: Vec<&str> = header.split(';').collect();
    let name = parts[0]
        .split_once('=')
        .map(|(n, _)| n.trim().to_string())
        .unwrap_or_default();

    let attrs: Vec<String> = parts[1..].iter().map(|s| s.trim().to_lowercase()).collect();
    let secure = attrs.iter().any(|a| a == "secure");
    let http_only = attrs.iter().any(|a| a == "httponly");
    let same_site = attrs.iter().find_map(|a| {
        a.strip_prefix("samesite=").map(|v| {
            let mut s = v.to_string();
            if let Some(c) = s.get_mut(0..1) {
                c.make_ascii_uppercase();
            }
            s
        })
    });
    let has_path_root = attrs.iter().any(|a| a == "path=/");
    let has_domain = attrs.iter().any(|a| a.starts_with("domain="));

    let host_prefix = name.starts_with("__Host-") && secure && has_path_root && !has_domain;
    let secure_prefix = name.starts_with("__Secure-") && secure;

    CookieInfo {
        is_session: is_session_cookie(&name),
        is_tracker: is_tracker_cookie(&name),
        name,
        secure,
        http_only,
        same_site,
        host_prefix,
        secure_prefix,
    }
}

fn compute_score(cookies: &[CookieInfo]) -> i32 {
    if cookies.is_empty() {
        return 0;
    }
    let all_secure = cookies.iter().all(|c| c.secure);
    let sessions: Vec<&CookieInfo> = cookies.iter().filter(|c| c.is_session).collect();
    let session_all_httponly = sessions.iter().all(|c| c.http_only);
    let any_samesite = cookies.iter().any(|c| c.same_site.is_some());

    if sessions.iter().any(|c| !c.secure) {
        return -40;
    }
    if sessions.iter().any(|c| !c.http_only) {
        return -30;
    }
    if !all_secure {
        return -20;
    }
    if all_secure && session_all_httponly && any_samesite {
        return 5;
    }
    0
}

/// Extract the `domain=` attribute value from a Set-Cookie string.
fn extract_domain_attr(cookie_str: &str) -> Option<String> {
    cookie_str
        .split(';')
        .skip(1)
        .map(|s| s.trim())
        .find_map(|attr| {
            let lower = attr.to_lowercase();
            if lower.starts_with("domain=") {
                Some(attr[7..].trim_start_matches('.').to_lowercase())
            } else {
                None
            }
        })
}

/// Extract host (no port) from a URL string.
fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = without_scheme.split('/').next()?;
    Some(host.split(':').next().unwrap_or("").to_lowercase())
}

/// Check cookie domain scope using the Public Suffix List.
fn check_domain_scope(cookie_str: &str, page_host: &str) -> Option<CookieFinding> {
    let domain_val = extract_domain_attr(cookie_str)?;
    let name = cookie_str
        .split(';')
        .next()
        .and_then(|p| p.split_once('='))
        .map(|(n, _)| n.trim().to_string())
        .unwrap_or_default();

    // If the domain attribute is a public suffix itself -> Critical
    if psl::domain(domain_val.as_bytes()).is_none() {
        return Some(CookieFinding {
            cookie: name,
            description: format!(
                "Cookie domain '.{domain_val}' is a public suffix \
                 -- could be shared across unrelated sites"
            ),
            severity: Severity::Critical,
        });
    }

    // Cookie domain broader than page host -> loosely scoped
    let page = extract_host(&format!("http://{page_host}"))?;
    if domain_val != page && page.ends_with(&format!(".{domain_val}")) {
        return Some(CookieFinding {
            cookie: name,
            description: format!(
                "Loosely scoped cookie: domain '.{domain_val}' set from '{page}'"
            ),
            severity: Severity::Medium,
        });
    }

    None
}

/// Analyze cookies from Set-Cookie header values.
pub fn analyze_cookies(set_cookie_headers: &[String], page_url: &str) -> CookieReport {
    let cookies: Vec<CookieInfo> = set_cookie_headers.iter().map(|h| parse_cookie(h)).collect();
    let mut findings = Vec::new();
    let page_host = extract_host(page_url).unwrap_or_default();

    for (i, c) in cookies.iter().enumerate() {
        if c.is_session && !c.secure {
            findings.push(CookieFinding {
                cookie: c.name.clone(),
                description: "Session cookie missing Secure flag".into(),
                severity: Severity::Critical,
            });
        }
        if c.is_session && !c.http_only {
            findings.push(CookieFinding {
                cookie: c.name.clone(),
                description: "Session cookie missing HttpOnly flag".into(),
                severity: Severity::High,
            });
        }
        if let Some(finding) = check_domain_scope(&set_cookie_headers[i], &page_host) {
            findings.push(finding);
        }
    }

    let score_modifier = compute_score(&cookies);
    CookieReport { cookies, findings, score_modifier }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "https://app.example.com/path";

    #[test]
    fn test_secure_httponly_samesite() {
        let r = analyze_cookies(&["session=abc; Secure; HttpOnly; SameSite=Strict".into()], PAGE);
        assert_eq!(r.score_modifier, 5);
    }

    #[test]
    fn test_session_without_httponly() {
        let r = analyze_cookies(&["PHPSESSID=abc; Secure".into()], PAGE);
        assert_eq!(r.score_modifier, -30);
        assert!(r.findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_session_without_secure() {
        let r = analyze_cookies(&["JSESSIONID=abc; HttpOnly".into()], PAGE);
        assert_eq!(r.score_modifier, -40);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_tracker_cookies_detected() {
        let r = analyze_cookies(&["_ga=GA1.2.xxx; Path=/".into()], PAGE);
        assert!(r.cookies[0].is_tracker);
    }

    #[test]
    fn test_host_prefix() {
        let r = analyze_cookies(&["__Host-session=abc; Secure; Path=/".into()], PAGE);
        assert!(r.cookies[0].host_prefix);
    }

    #[test]
    fn test_no_cookies() {
        let r = analyze_cookies(&[], PAGE);
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_public_suffix_domain_critical() {
        let r = analyze_cookies(
            &["track=1; Domain=.co.uk".into()],
            "https://example.co.uk/",
        );
        let finding = r.findings.iter().find(|f| f.severity == Severity::Critical);
        assert!(finding.is_some(), "expected Critical for public suffix domain");
        assert!(finding.unwrap().description.contains("public suffix"));
    }

    #[test]
    fn test_loosely_scoped_domain_medium() {
        let r = analyze_cookies(
            &["id=abc; Domain=.example.com".into()],
            "https://app.example.com/page",
        );
        let finding = r.findings.iter().find(|f| f.severity == Severity::Medium);
        assert!(finding.is_some(), "expected Medium for loosely scoped cookie");
        assert!(finding.unwrap().description.contains("Loosely scoped"));
    }

    #[test]
    fn test_no_domain_attr_no_finding() {
        let r = analyze_cookies(
            &["id=abc; Secure; HttpOnly".into()],
            "https://app.example.com/",
        );
        let domain_findings: Vec<_> = r.findings.iter()
            .filter(|f| {
                f.description.contains("public suffix")
                    || f.description.contains("Loosely")
            })
            .collect();
        assert!(domain_findings.is_empty());
    }
}
