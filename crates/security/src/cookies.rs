//! Cookie security analyzer.

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

/// Analyze cookies from Set-Cookie header values.
pub fn analyze_cookies(set_cookie_headers: &[String]) -> CookieReport {
    let cookies: Vec<CookieInfo> = set_cookie_headers.iter().map(|h| parse_cookie(h)).collect();
    let mut findings = Vec::new();

    for c in &cookies {
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
    }

    let score_modifier = compute_score(&cookies);
    CookieReport { cookies, findings, score_modifier }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_httponly_samesite() {
        let r = analyze_cookies(&["session=abc; Secure; HttpOnly; SameSite=Strict".into()]);
        assert_eq!(r.score_modifier, 5);
    }

    #[test]
    fn test_session_without_httponly() {
        let r = analyze_cookies(&["PHPSESSID=abc; Secure".into()]);
        assert_eq!(r.score_modifier, -30);
        assert!(r.findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_session_without_secure() {
        let r = analyze_cookies(&["JSESSIONID=abc; HttpOnly".into()]);
        assert_eq!(r.score_modifier, -40);
        assert!(r.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_tracker_cookies_detected() {
        let r = analyze_cookies(&["_ga=GA1.2.xxx; Path=/".into()]);
        assert!(r.cookies[0].is_tracker);
    }

    #[test]
    fn test_host_prefix() {
        let r = analyze_cookies(&["__Host-session=abc; Secure; Path=/".into()]);
        assert!(r.cookies[0].host_prefix);
    }

    #[test]
    fn test_no_cookies() {
        let r = analyze_cookies(&[]);
        assert_eq!(r.score_modifier, 0);
    }
}
