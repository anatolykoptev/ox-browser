//! Heuristic detection of JS-only pages that need Chrome rendering.

/// Minimum visible text (after tag stripping) for a page to be "real".
const MIN_TEXT_LEN: usize = 200;

/// Markers indicating the page is a JS shell or CF challenge.
const JS_SHELL_MARKERS: &[&str] = &[
    "challenge-platform",
    "_cf_chl_opt",
    "Enable JavaScript",
    "enable JavaScript",
    "JavaScript is required",
    "You need to enable JavaScript",
    "id=\"__next\"></div>",
    "id=\"root\"></div>",
    "id=\"app\"></div>",
];

/// Returns true if HTML looks like a JS shell without real content.
pub fn needs_js_rendering(html: &str) -> bool {
    for marker in JS_SHELL_MARKERS {
        if html.contains(marker) {
            return true;
        }
    }
    let text_len = strip_tags_len(html);
    text_len < MIN_TEXT_LEN
}

/// Count visible non-whitespace text length without allocating.
fn strip_tags_len(html: &str) -> usize {
    let mut len = 0;
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag && !ch.is_whitespace() => len += 1,
            _ => {}
        }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cf_challenge() {
        let html = r#"<html><body><script>challenge-platform</script></body></html>"#;
        assert!(needs_js_rendering(html));
    }

    #[test]
    fn detects_react_shell() {
        let html = r#"<html><head><script src="app.js"></script></head><body><div id="root"></div></body></html>"#;
        assert!(needs_js_rendering(html));
    }

    #[test]
    fn accepts_real_content() {
        let content = "a".repeat(250);
        let html = format!(r#"<html><body><h1>Title</h1><p>{content}</p></body></html>"#);
        assert!(!needs_js_rendering(&html));
    }

    #[test]
    fn detects_noscript() {
        let html = r#"<html><body><noscript>You need to enable JavaScript to run this app.</noscript></body></html>"#;
        assert!(needs_js_rendering(html));
    }

    #[test]
    fn detects_nextjs_shell() {
        let html = r#"<html><body><div id="__next"></div><script src="/_next/static/chunks/main.js"></script></body></html>"#;
        assert!(needs_js_rendering(html));
    }
}
