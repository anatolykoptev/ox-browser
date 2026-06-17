//! Heuristic detection of JS-only pages that need Chrome rendering.

/// Minimum visible text (after tag stripping) for a page to be "real".
const MIN_TEXT_LEN: usize = 200;

/// If HTML is larger than this and the text-to-HTML ratio is below TEXT_RATIO_THRESHOLD,
/// the page is likely SSR-shell with minimal pre-rendered content.
const LARGE_HTML_THRESHOLD: usize = 10_000;
/// Text must be at least 3% of HTML size to be considered "real content".
const TEXT_RATIO_THRESHOLD: f64 = 0.03;

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

/// Markers for SPA frameworks that rely heavily on client-side rendering.
const SPA_FRAMEWORK_MARKERS: &[&str] = &[
    "ng-version=",              // Angular
    "__NUXT__",                 // Nuxt
    "__remixContext",           // Remix
    "window.__INITIAL_STATE__", // Vue SSR shells
    "data-reactroot",           // React SSR (old)
];

/// Returns true if HTML looks like a JS shell without real content.
pub fn needs_js_rendering(html: &str) -> bool {
    for marker in JS_SHELL_MARKERS {
        if html.contains(marker) {
            return true;
        }
    }
    let text_len = strip_tags_len(html);
    if text_len < MIN_TEXT_LEN {
        return true;
    }

    // Large HTML but very little visible text relative to HTML size → partial SSR shell.
    if html.len() >= LARGE_HTML_THRESHOLD {
        let ratio = text_len as f64 / html.len() as f64;
        if ratio < TEXT_RATIO_THRESHOLD {
            // Only trigger if we also see SPA framework markers.
            for marker in SPA_FRAMEWORK_MARKERS {
                if html.contains(marker) {
                    return true;
                }
            }
        }
    }

    false
}

/// Count visible non-whitespace text length without allocating.
/// Skips content inside `<script>` and `<style>` tags.
fn strip_tags_len(html: &str) -> usize {
    let mut len = 0;
    let mut in_tag = false;
    let mut in_invisible = 0u8; // depth: >0 means inside script/style
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            in_tag = true;
            // Check for <script or <style
            if starts_with_at(bytes, i, b"<script") {
                in_invisible = in_invisible.saturating_add(1);
            } else if starts_with_at(bytes, i, b"</script") {
                in_invisible = in_invisible.saturating_sub(1);
            } else if starts_with_at(bytes, i, b"<style") {
                in_invisible = in_invisible.saturating_add(1);
            } else if starts_with_at(bytes, i, b"</style") {
                in_invisible = in_invisible.saturating_sub(1);
            }
            i += 1;
        } else if bytes[i] == b'>' {
            in_tag = false;
            i += 1;
        } else if !in_tag && in_invisible == 0 && !bytes[i].is_ascii_whitespace() {
            len += 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    len
}

fn starts_with_at(bytes: &[u8], pos: usize, prefix: &[u8]) -> bool {
    bytes.len() >= pos + prefix.len() && &bytes[pos..pos + prefix.len()] == prefix
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

    #[test]
    fn detects_angular_ssr_shell() {
        // Large HTML with Angular marker but very little visible text.
        let filler_tags = "<script>".repeat(1500); // bulk up HTML without adding text
        let html = format!(
            r#"<html ng-version="19.0"><body><app-root>{filler_tags}<p>Short text</p></app-root></body></html>"#
        );
        assert!(html.len() >= 10_000);
        assert!(needs_js_rendering(&html));
    }

    #[test]
    fn accepts_large_page_with_content() {
        // Large HTML with enough visible text ratio — should NOT trigger.
        // We need text > 3% of HTML. Make HTML ~12KB and text ~500 chars (4%).
        let padding = "<div class=\"x\">".repeat(800); // bulk HTML
        let content = "word ".repeat(100); // 500 chars of text
        let html = format!(
            r#"<html ng-version="19.0"><body>{padding}<article>{content}</article></body></html>"#
        );
        assert!(html.len() >= 10_000);
        assert!(!needs_js_rendering(&html));
    }
}
