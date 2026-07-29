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

/// Count visible non-whitespace **characters** (not bytes) without allocating.
/// Skips content inside `<script>` and `<style>` tags.
///
/// Public so the post-extraction sanity gate (`content::extraction_gate_trips`,
/// issue #110) can measure visible text on the same basis as this detector —
/// comparing extracted bytes to raw bytes makes the ratio a function of markup
/// bloat, so both sides are reduced to visible text first.
///
/// Counts Unicode characters, not UTF-8 bytes: a CJK codepoint (3 bytes) and a
/// Latin letter (1 byte) each count as 1. Without this, the absolute floor
/// (`EXTRACTION_GATE_SOURCE_FLOOR = 500`) would fire at ~167 CJK chars or ~250
/// Cyrillic chars instead of 500 chars — exposing genuinely thin non-Latin
/// pages to the gate's false positive (issue #110 L1). The *ratio* survives
/// either basis (both sides inflate equally), but the floor does not.
///
/// Whitespace is detected via `char::is_whitespace` (Unicode `White_Space`),
/// which covers ASCII whitespace plus U+00A0 (NBSP) and U+3000 (ideographic
/// space) — the previous `is_ascii_whitespace` missed both, so they counted as
/// visible text.
pub fn visible_text_len(html: &str) -> usize {
    strip_tags_len_impl(html)
}

fn strip_tags_len(html: &str) -> usize {
    strip_tags_len_impl(html)
}

fn strip_tags_len_impl(html: &str) -> usize {
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
        } else if !in_tag && in_invisible == 0 {
            // Visible text: advance one full UTF-8 character and count it if
            // it is not whitespace. `i` is at a char boundary here — tag
            // delimiters (`<`, `>`) are ASCII and land on char boundaries, so
            // every entry to this branch starts at a char boundary. Counting
            // chars (not bytes) keeps the floor char-based for all scripts.
            let ch = lower[i..].chars().next().unwrap();
            if !ch.is_whitespace() {
                len += 1;
            }
            i += ch.len_utf8();
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

    // ─── visible_text_len counts characters, not bytes (issue #110 L1) ────────
    //
    // The extraction gate's absolute floor (500) must fire at 500 characters
    // for every script, not 500 UTF-8 bytes. Without char-counting, a CJK page
    // (3 bytes/char) crosses the floor at ~167 chars and a Cyrillic page
    // (2 bytes/char) at ~250 — exposing genuinely thin non-Latin pages to the
    // gate's false positive. The ratio survives either basis (both sides
    // inflate equally), but the floor does not.

    #[test]
    fn visible_text_len_counts_cjk_chars_not_bytes() {
        // 10 CJK chars = 30 UTF-8 bytes. Must count as 10, not 30.
        let html = "<p>こんにちは</p>"; // 5 hiragana chars
        assert_eq!(
            visible_text_len(html),
            5,
            "5 hiragana chars must count as 5, not {} bytes",
            "こんにちは".len()
        );
    }

    #[test]
    fn visible_text_len_counts_cyrillic_chars_not_bytes() {
        // 6 Cyrillic chars = 12 UTF-8 bytes. Must count as 6, not 12.
        let html = "<p>Привет</p>"; // 6 Cyrillic chars
        assert_eq!(
            visible_text_len(html),
            6,
            "6 Cyrillic chars must count as 6, not {} bytes",
            "Привет".len()
        );
    }

    #[test]
    fn visible_text_len_cjk_floor_is_char_based() {
        // A CJK page with exactly 500 visible characters must be AT the floor,
        // not 3× above it (1500 bytes). This is the L1 regression: without
        // char-counting, a 500-char CJK page reads as 1500 and is firmly
        // above the floor when it should be at the boundary.
        let body = "あ".repeat(500); // 500 chars, 1500 bytes
        let html = format!("<html><body>{body}</body></html>");
        assert_eq!(
            visible_text_len(&html),
            500,
            "500 CJK chars must count as 500 (char-based floor), not 1500 (bytes)"
        );
    }

    #[test]
    fn visible_text_len_ideographic_space_is_whitespace() {
        // U+3000 (ideographic space) is whitespace — must NOT count as visible
        // text. The previous is_ascii_whitespace missed it (it is non-ASCII),
        // so it counted as 3 visible bytes. char::is_whitespace covers it.
        let html = "<p>あ\u{3000}い</p>"; // あ + ideographic space + い
        assert_eq!(
            visible_text_len(html),
            2,
            "U+3000 ideographic space must not count as visible text"
        );
    }

    #[test]
    fn visible_text_len_nbsp_is_whitespace() {
        // U+00A0 (no-break space) is whitespace — must NOT count as visible
        // text. The previous is_ascii_whitespace missed it (non-ASCII), so it
        // counted as 2 visible bytes.
        let html = "<p>a\u{00a0}b</p>"; // a + NBSP + b
        assert_eq!(
            visible_text_len(html),
            2,
            "U+00A0 NBSP must not count as visible text"
        );
    }

    #[test]
    fn visible_text_len_mixed_script_counts_chars() {
        // Mixed Latin + CJK + Cyrillic: each codepoint counts as 1.
        // "Hello" (5) + "世界" (2) + "Мир" (3) = 10 chars.
        let html = "<p>Hello世界Мир</p>";
        assert_eq!(
            visible_text_len(html),
            10,
            "mixed-script text must count codepoints, not bytes"
        );
    }

    #[test]
    fn visible_text_len_strips_script_style_with_multibyte() {
        // Script/style stripping must still work when the page has multibyte
        // chars — the tag detection is byte-based (ASCII) but the text counting
        // is char-based, and the two must not desync.
        let html = "<style>body{color:red}</style><p>テスト</p><script>var x=1</script>";
        assert_eq!(
            visible_text_len(html),
            3,
            "only the 3 katakana chars outside script/style must count"
        );
    }
}
