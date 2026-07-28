//! DOM-level noise filter — removes structural noise elements (cookie banners,
//! nav sidebars, social share widgets, modals, etc.) from the DOM before
//! content extraction.
//!
//! Tailwind-safe: animation utilities (`animate-spin`, `animate-pulse`) and
//! CSS custom properties (`[--foo:bar]`) are NOT noise. BEM component names
//! (`card__title`, `button--primary`) are NOT noise — they're structural
//! naming, not decorative classes.
//!
//! This runs as a pre-readability filter, complementing the CSS-selector-based
//! `NOISE_SELECTORS` in `content.rs`. It catches noise that CSS selectors
//! can't express: partial class matches, ID prefixes, ARIA roles on non-standard
//! elements, and combined heuristics.
//!
//! Clean-room adaptation informed by webclaw's `crates/webclaw-core/src/noise.rs`
//! (AGPL-3.0). Rewritten from scratch for `dom_query::NodeRef` — not a port.
//!
//! Issue #59: Noise filter — Tailwind-safe DOM noise detection.

use dom_query::Document;
use dom_query::NodeRef;

// ---------------------------------------------------------------------------
// Noise tag names — elements that are always noise
// ---------------------------------------------------------------------------

const NOISE_TAGS: &[&str] = &[
    "script",
    "style",
    "noscript",
    "iframe",
    "svg",
    "nav",
    "aside",
    "footer",
    "header",
    "video",
    "audio",
    "canvas",
    // NOTE: <form> is NOT here — ASP.NET wraps entire page body in <form>.
    // Forms are handled with a heuristic in is_noise() that distinguishes
    // small input forms (noise) from page-wrapping forms (not noise).
    // NOTE: <picture> is NOT here — it's a responsive image container.
];

// ---------------------------------------------------------------------------
// Noise ARIA roles — kept minimal to avoid false positives (webclaw approach)
// ---------------------------------------------------------------------------

const NOISE_ROLES: &[&str] = &["navigation", "banner", "complementary", "contentinfo"];

// ---------------------------------------------------------------------------
// Noise classes — exact token matches against class attribute tokens
// ---------------------------------------------------------------------------

/// Class tokens that indicate noise when matched EXACTLY (after splitting
/// the class attribute on whitespace). Uses webclaw's approach: substring
/// matching like `class.contains("nav")` causes false positives on classes
/// like `UnderlineNav`, `color-bg-header`, etc. Token matching avoids this.
const NOISE_CLASSES: &[&str] = &[
    "header",
    "top",
    "navbar",
    "footer",
    "bottom",
    "sidebar",
    "modal",
    "popup",
    "overlay",
    "ad",
    "ads",
    "advert",
    "lang-selector",
    "language",
    "social",
    "social-media",
    "social-links",
    "menu",
    "navigation",
    "breadcrumbs",
    "breadcrumb",
    "share",
    "widget",
    "cookie",
    "newsletter",
    "subscribe",
    "skip-link",
    "sr-only",
    "visually-hidden",
    "notification",
    "alert",
    "toast",
    "pagination",
    "pager",
    "signup",
    "login-form",
    "search-form",
    "related-posts",
    "recommended",
];

// ---------------------------------------------------------------------------
// Noise IDs — exact matches against id attribute
// ---------------------------------------------------------------------------

const NOISE_IDS: &[&str] = &[
    "header",
    "footer",
    "nav",
    "sidebar",
    "menu",
    "modal",
    "popup",
    "cookie",
    "breadcrumbs",
    "widget",
    "ad",
    "social",
    "share",
    "newsletter",
    "subscribe",
    "comments",
    "related",
];

/// Cookie consent platform ID/class prefixes — substring matched against
/// both id and class attributes. These platforms generate huge overlays that
/// are always noise.
const COOKIE_CONSENT_PREFIXES: &[&str] = &[
    "onetrust",
    "optanon",
    "ot-sdk",
    "cookiebot",
    "CybotCookiebot",
    "cc-",
    "cookie-law",
    "gdpr",
    "consent-",
    "cmp-",
    "sp_message",
    "qc-cmp",
    "trustarc",
    "evidon",
];

// ---------------------------------------------------------------------------
// is_noise — single-element check
// ---------------------------------------------------------------------------

/// Check if a DOM element is noise based on its tag name, ARIA role,
/// class patterns, and ID patterns.
///
/// Tailwind-safe: animation utilities and CSS custom properties do NOT
/// trigger noise classification. BEM component names (`card__title`) are
/// NOT noise — they're structural naming.
/// Safety valve threshold: if a noise-matched element has more than this
/// many characters of text, it's almost certainly a broken wrapper that
/// absorbed the page content — treat it as content, not noise.
const NOISE_TEXT_LIMIT: usize = 5000;

pub(crate) fn is_noise(node: &NodeRef) -> bool {
    if !node.is_element() {
        return false;
    }

    // Never treat <body> or <html> as noise.
    if let Some(name) = node.node_name() {
        let lower = name.to_lowercase();
        if lower == "body" || lower == "html" {
            return false;
        }

        // 1. Tag name check
        if NOISE_TAGS.contains(&lower.as_str()) {
            return true;
        }

        // <form> heuristic: ASP.NET wraps the entire page body in a single <form>.
        // These page-wrapping forms contain hundreds of words of real content.
        // Small forms (login, search, newsletter) are noise.
        if lower == "form" {
            let text_len = node.text().len();
            // A form with substantial text (>500 chars) is likely a page wrapper, not noise.
            if text_len < 500 {
                return true;
            }
            // Also check noise classes — a big form with class="login-form" is still noise
            if let Some(class) = node.class() {
                let cl = class.to_lowercase();
                if cl.split_whitespace().any(|token| {
                    token == "login-form"
                        || token == "search-form"
                        || token == "subscribe"
                        || token == "signup"
                        || token == "newsletter"
                        || token == "contact"
                }) {
                    return true;
                }
            }
            return false;
        }
    }

    // 2. ARIA role check
    if let Some(role) = node.attr("role") {
        let role = role.to_lowercase();
        if NOISE_ROLES.contains(&role.as_str()) {
            return true;
        }
    }

    // 3. Class check — exact token matching (webclaw approach)
    if let Some(class) = node.class()
        && is_noise_class(&class.to_lowercase())
    {
        // Safety valve: malformed HTML can leave noise containers unclosed,
        // causing them to absorb the entire page content. A real header/nav/
        // footer rarely exceeds a few thousand characters of text. If a
        // noise-class element has massive text content, it's almost certainly
        // a broken wrapper — treat it as content, not noise.
        let text_len = node.text().len();
        if text_len > NOISE_TEXT_LIMIT {
            return false;
        }
        return true;
    }

    // 4. ID check — exact match with structural exclusion
    if let Some(id) = node.id_attr() {
        let id_lower = id.to_lowercase();
        if NOISE_IDS.contains(&id_lower.as_str()) && !is_structural_id(&id_lower) {
            let text_len = node.text().len();
            if text_len > NOISE_TEXT_LIMIT {
                return false;
            }
            return true;
        }
        // Cookie consent platform IDs (prefix match) — with safety valve:
        // malformed HTML can leave a cookie container unclosed, causing it
        // to absorb page content. Same NOISE_TEXT_LIMIT guard as exact IDs.
        let text_len = node.text().len();
        for prefix in COOKIE_CONSENT_PREFIXES {
            if id_lower.starts_with(prefix) {
                if text_len > NOISE_TEXT_LIMIT {
                    return false;
                }
                return true;
            }
        }
    }

    // 5. Cookie consent class detection (prefix/substring match for platform classes)
    // — with safety valve: same NOISE_TEXT_LIMIT guard as ID prefix match.
    if let Some(class) = node.class() {
        let class_lower = class.to_lowercase();
        let text_len = node.text().len();
        for prefix in COOKIE_CONSENT_PREFIXES {
            if class_lower.contains(prefix) {
                if text_len > NOISE_TEXT_LIMIT {
                    return false;
                }
                return true;
            }
        }
    }

    // 6. Hidden elements
    if is_hidden(node) {
        return true;
    }

    false
}

/// Check if a class attribute string contains noise patterns.
/// Uses exact token matching: splits the class attribute on whitespace and
/// checks each token against the noise list. This avoids false positives
/// where `UnderlineNav` contains `nav` as a substring but is not a navigation
/// noise element.
fn is_noise_class(class: &str) -> bool {
    for token in class.split_whitespace() {
        let lower = token.to_lowercase();
        if NOISE_CLASSES.contains(&lower.as_str()) {
            return true;
        }
        // Structural elements use compound names (FooterLinks, Header-nav, etc.)
        // These are always noise regardless of compound form.
        if lower.starts_with("footer")
            || lower.starts_with("header-")
            || lower.starts_with("nav-")
        {
            return true;
        }
    }
    is_ad_class(class)
}

/// Check if a class attribute contains ad-related tokens.
fn is_ad_class(class: &str) -> bool {
    class.split_whitespace().any(|token| {
        token == "ad"
            || token.starts_with("ad-")
            || token.starts_with("ad_")
            || token.ends_with("-ad")
            || token.ends_with("_ad")
    })
}

/// Check if an ID is structural (not noise even if it matches a noise pattern).
/// IDs containing these suffixes are app mount points, not noise containers.
fn is_structural_id(id: &str) -> bool {
    const STRUCTURAL_SUFFIXES: &[&str] =
        &["portal", "root", "container", "wrapper", "mount", "app"];
    STRUCTURAL_SUFFIXES.iter().any(|s| id.contains(s))
}

/// Check if an element is hidden via inline styles or ARIA.
///
/// NOTE: the HTML `hidden` attribute is intentionally NOT checked here.
/// React Suspense boundaries use `<div hidden id="S:N">` to wrap server-rendered
/// content that is revealed after hydration. The content IS in the HTML —
/// stripping it loses real content (e.g., feature card sections on nextjs.org).
/// Only `display:none`, `visibility:hidden`, and `aria-hidden="true"` are treated
/// as truly hidden.
fn is_hidden(node: &NodeRef) -> bool {
    if let Some(style) = node.attr("style") {
        let style = style.to_lowercase();
        if style.contains("display:none") || style.contains("display: none") {
            return true;
        }
        if style.contains("visibility:hidden") || style.contains("visibility: hidden") {
            return true;
        }
    }
    if node.has_attr("aria-hidden")
        && let Some(val) = node.attr("aria-hidden")
        && val.as_ref() == "true"
    {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// is_noise_descendant — ancestor walk
// ---------------------------------------------------------------------------

/// Check if any ancestor of the given element is noise.
/// Walks up the DOM tree checking each ancestor with `is_noise`.
///
/// Not used by `remove_noise` (which removes entire subtrees), but available
/// for text-level pipelines that need to skip elements whose ancestors are
/// noise without removing them from the DOM.
#[allow(dead_code)]
pub(crate) fn is_noise_descendant(node: &NodeRef) -> bool {
    for ancestor in node.ancestors(None) {
        if is_noise(&ancestor) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// remove_noise — DOM mutation
// ---------------------------------------------------------------------------

/// Remove all noise elements from the document.
///
/// Collects noise nodes first (to avoid mutating during iteration), then
/// removes them. Removing a node also removes its descendants, so
/// `is_noise_descendant` is not needed here — children of noise elements
/// are removed automatically.
///
/// This should be called AFTER `NOISE_SELECTORS` removal in `content.rs`,
/// as a second pass to catch noise that CSS selectors can't express.
pub fn remove_noise(doc: &Document) {
    // Collect all noise nodes. We use `select("*")` to get all elements,
    // then filter for noise. We must collect before removing to avoid
    // mutating the tree during iteration.
    let all_elements = doc.select("*");
    let noise_nodes: Vec<NodeRef> = all_elements
        .nodes()
        .iter()
        .filter(|n| is_noise(n))
        .cloned()
        .collect();

    for node in &noise_nodes {
        node.remove_from_parent();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dom_query::Document;

    fn count_noise(doc: &Document) -> usize {
        doc.select("*")
            .nodes()
            .iter()
            .filter(|n| is_noise(n))
            .count()
    }

    #[test]
    fn detects_nav_tag() {
        let html = r#"<html><body><nav><a href="/">Home</a></nav><article><p>Content</p></article></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn detects_footer_tag() {
        let html = r#"<html><body><footer>Copyright 2026</footer><main><p>Content</p></main></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn detects_cookie_consent_by_class() {
        let html = r#"<html><body><div class="cookie-consent-banner">We use cookies</div><div class="content">Real content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn detects_onetrust_by_id() {
        let html = r#"<html><body><div id="onetrust-banner-sdk">Cookie settings</div><div id="main-content">Real content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn detects_aria_navigation_role() {
        let html = r#"<html><body><div role="navigation"><a href="/">Home</a></div><div role="main"><p>Content</p></div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn detects_hidden_element() {
        let html =
            r#"<html><body><div style="display:none">Hidden</div><div>Visible</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn detects_aria_hidden() {
        let html = r#"<html><body><div aria-hidden="true">Hidden from screen readers</div><div aria-hidden="false">Visible</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn tailwind_animate_not_noise() {
        // "animate-menu-open" contains "menu" but should NOT be noise
        let html = r#"<html><body><div class="animate-menu-open">Animated menu content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(
            count_noise(&doc),
            0,
            "animate-menu-open should not be noise"
        );
    }

    #[test]
    fn tailwind_transition_not_noise() {
        // "transition-footer-fade" contains "footer" but should NOT be noise
        let html = r#"<html><body><div class="transition-footer-fade">Footer fade animation</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(
            count_noise(&doc),
            0,
            "transition-footer-fade should not be noise"
        );
    }

    #[test]
    fn real_nav_class_is_noise() {
        // Exact token match: "navbar" is in NOISE_CLASSES.
        // Note: "nav" alone is NOT in NOISE_CLASSES — we rely on the <nav> tag
        // for navigation elements, not the class, to avoid false positives on
        // classes like "post-nav" (article pagination).
        let html = r#"<html><body><div class="navbar">Navigation links</div><div class="article-body">Content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn nav_prefix_class_is_noise() {
        // Structural prefix: "nav-main" starts with "nav-"
        let html = r#"<html><body><div class="nav-main">Navigation links</div><div class="article-body">Content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn compound_nav_not_noise() {
        // "UnderlineNav" is a single token — does NOT match "nav" exactly.
        // This is the GitHub false-positive case that token matching fixes.
        let html = r#"<html><body><div class="UnderlineNav">Content here</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 0, "UnderlineNav should not be noise");
    }

    #[test]
    fn social_share_class_is_noise() {
        // Exact token match: "social" is in NOISE_CLASSES
        let html = r#"<html><body><div class="social share-buttons">Share on Twitter</div><div class="post-content">Article</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn newsletter_signup_is_noise() {
        // Exact token match: "newsletter" is in NOISE_CLASSES
        let html = r#"<html><body><div class="newsletter signup">Subscribe!</div><article>Content</article></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn bem_component_not_noise() {
        // BEM naming: "card__title", "button--primary" — structural, not noise
        let html = r#"<html><body><div class="card__title">Title</div><div class="button--primary">Click</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 0);
    }

    #[test]
    fn remove_noise_strips_banners() {
        let html = r#"<html><body><nav>Nav</nav><div class="cookie">Cookies</div><article><p>Real content</p></article><footer>Footer</footer></body></html>"#;
        let doc = Document::from(html);
        remove_noise(&doc);
        let html_out = doc.html();
        assert!(!html_out.contains("Cookies"));
        assert!(!html_out.contains("Nav"));
        assert!(!html_out.contains("Footer"));
        assert!(html_out.contains("Real content"));
    }

    #[test]
    fn remove_noise_preserves_content() {
        let html = r#"<html><body><article><h1>Title</h1><p>Important content here</p><pre><code>let x = 1;</code></pre></article></body></html>"#;
        let doc = Document::from(html);
        remove_noise(&doc);
        let html_out = doc.html();
        assert!(html_out.contains("Title"));
        assert!(html_out.contains("Important content"));
        assert!(html_out.contains("let x = 1;"));
    }

    #[test]
    fn is_noise_descendant_detects_ancestor() {
        let html = r#"<html><body><nav><div><a href="/">Home</a></div></nav><article><p>Content</p></article></body></html>"#;
        let doc = Document::from(html);
        // The <a> inside <nav> is a noise descendant
        let links = doc.select("a");
        assert!(!links.nodes().is_empty());
        for link in links.nodes() {
            assert!(
                is_noise_descendant(link),
                "link inside nav should be noise descendant"
            );
        }
    }

    #[test]
    fn is_noise_descendant_false_for_content() {
        let html = r#"<html><body><article><p>Content</p></article></body></html>"#;
        let doc = Document::from(html);
        let paragraphs = doc.select("p");
        for p in paragraphs.nodes() {
            assert!(
                !is_noise_descendant(p),
                "p inside article should not be noise descendant"
            );
        }
    }

    #[test]
    fn sidebar_class_is_noise() {
        let html = r#"<html><body><div class="sidebar">Widget area</div><main>Content</main></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn modal_class_is_noise() {
        // Exact token match: "modal" is in NOISE_CLASSES
        let html = r#"<html><body><div class="modal overlay">Modal content</div><div class="page-content">Real content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn advertisement_class_is_noise() {
        // "ad-banner" starts with "ad-" — caught by is_ad_class
        let html = r#"<html><body><div class="ad-banner">Buy now!</div><article>News article</article></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn script_style_iframe_are_noise() {
        let html = r#"<html><head><script>var x=1;</script><style>body{color:red}</style></head><body><iframe src="ad.html"></iframe><p>Content</p></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 3);
    }

    #[test]
    fn hidden_attr_is_not_noise() {
        // HTML `hidden` attribute is NOT treated as noise — React Suspense
        // boundaries use `<div hidden id="S:N">` for server-rendered content
        // that is revealed after hydration. The content is real.
        let html =
            r#"<html><body><div hidden>This is hidden</div><div>Visible</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 0, "hidden attribute should not be noise");
    }
}
