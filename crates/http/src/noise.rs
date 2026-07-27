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
//! Ported from webclaw `crates/webclaw-core/src/noise.rs` (MIT), adapted from
//! `scraper::ElementRef` to `dom_query::NodeRef`.
//!
//! Issue #59: Noise filter — Tailwind-safe DOM noise detection.

use dom_query::Document;
use dom_query::NodeRef;

// ---------------------------------------------------------------------------
// Noise tag names — elements that are always noise
// ---------------------------------------------------------------------------

const NOISE_TAGS: &[&str] = &[
    "nav", "footer", "header", "aside", "script", "style", "noscript", "iframe", "svg", "form",
];

// ---------------------------------------------------------------------------
// Noise ARIA roles
// ---------------------------------------------------------------------------

const NOISE_ROLES: &[&str] = &[
    "navigation",
    "banner",
    "contentinfo",
    "complementary",
    "search",
    "menu",
    "menubar",
    "toolbar",
    "dialog",
    "alertdialog",
    "status",
    "alert",
    "tooltip",
    "tablist",
    "tab",
    "tab-panel",
];

// ---------------------------------------------------------------------------
// Noise class patterns — substring matches against class attribute
// ---------------------------------------------------------------------------

const NOISE_CLASS_PATTERNS: &[&str] = &[
    // Navigation
    "nav",
    "navbar",
    "navigation",
    "menu",
    "breadcrumb",
    "pagination",
    "pager",
    // Layout chrome
    "sidebar",
    "footer",
    "header",
    "masthead",
    "toolbar",
    "banner",
    // Cookie/consent
    "cookie",
    "consent",
    "gdpr",
    "onetrust",
    "cmp-",
    "cmp_",
    // Ads
    "advert",
    "advertisement",
    "adsense",
    "ad-banner",
    "ad-container",
    "ad-slot",
    "dfp",
    "google-ad",
    "promo",
    "sponsored",
    // Social
    "social",
    "share",
    "sharing",
    "twitter-share",
    "facebook-share",
    "linkedin-share",
    // Modals/overlays
    "modal",
    "popup",
    "overlay",
    "lightbox",
    "dialog",
    // Newsletter/signup
    "newsletter",
    "subscribe",
    "signup-form",
    "email-signup",
    // Widgets
    "widget",
    "widget-area",
    // Skip links / accessibility chrome
    "skip-link",
    "skip-to-content",
    "screen-reader",
    "visually-hidden",
    "sr-only",
];

// ---------------------------------------------------------------------------
// Noise ID patterns — substring matches against id attribute
// ---------------------------------------------------------------------------

const NOISE_ID_PATTERNS: &[&str] = &[
    "nav",
    "navbar",
    "navigation",
    "menu",
    "footer",
    "header",
    "sidebar",
    "breadcrumb",
    "pagination",
    "cookie",
    "consent",
    "onetrust",
    "cmp-",
    "cmp_",
    "modal",
    "popup",
    "overlay",
    "newsletter",
    "subscribe",
    "social",
    "share",
    "advert",
    "ad-",
    "sidebar",
];

// ---------------------------------------------------------------------------
// Tailwind-safe exclusions — class substrings that look noise-ish but aren't
// ---------------------------------------------------------------------------

/// Class substrings that should NOT trigger noise classification even if they
/// contain a noise pattern. These are Tailwind animation utilities and CSS
/// custom property syntax that appear in real content elements.
const TAILWIND_SAFE_PATTERNS: &[&str] = &[
    "animate-",
    "transition-",
    "duration-",
    "delay-",
    "ease-",
    "motion-",
    "group-hover:",
    "peer-hover:",
    "focus-within:",
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
pub(crate) fn is_noise(node: &NodeRef) -> bool {
    if !node.is_element() {
        return false;
    }

    // 1. Tag name check
    if let Some(name) = node.node_name() {
        let lower = name.to_lowercase();
        if NOISE_TAGS.contains(&lower.as_str()) {
            return true;
        }
    }

    // 2. ARIA role check
    if let Some(role) = node.attr("role") {
        let role = role.to_lowercase();
        if NOISE_ROLES.contains(&role.as_str()) {
            return true;
        }
    }

    // 3. Class pattern check (Tailwind-safe)
    if let Some(class) = node.class()
        && is_noise_class(&class.to_lowercase())
    {
        return true;
    }

    // 4. ID pattern check
    if let Some(id) = node.id_attr() {
        let id = id.to_lowercase();
        if is_noise_id(&id) {
            return true;
        }
    }

    // 5. Hidden elements
    if is_hidden(node) {
        return true;
    }

    false
}

/// Check if a class attribute string contains noise patterns.
/// Tailwind-safe: animation/transition utilities are excluded.
fn is_noise_class(class: &str) -> bool {
    // Quick check: if the class contains Tailwind-safe patterns,
    // don't flag it based on those substrings.
    let has_tailwind_safe = TAILWIND_SAFE_PATTERNS.iter().any(|p| class.contains(p));

    for pattern in NOISE_CLASS_PATTERNS {
        if class.contains(pattern) {
            // If the only match is in a Tailwind-safe context, skip.
            // Check if the pattern appears outside of a safe prefix.
            if has_tailwind_safe && is_only_in_safe_context(class, pattern) {
                continue;
            }
            return true;
        }
    }
    false
}

/// Check if the noise pattern only appears within a Tailwind-safe prefix.
/// E.g., "animate-menu-open" contains "menu" but only within "animate-menu-open".
fn is_only_in_safe_context(class: &str, pattern: &str) -> bool {
    // Find all occurrences of the pattern
    let mut search_from = 0;
    while let Some(pos) = class[search_from..].find(pattern) {
        let abs_pos = search_from + pos;
        // Check if this occurrence is preceded by a safe pattern
        let before = &class[..abs_pos];
        let is_safe = TAILWIND_SAFE_PATTERNS.iter().any(|safe| {
            before
                .rfind(safe)
                .is_some_and(|sp| abs_pos - sp < safe.len() + 20)
        });
        if !is_safe {
            return false;
        }
        search_from = abs_pos + pattern.len();
    }
    true
}

/// Check if an ID string contains noise patterns.
fn is_noise_id(id: &str) -> bool {
    NOISE_ID_PATTERNS.iter().any(|p| id.contains(p))
}

/// Check if an element is hidden via inline styles.
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
    if let Some(hidden) = node.attr("hidden") {
        let _ = hidden;
        return true;
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
        let html = r#"<html><body><div class="main-nav">Navigation links</div><div class="article-body">Content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn social_share_class_is_noise() {
        let html = r#"<html><body><div class="social-share-buttons">Share on Twitter</div><div class="post-content">Article</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn newsletter_signup_is_noise() {
        let html = r#"<html><body><div class="newsletter-signup">Subscribe!</div><article>Content</article></body></html>"#;
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
        let html = r#"<html><body><nav>Nav</nav><div class="cookie-consent">Cookies</div><article><p>Real content</p></article><footer>Footer</footer></body></html>"#;
        let doc = Document::from(html);
        remove_noise(&doc);
        let html_out = doc.html();
        assert!(!html_out.contains("cookie-consent"));
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
        let html = r#"<html><body><div class="modal-overlay">Modal content</div><div class="page-content">Real content</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }

    #[test]
    fn advertisement_class_is_noise() {
        let html = r#"<html><body><div class="advertisement">Buy now!</div><article>News article</article></body></html>"#;
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
    fn hidden_attr_is_noise() {
        let html =
            r#"<html><body><div hidden>This is hidden</div><div>Visible</div></body></html>"#;
        let doc = Document::from(html);
        assert_eq!(count_noise(&doc), 1);
    }
}
