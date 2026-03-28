//! Accessibility analysis: lang, alt text, headings, ARIA landmarks, form labels.

use dom_query::Document;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct HeadingInfo {
    pub level: u8,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AccessibilityReport {
    pub lang: String,
    pub images_with_alt: u32,
    pub images_empty_alt: u32,
    pub images_no_alt: u32,
    pub h1_count: u32,
    pub headings: Vec<HeadingInfo>,
    pub heading_skip: bool,
    pub landmarks: u32,
    pub inputs_total: u32,
    pub inputs_with_label: u32,
    pub score: u8,
}

/// Analyze HTML for accessibility attributes and compute a 0–100 score.
pub fn analyze(html: &str) -> AccessibilityReport {
    let doc = Document::from(html);
    let lang = extract_lang(&doc);
    let (images_with_alt, images_empty_alt, images_no_alt) = count_images(&doc);
    let (headings, h1_count, heading_skip) = analyze_headings(&doc);
    let landmarks = count_landmarks(&doc);
    let (inputs_total, inputs_with_label) = count_labeled_inputs(&doc);
    let mut r = AccessibilityReport {
        lang,
        images_with_alt,
        images_empty_alt,
        images_no_alt,
        headings,
        h1_count,
        heading_skip,
        landmarks,
        inputs_total,
        inputs_with_label,
        score: 0,
    };
    r.score = compute_score(&r);
    r
}

fn extract_lang(doc: &Document) -> String {
    doc.select("html").iter().next()
        .and_then(|el| {
            let v = el.attr("lang").unwrap_or_default();
            if v.trim().is_empty() { None } else { Some(v.trim().to_string()) }
        })
        .unwrap_or_default()
}

fn count_images(doc: &Document) -> (u32, u32, u32) {
    let (mut with_alt, mut empty_alt, mut no_alt) = (0u32, 0u32, 0u32);
    for img in doc.select("img").iter() {
        match img.attr("alt") {
            None => no_alt += 1,
            Some(v) if v.trim().is_empty() => empty_alt += 1,
            Some(_) => with_alt += 1,
        }
    }
    (with_alt, empty_alt, no_alt)
}

fn analyze_headings(doc: &Document) -> (Vec<HeadingInfo>, u32, bool) {
    let mut headings = Vec::new();
    for level in 1u8..=6 {
        for el in doc.select(&format!("h{level}")).iter() {
            headings.push(HeadingInfo { level, text: el.text().trim().to_string() });
        }
    }
    headings.sort_by_key(|h| h.level);

    let h1_count = headings.iter().filter(|h| h.level == 1).count() as u32;

    let mut levels: Vec<u8> = headings.iter().map(|h| h.level).collect();
    levels.sort_unstable();
    levels.dedup();
    let heading_skip = levels.windows(2).any(|w| w[1] > w[0] + 1);

    // Cap output to prevent bloated responses
    headings.truncate(50);

    (headings, h1_count, heading_skip)
}

fn count_landmarks(doc: &Document) -> u32 {
    const SEMANTIC: &[&str] = &["main", "nav", "header", "footer", "aside"];
    const ARIA_ROLES: &[&str] =
        &["main", "navigation", "banner", "contentinfo", "complementary", "search"];

    let mut count: u32 = SEMANTIC.iter().map(|t| doc.select(t).length() as u32).sum();
    for el in doc.select("[role]").iter() {
        if let Some(role) = el.attr("role") {
            if ARIA_ROLES.contains(&role.trim()) { count += 1; }
        }
    }
    count
}

fn count_labeled_inputs(doc: &Document) -> (u32, u32) {
    let (mut total, mut labeled) = (0u32, 0u32);
    for input in doc.select("input, textarea, select").iter() {
        let t = input.attr("type").unwrap_or_default().trim().to_lowercase();
        if matches!(t.as_str(), "hidden" | "submit" | "button" | "reset") { continue; }

        // Skip inputs inside aria-hidden containers (e.g. honeypot fields)
        let ancestors = input.ancestors(None);
        let in_aria_hidden = ancestors.iter().any(|a| {
            a.attr("aria-hidden")
                .map(|v| v.to_string().trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        });
        if in_aria_hidden { continue; }

        total += 1;

        // 1. Explicit: <label for="id"> matches input id
        let id = input.attr("id").unwrap_or_default();
        let has_for = !id.is_empty() && doc.select(&format!("label[for=\"{id}\"]")).length() > 0;

        // 2. ARIA: aria-label or aria-labelledby
        let has_aria = input.attr("aria-label").map(|v| !v.trim().is_empty()).unwrap_or(false)
            || input.attr("aria-labelledby").map(|v| !v.trim().is_empty()).unwrap_or(false);

        // 3. Title attribute
        let has_title = input.attr("title").map(|v| !v.trim().is_empty()).unwrap_or(false);

        // 4. Implicit: input nested inside a <label> element
        let has_implicit = input.ancestors(Some(10)).iter().any(|a| {
            a.is("label")
        });

        if has_for || has_aria || has_title || has_implicit { labeled += 1; }
    }
    (total, labeled)
}

fn compute_score(r: &AccessibilityReport) -> u8 {
    let mut score = 0u32;
    if !r.lang.is_empty() { score += 25; }
    let total_img = r.images_with_alt + r.images_empty_alt + r.images_no_alt;
    if total_img == 0 || r.images_no_alt == 0 { score += 25; }
    if r.h1_count == 1 { score += 15; }
    if !r.heading_skip { score += 10; }
    if r.landmarks > 0 { score += 15; }
    if r.inputs_total == 0 || r.inputs_with_label == r.inputs_total { score += 10; }
    score.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_html_lang() {
        assert_eq!(analyze(r#"<html lang="en"><body></body></html>"#).lang, "en");
        assert_eq!(analyze(r#"<html><body></body></html>"#).lang, "");
    }

    #[test]
    fn count_alt_text() {
        let r = analyze(r#"<html><body>
            <img src="a.png" alt="cat">
            <img src="b.png" alt="">
            <img src="c.png">
        </body></html>"#);
        assert_eq!((r.images_with_alt, r.images_empty_alt, r.images_no_alt), (1, 1, 1));
    }

    #[test]
    fn heading_hierarchy() {
        let skip = analyze(r#"<html><body><h1>T</h1><h3>Skip</h3></body></html>"#);
        assert_eq!(skip.h1_count, 1);
        assert!(skip.heading_skip, "expected skip detected");

        let no_skip = analyze(r#"<html><body><h1>T</h1><h2>S</h2><h3>U</h3></body></html>"#);
        assert!(!no_skip.heading_skip);
    }

    #[test]
    fn aria_landmarks() {
        let r = analyze(r#"<html><body>
            <header>H</header><nav>N</nav><main>M</main>
            <div role="search">S</div><footer>F</footer>
        </body></html>"#);
        assert!(r.landmarks >= 4, "expected >=4, got {}", r.landmarks);
    }

    #[test]
    fn form_labels_explicit_and_aria() {
        let r = analyze(r#"<html><body><form>
            <label for="name">Name</label>
            <input id="name" type="text">
            <input type="text" aria-label="Email">
            <input type="text">
        </form></body></html>"#);
        assert_eq!((r.inputs_total, r.inputs_with_label), (3, 2));
    }

    #[test]
    fn form_labels_implicit_wrapping() {
        // Input inside <label> — valid implicit association
        let r = analyze(r#"<html><body><form>
            <label><input type="checkbox"> I agree</label>
            <label>Name <input type="text"></label>
            <input type="text">
        </form></body></html>"#);
        assert_eq!(r.inputs_total, 3);
        assert_eq!(r.inputs_with_label, 2, "implicit label wrapping should count");
    }

    #[test]
    fn form_labels_skip_aria_hidden() {
        // Inputs inside aria-hidden containers (honeypots) should be skipped entirely
        let r = analyze(r#"<html><body><form>
            <label for="name">Name</label>
            <input id="name" type="text">
            <div aria-hidden="true"><input type="text" name="honeypot"></div>
        </form></body></html>"#);
        assert_eq!(r.inputs_total, 1, "aria-hidden input should not be counted");
        assert_eq!(r.inputs_with_label, 1);
    }

    #[test]
    fn headings_capped_at_50() {
        let headings_html: String = (0..100)
            .map(|i| format!("<h2>Heading {i}</h2>"))
            .collect();
        let html = format!("<html lang=\"en\"><body><h1>Main</h1>{headings_html}</body></html>");
        let r = analyze(&html);
        assert!(r.headings.len() <= 50, "got {} headings", r.headings.len());
        assert_eq!(r.h1_count, 1);
        assert!(!r.heading_skip);
    }

    #[test]
    fn score_calculation() {
        let perfect = analyze(r#"<html lang="en"><body>
            <header>H</header>
            <main><h1>T</h1><h2>S</h2>
                <img src="a.png" alt="d">
                <label for="q">Q</label>
                <input id="q" type="text">
            </main>
            <footer>F</footer>
        </body></html>"#);
        assert_eq!(perfect.score, 100, "expected 100, got {:?}", perfect);

        let bad = analyze(r#"<html><body><img src="x.png"></body></html>"#);
        assert!(bad.score < 40, "expected low score, got {}", bad.score);
    }
}
