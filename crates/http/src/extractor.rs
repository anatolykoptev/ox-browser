//! Readability-style content extraction — clean-room implementation.
//!
//! Scores candidate nodes by text density and structural signals, picks the best,
//! then runs recovery passes to recapture content lost to noise filtering
//! (H1 outside content node, hero taglines, section headings, footer CTAs,
//! footer sitemaps, announcement banners).
//!
//! Not a port of any specific library. The scoring heuristic (text length +
//! semantic tag bonus + link density penalty) and recovery passes are
//! informed by the general Readability approach (Mozilla Readability.js,
//! Apache 2.0; original Arc90 Readability, Apache 2.0) and refined through
//! empirical testing against real-world pages (BBC, Next.js, GitHub, Vercel,
//! Hacker News).
//!
//! Issue #65: replace `readabilityrs` with own extractor.

use crate::noise;
use dom_query::Document;
use dom_query::NodeRef;
use dom_query::Selection;
use url::Url;

/// Selectors for candidate content nodes, ordered by semantic strength.
const CANDIDATE_SELECTOR: &str = "article, main, [role='main'], div, section, td";
const BODY_SELECTOR: &str = "body";
const H1_SELECTOR: &str = "h1";
const H2_SELECTOR: &str = "h2";
const P_SELECTOR: &str = "p";
const A_SELECTOR: &str = "a";
const ANNOUNCEMENT_SELECTOR: &str = "[role='region'][aria-label]";
const FOOTER_SELECTOR: &str = "footer";
const FOOTER_HEADING_SELECTOR: &str = "h2, h3, h4, h5, h6";

/// Structural noise tags — content inside these is genuinely non-content
/// (unlike class-based noise which can false-positive on "section-header").
const STRUCTURAL_NOISE_TAGS: &[&str] = &["nav", "aside", "footer", "header"];

/// Minimum text length for a node to be scored (chars).
const MIN_TEXT_LEN: f64 = 50.0;

/// Result of content extraction.
pub struct ExtractedNode {
    /// HTML of the selected content node (for markdown conversion).
    pub html: String,
    /// Title from `<h1>` recovery (empty if H1 is inside the content node).
    pub recovered_h1: String,
}

/// Extract the main content from a parsed HTML document.
///
/// Scores candidate nodes, picks the best, then appends HTML from sibling
/// `<section>` elements that contain substantial content but weren't selected
/// as the best node (e.g., feature card sections on marketing pages where
/// the hero `<main>` wins on semantic bonus but features are in a sibling
/// `<section>`).
pub fn extract_content_html(doc: &Document, _base_url: Option<&Url>) -> ExtractedNode {
    let best = find_best_node(doc);

    let (mut content_html, recovered_h1) = match best {
        Some(node) => {
            let html = node.html().to_string();
            let h1 = recover_h1(doc, &html);

            // Sibling section recovery: find <section> siblings of the best node
            // that contain substantial text not already in the content node.
            // This captures feature card sections, pricing tables, etc. that
            // live outside <main>/<article> on marketing pages.
            let sibling_sections = collect_sibling_sections(&node);
            if !sibling_sections.is_empty() {
                let mut combined = html;
                for section_html in sibling_sections {
                    combined.push_str(&section_html);
                }
                (combined, h1)
            } else {
                (html, h1)
            }
        }
        None => {
            // Fallback: body (or root if no body)
            let body = doc.select(BODY_SELECTOR).nodes().first().cloned();
            match body {
                Some(b) => {
                    let html = b.html().to_string();
                    let h1 = recover_h1(doc, &html);
                    (html, h1)
                }
                None => {
                    let root = doc.html_root();
                    let html = root.html().to_string();
                    let h1 = recover_h1(doc, &html);
                    (html, h1)
                }
            }
        }
    };

    // Trim trailing whitespace
    content_html = content_html.trim().to_string();

    ExtractedNode {
        html: content_html,
        recovered_h1,
    }
}

/// Collect HTML from sibling `<section>` and content-rich `<div>` elements of
/// the best node, walking up to 3 ancestor levels.
///
/// On marketing pages (Next.js, Vercel, ...), the hero `<main>` wins scoring
/// but feature cards live in sibling `<section>` tags or `<div>` wrappers
/// (e.g., React Suspense boundaries `<div hidden id="S:N">`). These siblings
/// may be at a higher DOM level than the best node (e.g., best node is an
/// inner `<main>` inside an outer `<main>`, while features are siblings of
/// the outer `<main>` at `<body>` level). This walks up to 3 ancestor levels
/// to find content-rich siblings.
fn collect_sibling_sections(best: &NodeRef<'_>) -> Vec<String> {
    let mut sections = Vec::new();
    let mut current = *best;

    for _level in 0..3 {
        let parent = match current.parent() {
            Some(p) => p,
            None => break,
        };

        // Don't go above <body>
        let parent_tag = parent
            .node_name()
            .map(|n| n.to_lowercase())
            .unwrap_or_default();
        if parent_tag == "html" {
            break;
        }

        for child in parent.children() {
            // Skip the current ancestor (and the best node itself)
            if child.id == current.id || child.id == best.id {
                continue;
            }

            let tag = child
                .node_name()
                .map(|n| n.to_lowercase())
                .unwrap_or_default();

            // Only interested in <section> siblings, or <div> siblings that
            // contain substantial content (e.g., React Suspense boundaries).
            if tag != "section" && tag != "div" {
                continue;
            }

            // Skip noise elements
            if noise::is_noise(&child) || noise::is_noise_descendant(&child) {
                continue;
            }

            // Only include elements with substantial text
            let text = child.text().to_string();
            let text_len = text.split_whitespace().count();
            if text_len < 50 {
                continue;
            }

            // For <div> siblings, require even more text to avoid picking up
            // navigation bars or small UI elements disguised as divs.
            if tag == "div" && text_len < 100 {
                continue;
            }

            // Skip if this sibling is an ancestor of the best node
            // (we don't want to re-include the entire parent tree)
            if is_ancestor_of(&child, best) {
                continue;
            }

            sections.push(child.html().to_string());
        }

        // Move up one level
        current = parent;
    }

    sections
}

/// Check if `ancestor` is an ancestor of `descendant` in the DOM tree.
fn is_ancestor_of(ancestor: &NodeRef<'_>, descendant: &NodeRef<'_>) -> bool {
    let mut current = *descendant;
    while let Some(parent) = current.parent() {
        if parent.id == ancestor.id {
            return true;
        }
        current = parent;
    }
    false
}

/// Select descendants of a node matching a CSS selector.
fn select_within<'a>(node: &NodeRef<'a>, sel: &str) -> Vec<NodeRef<'a>> {
    Selection::from(*node).select(sel).nodes().to_vec()
}

/// Find the best content candidate by scoring.
fn find_best_node(doc: &Document) -> Option<NodeRef<'_>> {
    let candidates = doc.select(CANDIDATE_SELECTOR);
    let mut best: Option<(NodeRef<'_>, f64)> = None;

    for node in candidates.nodes() {
        if noise::is_noise(node) || noise::is_noise_descendant(node) {
            continue;
        }

        let score = score_node(node);
        if score > 0.0 && best.as_ref().is_none_or(|(_, s)| score > *s) {
            best = Some((*node, score));
        }
    }

    best.map(|(node, _)| node)
}

/// Score a candidate node by text density and structural signals.
///
/// - Base: `ln(text_len)` — log scale avoids huge nodes dominating by size.
/// - Semantic bonus: +50 for `<article>`/`<main>`/`role="main"`.
/// - Class/ID bonus: +25 for content/article/post/entry patterns.
/// - Paragraph density: +3 per `<p>` child.
/// - Link density penalty: link-dense nodes score low (nav, footer).
fn score_node(node: &NodeRef<'_>) -> f64 {
    let text = node.text().to_string();
    let text_len = text.len() as f64;

    if text_len < MIN_TEXT_LEN {
        return 0.0;
    }

    let mut score = text_len.ln();

    let tag = node
        .node_name()
        .map(|n| n.to_lowercase())
        .unwrap_or_default();
    let is_semantic = matches!(tag.as_str(), "article" | "main")
        || node.attr("role").is_some_and(|r| r.as_ref() == "main");

    // Semantic tag bonus
    if is_semantic {
        score += 50.0;
    }

    // Class/ID bonus
    if let Some(class) = node.attr("class") {
        let cl = class.to_lowercase();
        if cl.contains("content")
            || cl.contains("article")
            || cl.contains("post")
            || cl.contains("entry")
        {
            score += 25.0;
        }
    }
    if let Some(id) = node.attr("id") {
        let id = id.to_lowercase();
        if id.contains("content")
            || id.contains("article")
            || id.contains("post")
            || id.contains("main")
        {
            score += 25.0;
        }
    }

    // Paragraph density
    let p_count = select_within(node, P_SELECTOR).len() as f64;
    score += p_count * 3.0;

    // Link density penalty
    let link_text_len: f64 = select_within(node, A_SELECTOR)
        .iter()
        .map(|a| a.text().len() as f64)
        .sum();

    if text_len > 0.0 {
        let link_density = link_text_len / text_len;
        if is_semantic {
            // Semantic nodes: milder penalty (docs have TOC links inside main)
            if link_density > 0.7 {
                score *= 0.3;
            } else if link_density > 0.5 {
                score *= 0.5;
            }
        } else {
            // Generic divs: heavy penalty for link-dense content
            if link_density > 0.5 {
                score *= 0.1;
            } else if link_density > 0.3 {
                score *= 0.5;
            }
        }
    }

    score
}

/// Recover the page's H1 if it's outside the content node.
///
/// The best content node often excludes the page's primary H1 (e.g., in a
/// hero/banner section). If the document has an H1 and its text isn't in the
/// content HTML, return it so the caller can prepend it.
fn recover_h1(doc: &Document, content_html: &str) -> String {
    let h1_sel = doc.select(H1_SELECTOR);
    // Skip h1 elements that are visually hidden (sr-only, aria-hidden, etc.)
    // — these are accessibility chrome, not visible page headings. GitHub's
    // search dialog has <h1 class="sr-only">Search code...</h1> which is not
    // a visible heading and should not become the page title.
    let h1 = h1_sel
        .nodes()
        .iter()
        .find(|h1| !crate::noise::is_noise(h1));

    let Some(h1) = h1 else {
        return String::new();
    };
    let h1_text = h1
        .text()
        .to_string()
        .trim()
        .trim_end_matches(|c: char| !c.is_alphanumeric())
        .trim()
        .to_string();

    if h1_text.is_empty() || content_html.contains(&h1_text) {
        return String::new();
    }

    h1_text
}

/// Recover content lost to noise filtering. Runs after the content node is
/// selected and converted to markdown. Mutates `markdown` in place.
///
/// Recovery passes:
/// 1. H1 heading — prepend `# {h1_text}` if recovered
/// 2. Hero paragraph — find `<p>` 40-300 chars near H1 (tagline/mission)
/// 3. Announcement banners — `role="region" aria-label="*announcement*"`
/// 4. Section headings — `<h2>` stripped but sibling content IS in markdown
/// 5. Footer CTA — `<h2>` + docs/app/API links from footer
/// 6. Footer sitemap — 3+ categories of links from footer
pub fn recover_content(
    doc: &Document,
    base_url: Option<&Url>,
    markdown: &mut String,
    recovered_h1: &str,
    links: &mut Vec<(String, String)>,
) {
    // 1. H1 heading
    if !recovered_h1.is_empty() && !markdown.contains(recovered_h1) {
        let h1_node = doc.select(H1_SELECTOR).nodes().first().cloned();
        *markdown = format!("# {recovered_h1}\n\n{markdown}");
        // 2. Hero paragraph — find <p> near the H1
        if let Some(h1) = h1_node {
            recover_hero_paragraph(&h1, markdown);
        }
    }

    // 3. Announcement banners
    recover_announcements(doc, base_url, markdown, links);

    // 4. Section headings
    recover_section_headings(doc, markdown);

    // 5. Footer CTA
    recover_footer_cta(doc, base_url, markdown, links);

    // 6. Footer sitemap
    recover_footer_sitemap(doc, base_url, markdown, links);
}

/// Recover the hero paragraph (mission/tagline) near the H1.
///
/// Walks up from H1 to find a container holding both H1 and sibling content,
/// then searches for a substantial `<p>` (40-300 chars) not already in markdown.
fn recover_hero_paragraph(h1: &NodeRef<'_>, markdown: &mut String) {
    let mut node = h1.parent();
    for _ in 0..4 {
        let Some(parent) = node else { break };

        for descendant in parent.descendants() {
            let is_p = descendant.node_name().is_some_and(|n| n.as_ref() == "p");
            if !is_p {
                continue;
            }
            let text = descendant
                .text()
                .to_string()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if text.len() < 40 || text.len() > 300 {
                continue;
            }
            if markdown.contains(&text) {
                continue;
            }
            let insert = format!("\n{text}\n");
            if let Some(pos) = markdown.find('\n') {
                markdown.insert_str(pos + 1, &insert);
            } else {
                markdown.push_str(&insert);
            }
            return;
        }
        node = parent.parent();
    }
}

/// Recover announcement banners stripped as noise.
///
/// Pattern: `<div role="region" aria-label="Announcement">` with short meaningful text.
fn recover_announcements(
    doc: &Document,
    base_url: Option<&Url>,
    markdown: &mut String,
    links: &mut Vec<(String, String)>,
) {
    for el in doc.select(ANNOUNCEMENT_SELECTOR).nodes() {
        let label = el.attr("aria-label").unwrap_or_default().to_lowercase();
        if !label.contains("announcement") {
            continue;
        }

        let text = el
            .text()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if text.is_empty() || markdown.contains(&text) {
            continue;
        }

        let mut announcement = format!("> **{text}**");
        for a in select_within(el, A_SELECTOR) {
            let link_text = a.text().to_string().trim().to_string();
            let href = a
                .attr("href")
                .map(|h| resolve_url(h.as_ref(), base_url))
                .unwrap_or_default();
            if !link_text.is_empty() && !href.is_empty() {
                links.push((link_text, href));
            }
        }
        announcement.push_str("\n\n");
        *markdown = format!("{announcement}{markdown}");
    }
}

/// Recover `<h2>` headings stripped because their wrapper had a noise class.
///
/// If adjacent content from the same section IS in the markdown, the heading
/// should be there too. Inserts the heading before the anchor content.
fn recover_section_headings(doc: &Document, markdown: &mut String) {
    for h2 in doc.select(H2_SELECTOR).nodes() {
        let h2_text = h2.text().to_string().trim().to_string();
        if h2_text.is_empty() || find_content_position(markdown, &h2_text).is_some() {
            continue;
        }

        // Don't recover headings inside structural noise tags
        if is_inside_structural_noise(h2) {
            continue;
        }

        // Check if sibling content from the same section is in the markdown
        if let Some(anchor) = find_sibling_anchor_text(h2, markdown)
            && let Some(pos) = find_content_position(markdown, &anchor)
        {
            let line_start = markdown[..pos].rfind('\n').map_or(0, |p| p + 1);
            let insert_pos = walk_back_past_orphans(markdown, line_start);
            let heading_md = format!("## {h2_text}\n\n");
            markdown.insert_str(insert_pos, &heading_md);
        }
    }

    // Recover eyebrow text (short taglines above section headings)
    for h2 in doc.select(H2_SELECTOR).nodes() {
        let h2_text = h2.text().to_string().trim().to_string();
        if h2_text.is_empty() || find_content_position(markdown, &h2_text).is_none() {
            continue;
        }

        if let Some(parent) = h2.parent() {
            for child in parent.children() {
                if child.id == h2.id {
                    break;
                }
                let is_p = child.node_name().is_some_and(|n| n.as_ref() == "p");
                if !is_p {
                    continue;
                }
                let p_text = child.text().to_string().trim().to_string();
                if p_text.is_empty() || p_text.len() > 80 || p_text.starts_with('/') {
                    continue;
                }
                let plain_md = strip_md_formatting(markdown);
                if plain_md.contains(&p_text) {
                    continue;
                }
                if let Some(pos) = find_content_position(markdown, &h2_text) {
                    let line_start = markdown[..pos].rfind('\n').map_or(0, |p| p + 1);
                    let eyebrow_md = format!("*{p_text}*\n\n");
                    markdown.insert_str(line_start, &eyebrow_md);
                }
            }
        }
    }
}

/// Find text from a sibling element in the same section that IS in the markdown.
fn find_sibling_anchor_text(heading: &NodeRef<'_>, markdown: &str) -> Option<String> {
    let heading_text = heading.text().to_string();

    let mut node = heading.parent();
    while let Some(parent) = node {
        if let Some(tag) = parent.node_name().map(|n| n.to_lowercase())
            && matches!(tag.as_str(), "section" | "article" | "main" | "body")
        {
            for descendant in parent.descendants() {
                let dtag = descendant.node_name().map(|n| n.to_lowercase());
                if !matches!(dtag.as_deref(), Some("p") | Some("h3") | Some("h4")) {
                    continue;
                }
                let el_text: String = descendant
                    .text()
                    .to_string()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if el_text.is_empty() || heading_text.contains(&el_text) {
                    continue;
                }
                if el_text.len() > 15 && find_content_position(markdown, &el_text).is_some() {
                    return Some(el_text);
                }
            }
            break;
        }
        node = parent.parent();
    }
    None
}

/// Recover CTA links and headings from footer sections.
fn recover_footer_cta(
    doc: &Document,
    base_url: Option<&Url>,
    markdown: &mut String,
    links: &mut Vec<(String, String)>,
) {
    for footer in doc.select(FOOTER_SELECTOR).nodes() {
        // Recover h2 headings (CTA headings)
        for h2 in select_within(footer, H2_SELECTOR) {
            let h2_text = h2.text().to_string().trim().to_string();
            if h2_text.is_empty() || markdown.contains(&h2_text) {
                continue;
            }
            let h2_lower = h2_text.to_lowercase();
            if h2_lower == "footer" || h2_lower == "navigation" || h2_lower == "site map" {
                continue;
            }
            if let Some(class) = h2.attr("class") {
                let cl = class.to_lowercase();
                if cl.contains("sr-only")
                    || cl.contains("visually-hidden")
                    || cl.contains("screen-reader")
                {
                    continue;
                }
            }
            markdown.push_str(&format!("\n\n## {h2_text}\n\n"));
        }

        // Recover valuable CTA links (docs/app/API)
        for a in select_within(footer, A_SELECTOR) {
            let href = match a.attr("href") {
                Some(h) => resolve_url(h.as_ref(), base_url),
                None => continue,
            };
            let text = a.text().to_string().trim().to_string();
            if text.is_empty() || href.is_empty() {
                continue;
            }
            let href_lower = href.to_lowercase();
            let is_valuable_cta = href_lower.contains("docs.")
                || href_lower.contains("/docs")
                || href_lower.contains("app.")
                || href_lower.contains("/app")
                || href_lower.contains("api.");
            if is_valuable_cta && !markdown.contains(&text) {
                markdown.push_str(&format!("[{text}]({href})\n\n"));
                links.push((text, href));
            }
        }
    }
}

/// Recover structured site navigation from footer (product/service listings).
///
/// Only fires when the footer has 3+ categories of links (Products, Solutions, etc.).
fn recover_footer_sitemap(
    doc: &Document,
    base_url: Option<&Url>,
    markdown: &mut String,
    links: &mut Vec<(String, String)>,
) {
    for footer in doc.select(FOOTER_SELECTOR).nodes() {
        let mut categories: Vec<(String, Vec<(String, String)>)> = Vec::new();

        for heading in select_within(footer, FOOTER_HEADING_SELECTOR) {
            let heading_text = heading.text().to_string().trim().to_string();
            if heading_text.is_empty() || heading_text.len() > 50 {
                continue;
            }
            if heading_text.eq_ignore_ascii_case("footer") || markdown.contains(&heading_text) {
                continue;
            }

            let cat_links = collect_sibling_links(&heading, base_url);
            if cat_links.len() >= 2 && cat_links.len() <= 20 {
                categories.push((heading_text, cat_links));
            }
        }

        if categories.len() < 3 {
            continue;
        }

        let mut sitemap = String::from("\n\n---\n\n");
        for (heading, cat_links) in &categories {
            let names: Vec<&str> = cat_links.iter().map(|(t, _)| t.as_str()).collect();
            sitemap.push_str(&format!("**{heading}**: {}\n", names.join(", ")));
            for (text, href) in cat_links {
                links.push((text.clone(), href.clone()));
            }
        }
        markdown.push_str(&sitemap);
    }
}

/// Collect links from the same container as a heading element.
fn collect_sibling_links(heading: &NodeRef<'_>, base_url: Option<&Url>) -> Vec<(String, String)> {
    let mut node = heading.parent();
    for _ in 0..2 {
        let Some(parent) = node else { break };
        let a_elements = select_within(&parent, A_SELECTOR);
        if a_elements.len() >= 2 {
            return a_elements
                .iter()
                .filter_map(|a| {
                    let text = a.text().to_string().trim().to_string();
                    let href = a.attr("href").map(|h| resolve_url(h.as_ref(), base_url));
                    match (text.is_empty(), href) {
                        (false, Some(h))
                            if !h.is_empty()
                                && text.len() > 1
                                && text.len() < 60
                                && !matches!(
                                    text.to_lowercase().as_str(),
                                    "here" | "link" | "click" | "more"
                                ) =>
                        {
                            Some((text, h))
                        }
                        _ => None,
                    }
                })
                .collect();
        }
        node = parent.parent();
    }
    Vec::new()
}

/// Walk backwards from `pos`, skipping blank lines and short orphan lines
/// (<=25 chars, likely stat numbers) that belong to the same section.
fn walk_back_past_orphans(markdown: &str, mut pos: usize) -> usize {
    loop {
        if pos == 0 {
            break;
        }
        let prev_end = pos.saturating_sub(1);
        let prev_start = markdown[..prev_end].rfind('\n').map_or(0, |p| p + 1);
        let prev_line = markdown[prev_start..prev_end].trim();

        if prev_line.is_empty() {
            pos = prev_start;
            continue;
        }
        if prev_line.starts_with('#') || prev_line.starts_with('>') || prev_line.len() > 25 {
            break;
        }
        pos = prev_start;
    }
    pos
}

/// Quick strip of markdown bold/italic markers for plain-text comparison.
fn strip_md_formatting(md: &str) -> String {
    md.replace("**", "").replace('*', "")
}

/// Find `needle` in `markdown` at a position that isn't inside image/link alt text.
fn find_content_position(markdown: &str, needle: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(pos) = markdown[search_from..].find(needle) {
        let abs_pos = search_from + pos;
        if !is_inside_image_syntax(markdown, abs_pos) {
            return Some(abs_pos);
        }
        search_from = abs_pos + needle.len();
    }
    None
}

/// Check if a position in markdown falls inside `![...](...)` image syntax.
fn is_inside_image_syntax(markdown: &str, pos: usize) -> bool {
    let before = &markdown[..pos];
    let bytes = before.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if i > 0 && bytes[i - 1] == b'!' && bytes[i] == b'[' {
            let after = &markdown[pos..];
            if after.contains("](") {
                return true;
            }
        }
        if bytes[i] == b')' {
            break;
        }
    }
    false
}

/// Check if an element is inside a structural noise tag (nav, aside, footer, header).
fn is_inside_structural_noise(el: &NodeRef<'_>) -> bool {
    for ancestor in el.ancestors(None) {
        if let Some(tag) = ancestor.node_name().map(|n| n.to_lowercase()) {
            if STRUCTURAL_NOISE_TAGS.contains(&tag.as_str()) {
                return true;
            }
            if let Some(role) = ancestor.attr("role")
                && (role.as_ref() == "navigation" || role.as_ref() == "contentinfo")
            {
                return true;
            }
        }
    }
    false
}

/// Resolve a possibly-relative URL against the base URL.
fn resolve_url(href: &str, base_url: Option<&Url>) -> String {
    if let Some(base) = base_url
        && let Ok(abs) = base.join(href)
    {
        return abs.to_string();
    }
    href.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(html: &str) -> Document {
        Document::from(html)
    }

    #[test]
    fn picks_article_over_nav() {
        let html = r##"
        <html><body>
            <nav><ul><li><a href="/">Home</a></li></ul></nav>
            <article>
                <h1>Real Article</h1>
                <p>This is the main content of the page. It contains several paragraphs
                of text that make it clearly the main content area.</p>
                <p>Another paragraph with useful information for the reader.</p>
                <p>And a third paragraph to make it really obvious this is content.</p>
            </article>
            <aside class="sidebar"><h3>Related</h3></aside>
        </body></html>"##;
        let doc = parse(html);
        let result = extract_content_html(&doc, None);
        assert!(result.html.contains("Real Article"));
        assert!(result.html.contains("main content"));
    }

    #[test]
    fn falls_back_to_body() {
        let html =
            r##"<html><body><p>Simple page with just a paragraph of text here.</p></body></html>"##;
        let doc = parse(html);
        let result = extract_content_html(&doc, None);
        assert!(result.html.contains("Simple page"));
    }

    #[test]
    fn prefers_content_class() {
        let html = r##"
        <html><body>
            <div class="header"><p>Site header with some branding text content here</p></div>
            <div class="content">
                <h1>Main Content</h1>
                <p>This is the primary content of the page that readers want to see.
                It has multiple sentences and meaningful paragraphs.</p>
                <p>Second paragraph with additional details and context for the article.</p>
                <p>Third paragraph because real articles have substantial text.</p>
            </div>
            <div class="footer"><p>Footer stuff with copyright and legal text here</p></div>
        </body></html>"##;
        let doc = parse(html);
        let result = extract_content_html(&doc, None);
        assert!(result.html.contains("Main Content"));
    }

    #[test]
    fn recovers_h1_outside_content_node() {
        let html = r##"
        <html><body>
            <header><h1>Page Title</h1></header>
            <div class="content">
                <p>This is the main content of the page with enough text to be scored.</p>
                <p>Second paragraph with more content for the reader to read.</p>
            </div>
        </body></html>"##;
        let doc = parse(html);
        let result = extract_content_html(&doc, None);
        assert_eq!(result.recovered_h1, "Page Title");
    }

    #[test]
    fn h1_inside_content_not_recovered() {
        let html = r##"
        <html><body>
            <article>
                <h1>Article Title</h1>
                <p>This is the main content of the page with enough text to be scored.</p>
                <p>Second paragraph with more content for the reader to read.</p>
            </article>
        </body></html>"##;
        let doc = parse(html);
        let result = extract_content_html(&doc, None);
        assert!(result.recovered_h1.is_empty());
    }

    #[test]
    fn find_content_position_skips_image_alt() {
        let md = "![alt needle text](/img.png) Some text. needle text here.";
        let pos = find_content_position(md, "needle text");
        assert!(pos.is_some());
        let pos = pos.unwrap();
        // Should find the second occurrence (after the image), not the one in alt text
        assert!(
            pos > md.find("](").unwrap(),
            "should skip the image-alt occurrence"
        );
    }

    #[test]
    fn find_content_position_multibyte_safe() {
        let md = "![foo needle bar](a.png) Ещё текст needle here";
        let pos = find_content_position(md, "needle");
        assert!(pos.is_some());
        let pos = pos.unwrap();
        assert!(md.is_char_boundary(pos));
    }

    #[test]
    fn walk_back_past_orphans_skips_short_lines() {
        let md = "## Heading\n\n42\n\nContent line here";
        let content_pos = md.find("Content").unwrap();
        let line_start = md[..content_pos].rfind('\n').map_or(0, |p| p + 1);
        let result = walk_back_past_orphans(md, line_start);
        assert!(md[..result].contains("Heading"));
    }

    #[test]
    fn strip_md_formatting_removes_bold_italic() {
        assert_eq!(strip_md_formatting("**bold**"), "bold");
        assert_eq!(strip_md_formatting("*italic*"), "italic");
        assert_eq!(
            strip_md_formatting("**bold** and *italic*"),
            "bold and italic"
        );
    }

    #[test]
    fn score_node_short_text_returns_zero() {
        let doc = parse("<html><body><div>short</div></body></html>");
        let sel_div = doc.select("div");
        let div = sel_div.nodes().first().unwrap();
        assert_eq!(score_node(div), 0.0);
    }

    #[test]
    fn score_node_article_gets_semantic_bonus() {
        let html = r##"<html><body>
            <article><p>This is a long enough paragraph to pass the minimum text length threshold for scoring.</p></article>
            <div><p>This is a long enough paragraph to pass the minimum text length threshold for scoring.</p></div>
        </body></html>"##;
        let doc = parse(html);
        let sel_article = doc.select("article");
        let article = sel_article.nodes().first().unwrap();
        let sel_div = doc.select("div");
        let div = sel_div.nodes().first().unwrap();
        let article_score = score_node(article);
        let div_score = score_node(div);
        assert!(
            article_score > div_score,
            "article should score higher than div"
        );
        assert!(
            article_score > 50.0,
            "article should get +50 semantic bonus"
        );
    }

    #[test]
    fn score_node_link_density_penalizes_nav() {
        let html = r##"<html><body>
            <div class="nav">
                <a href="/1">Link one with text</a>
                <a href="/2">Link two with text</a>
                <a href="/3">Link three with text</a>
                <a href="/4">Link four with text</a>
                <a href="/5">Link five with text</a>
            </div>
        </body></html>"##;
        let doc = parse(html);
        let sel_nav = doc.select("div");
        let nav = sel_nav.nodes().first().unwrap();
        let score = score_node(nav);
        // Link-dense nav should be penalized (×0.1–0.5 for high link density).
        // Without penalty, score would be ln(text_len) ≈ 5; with penalty < 3.
        assert!(score < 3.0, "link-dense nav should score low, got {score}");
    }

    #[test]
    fn is_inside_structural_noise_detects_nav() {
        let html = r##"<html><body>
            <nav><h2>Navigation Heading</h2></nav>
        </body></html>"##;
        let doc = parse(html);
        let sel_h2 = doc.select("h2");
        let h2 = sel_h2.nodes().first().unwrap();
        assert!(is_inside_structural_noise(h2));
    }

    #[test]
    fn is_inside_structural_noise_false_for_content() {
        let html = r##"<html><body>
            <article><h2>Content Heading</h2></article>
        </body></html>"##;
        let doc = parse(html);
        let sel_h2 = doc.select("h2");
        let h2 = sel_h2.nodes().first().unwrap();
        assert!(!is_inside_structural_noise(h2));
    }

    #[test]
    fn resolve_url_with_base() {
        let base = Url::parse("https://example.com/page").unwrap();
        assert_eq!(
            resolve_url("/docs", Some(&base)),
            "https://example.com/docs"
        );
        assert_eq!(
            resolve_url("https://other.com/x", Some(&base)),
            "https://other.com/x"
        );
    }

    #[test]
    fn resolve_url_without_base() {
        assert_eq!(resolve_url("/docs", None), "/docs");
    }
}
