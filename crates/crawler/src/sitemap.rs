//! Sitemap XML parser and auto-discovery.

use anyhow::Result;

/// Maximum decompressed sitemap size (50 MB — the Google sitemap protocol spec
/// max per file). A gzipped sitemap from an attacker-chosen site can be a few
/// KB on the wire but decompress without limit; the cap in
/// [`parse_sitemap_with_cap`] applies to the DECOMPRESSED byte count, not the
/// compressed one (issue #119 — capping compressed bytes is the mistake that
/// makes a bomb guard useless).
const SITEMAP_MAX_DECOMPRESSED_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum URL entries collected from one sitemap document (50,000 — the
/// sitemap protocol's per-file URL limit, the same bound Google and the
/// common sitemap libraries enforce). The byte cap above bounds input size
/// but not heap growth: 50 MB of small `<loc>` blocks still materializes on
/// the order of a million `SitemapEntry`/`String` allocations. Truncation,
/// not an error — a file past the protocol limit still yields its first
/// 50k legitimate URLs for discovery (issue #150).
const MAX_SITEMAP_URLS: usize = 50_000;

/// A single URL entry from a sitemap urlset.
#[derive(Debug, Clone)]
pub struct SitemapEntry {
    pub url: String,
    pub lastmod: Option<String>,
    pub priority: Option<f32>,
    pub changefreq: Option<String>,
}

/// Parsed sitemap content — either an index or a urlset.
#[derive(Debug)]
pub enum SitemapContent {
    /// Sitemap index containing URLs of nested sitemaps.
    Index(Vec<String>),
    /// URL set containing page entries.
    UrlSet(Vec<SitemapEntry>),
}

/// Parse a sitemap XML document (either index or urlset).
///
/// Uses the default decompressed-body cap of 50 MB
/// ([`SITEMAP_MAX_DECOMPRESSED_BYTES`]). For tests that need a smaller cap,
/// use [`parse_sitemap_with_cap`].
pub fn parse_sitemap(xml: &[u8]) -> Result<SitemapContent> {
    parse_sitemap_with_cap(xml, SITEMAP_MAX_DECOMPRESSED_BYTES)
}

/// Parse a sitemap XML document with an explicit decompressed-body cap.
///
/// If the input is gzip-compressed (magic bytes `0x1f 0x8b`), it is
/// decompressed via [`ox_http::body_cap::gunzip_capped`] which enforces a
/// ceiling on the **decompressed** byte count — not the compressed one. This
/// is the decompression-bomb guard: a `sitemap.xml.gz` from an attacker-chosen
/// site may be a few KB on the wire but expand without limit (issue #119).
pub fn parse_sitemap_with_cap(xml: &[u8], max_decompressed_bytes: u64) -> Result<SitemapContent> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    // Detect gzip (magic bytes 0x1f, 0x8b). Decompress with a cap on the
    // DECOMPRESSED byte count — capping the compressed size is the mistake
    // that makes a bomb guard useless (issue #119).
    let data = if xml.len() >= 2 && xml[0] == 0x1f && xml[1] == 0x8b {
        ox_http::body_cap::gunzip_capped(xml, max_decompressed_bytes)?
    } else {
        xml.to_vec()
    };

    let mut reader = Reader::from_reader(data.as_slice());
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut is_index = false;
    let mut decided = false;

    // Detect type by first significant tag
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match name.as_str() {
                    "sitemapindex" => {
                        is_index = true;
                        decided = true;
                        break;
                    }
                    "urlset" => {
                        is_index = false;
                        decided = true;
                        break;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if !decided {
        return Err(anyhow::anyhow!("no <urlset> or <sitemapindex> found"));
    }

    buf.clear();

    if is_index {
        parse_index(&mut reader, &mut buf)
    } else {
        parse_urlset_xml(&mut reader, &mut buf)
    }
}

/// Resolve one `&ref;` event into `text`: `&#N;` char refs via
/// `resolve_char_ref`, the five predefined XML entities via
/// `resolve_predefined_entity` — the same table 0.37's `unescape()`
/// used — and anything else is a parse error (fail-closed, matching
/// the old behavior on `&nbsp;`-style HTML entities).
fn push_ref(text: &mut String, e: &quick_xml::events::BytesRef<'_>) -> Result<()> {
    if let Some(ch) = e.resolve_char_ref()? {
        text.push(ch);
        return Ok(());
    }
    let name = e.decode()?;
    match quick_xml::escape::resolve_predefined_entity(&name) {
        Some(resolved) => text.push_str(resolved),
        None => return Err(anyhow::anyhow!("XML parse error: unknown entity &{name};")),
    }
    Ok(())
}

fn parse_index(reader: &mut quick_xml::Reader<&[u8]>, buf: &mut Vec<u8>) -> Result<SitemapContent> {
    use quick_xml::events::Event;

    let mut urls = Vec::new();
    let mut in_loc = false;
    // quick-xml >= 0.38 splits every `&ref;` out of Text into a separate
    // GeneralRef event, so a <loc> body arrives as fragments — accumulate
    // them and push the joined, trimmed text on </loc>.
    let mut text = String::new();

    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(ref e)) if e.local_name().as_ref() == b"loc" => {
                in_loc = true;
                text.clear();
            }
            Ok(Event::Text(ref e)) if in_loc => {
                text.push_str(&e.xml10_content()?);
            }
            Ok(Event::GeneralRef(ref e)) if in_loc => {
                push_ref(&mut text, e)?;
            }
            Ok(Event::CData(ref e)) if in_loc => {
                text.push_str(&e.decode()?);
            }
            Ok(Event::End(ref e)) if e.local_name().as_ref() == b"loc" => {
                in_loc = false;
                let url = text.trim();
                if !url.is_empty() {
                    urls.push(url.to_string());
                    if urls.len() >= MAX_SITEMAP_URLS {
                        tracing::warn!(MAX_SITEMAP_URLS, "sitemap index URL count capped");
                        break;
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }
    Ok(SitemapContent::Index(urls))
}

fn parse_urlset_xml(
    reader: &mut quick_xml::Reader<&[u8]>,
    buf: &mut Vec<u8>,
) -> Result<SitemapContent> {
    use quick_xml::events::Event;

    let mut entries = Vec::new();
    let mut current: Option<SitemapEntry> = None;
    let mut current_tag = String::new();
    // See parse_index: element text arrives fragmented across
    // Text/GeneralRef/CData events; accumulate and assign on the
    // element's End tag.
    let mut text = String::new();

    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match name.as_str() {
                    "url" => {
                        current = Some(SitemapEntry {
                            url: String::new(),
                            lastmod: None,
                            priority: None,
                            changefreq: None,
                        });
                    }
                    "loc" | "lastmod" | "priority" | "changefreq" => {
                        current_tag = name;
                        text.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) if !current_tag.is_empty() => {
                text.push_str(&e.xml10_content()?);
            }
            Ok(Event::GeneralRef(ref e)) if !current_tag.is_empty() => {
                push_ref(&mut text, e)?;
            }
            Ok(Event::CData(ref e)) if !current_tag.is_empty() => {
                text.push_str(&e.decode()?);
            }
            Ok(Event::End(ref e)) => {
                let name = e.local_name();
                if name.as_ref() == b"url" {
                    if let Some(entry) = current.take()
                        && !entry.url.is_empty()
                    {
                        entries.push(entry);
                        if entries.len() >= MAX_SITEMAP_URLS {
                            tracing::warn!(MAX_SITEMAP_URLS, "sitemap urlset entries capped");
                            break;
                        }
                    }
                    current_tag.clear();
                } else if name.as_ref() == current_tag.as_bytes() {
                    let value = text.trim();
                    if let Some(ref mut entry) = current {
                        match current_tag.as_str() {
                            "loc" => entry.url = value.to_string(),
                            "lastmod" => entry.lastmod = Some(value.to_string()),
                            "priority" => entry.priority = value.parse().ok(),
                            "changefreq" => entry.changefreq = Some(value.to_string()),
                            _ => {}
                        }
                    }
                    current_tag.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }
    Ok(SitemapContent::UrlSet(entries))
}

/// Filter sitemap entries, keeping only those with lastmod >= since or no lastmod.
pub fn filter_since(entries: Vec<SitemapEntry>, since: &str) -> Vec<SitemapEntry> {
    entries
        .into_iter()
        .filter(|e| match &e.lastmod {
            Some(date) => date.as_str() >= since,
            None => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urlset() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc>https://example.com/page1</loc>
                <lastmod>2026-03-01</lastmod>
                <priority>0.8</priority>
                <changefreq>weekly</changefreq>
            </url>
            <url>
                <loc>https://example.com/page2</loc>
            </url>
        </urlset>"#;

        let result = parse_sitemap(xml).unwrap();
        match result {
            SitemapContent::UrlSet(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].url, "https://example.com/page1");
                assert_eq!(entries[0].lastmod.as_deref(), Some("2026-03-01"));
                assert_eq!(entries[0].priority, Some(0.8));
                assert_eq!(entries[0].changefreq.as_deref(), Some("weekly"));
                assert_eq!(entries[1].url, "https://example.com/page2");
                assert!(entries[1].lastmod.is_none());
                assert!(entries[1].priority.is_none());
            }
            _ => panic!("expected UrlSet"),
        }
    }

    #[test]
    fn parse_sitemap_index() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap>
                <loc>https://example.com/sitemap-posts.xml</loc>
            </sitemap>
            <sitemap>
                <loc>https://example.com/sitemap-pages.xml</loc>
            </sitemap>
        </sitemapindex>"#;

        let result = parse_sitemap(xml).unwrap();
        match result {
            SitemapContent::Index(urls) => {
                assert_eq!(urls.len(), 2);
                assert_eq!(urls[0], "https://example.com/sitemap-posts.xml");
                assert_eq!(urls[1], "https://example.com/sitemap-pages.xml");
            }
            _ => panic!("expected Index"),
        }
    }

    #[test]
    fn parse_empty_urlset() {
        let xml = br#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>"#;
        let result = parse_sitemap(xml).unwrap();
        match result {
            SitemapContent::UrlSet(entries) => assert!(entries.is_empty()),
            _ => panic!("expected UrlSet"),
        }
    }

    #[test]
    fn parse_gzipped_urlset() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let xml = br#"<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/gz-page</loc></url>
        </urlset>"#;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml).unwrap();
        let gzipped = encoder.finish().unwrap();

        let result = parse_sitemap(&gzipped).unwrap();
        match result {
            SitemapContent::UrlSet(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].url, "https://example.com/gz-page");
            }
            _ => panic!("expected UrlSet"),
        }
    }

    /// `&amp;`-style references are MANDATORY escaping for query-string
    /// URLs in sitemaps. quick-xml >= 0.38 emits them as GeneralRef
    /// events — a parser that drops them truncates URLs at `&`, one that
    /// assigns per-fragment keeps only the tail.
    #[test]
    fn urlset_resolves_entity_refs_in_loc() {
        let xml = br#"<urlset><url><loc>https://a.test/?x=1&amp;y=2</loc></url></urlset>"#;
        let SitemapContent::UrlSet(entries) = parse_sitemap(xml).unwrap() else {
            panic!("expected urlset");
        };
        assert_eq!(entries[0].url, "https://a.test/?x=1&y=2");
    }

    /// Character refs (`&#38;` = `&`) resolve the same way, and the
    /// sitemap-index <loc> arm gets the identical treatment.
    #[test]
    fn index_resolves_char_refs_in_loc() {
        let xml = br#"<sitemapindex><sitemap><loc>https://a.test/s.xml&#63;p=1</loc></sitemap></sitemapindex>"#;
        let SitemapContent::Index(urls) = parse_sitemap(xml).unwrap() else {
            panic!("expected index");
        };
        assert_eq!(urls[0], "https://a.test/s.xml?p=1");
    }

    /// CDATA inside <loc> is literal text — accumulated like the rest.
    #[test]
    fn urlset_reads_cdata_in_loc() {
        let xml = br#"<urlset><url><loc><![CDATA[https://a.test/?x=1&y=2]]></loc></url></urlset>"#;
        let SitemapContent::UrlSet(entries) = parse_sitemap(xml).unwrap() else {
            panic!("expected urlset");
        };
        assert_eq!(entries[0].url, "https://a.test/?x=1&y=2");
    }

    /// A urlset past the protocol's 50k URL limit is truncated, not grown
    /// without bound — the byte cap alone does not bound heap growth.
    #[test]
    fn urlset_caps_entries_at_protocol_limit() {
        let mut xml = String::from("<urlset>");
        for i in 0..MAX_SITEMAP_URLS + 1 {
            xml.push_str(&format!("<url><loc>https://a.test/{i}</loc></url>"));
        }
        xml.push_str("</urlset>");
        let out = parse_sitemap(xml.as_bytes()).unwrap();
        let SitemapContent::UrlSet(entries) = out else {
            panic!("expected urlset");
        };
        assert_eq!(entries.len(), MAX_SITEMAP_URLS);
    }

    /// Same cap on a sitemap index's child list.
    #[test]
    fn index_caps_children_at_protocol_limit() {
        let mut xml = String::from("<sitemapindex>");
        for i in 0..MAX_SITEMAP_URLS + 1 {
            xml.push_str(&format!(
                "<sitemap><loc>https://a.test/{i}.xml</loc></sitemap>"
            ));
        }
        xml.push_str("</sitemapindex>");
        let out = parse_sitemap(xml.as_bytes()).unwrap();
        let SitemapContent::Index(urls) = out else {
            panic!("expected index");
        };
        assert_eq!(urls.len(), MAX_SITEMAP_URLS);
    }

    #[test]
    fn parse_invalid_xml_errors() {
        let xml = b"not xml at all";
        assert!(parse_sitemap(xml).is_err());
    }

    #[test]
    fn filter_entries_by_since() {
        let entries = vec![
            SitemapEntry {
                url: "https://a.com/old".into(),
                lastmod: Some("2025-01-01".into()),
                priority: None,
                changefreq: None,
            },
            SitemapEntry {
                url: "https://a.com/new".into(),
                lastmod: Some("2026-03-01".into()),
                priority: None,
                changefreq: None,
            },
            SitemapEntry {
                url: "https://a.com/nodate".into(),
                lastmod: None,
                priority: None,
                changefreq: None,
            },
        ];
        let filtered = filter_since(entries, "2026-01-01");
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].url, "https://a.com/new");
        assert_eq!(filtered[1].url, "https://a.com/nodate");
    }

    /// Decompression-bomb guard: a gzipped sitemap whose compressed size is
    /// tiny but whose DECOMPRESSED size exceeds the cap must be rejected.
    ///
    /// This test ACTUALLY COMPRESSES a large body and asserts the decompressed
    /// read is rejected — not just that the code exists. The compressed payload
    /// is well under the cap (proving capping compressed bytes would miss it),
    /// while the decompressed payload far exceeds it.
    #[test]
    fn rejects_gzip_bomb_decompressed_exceeds_cap() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        // Build a large XML sitemap — 10 000 URL entries, ~800 KB decompressed.
        let mut xml = String::from(
            r#"<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">"#,
        );
        for i in 0..10_000 {
            xml.push_str(&format!(
                "<url><loc>https://example.com/page{i}</loc></url>"
            ));
        }
        xml.push_str("</urlset>");

        let decompressed_size = xml.len();

        // Gzip compress — repetitive XML compresses dramatically.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).unwrap();
        let gzipped = encoder.finish().unwrap();
        let compressed_size = gzipped.len();

        // The bomb shape: compressed is tiny, decompressed is large.
        // The compression ratio proves this is a real bomb vector.
        let ratio = decompressed_size as f64 / compressed_size as f64;
        assert!(
            compressed_size < 50_000,
            "compressed ({compressed_size}) should be small"
        );
        assert!(
            ratio > 10.0,
            "compression ratio ({ratio:.1}x) should be >10x — this is the bomb shape"
        );

        // Cap at 100 KB — the decompressed body (~800 KB) exceeds it, but the
        // compressed body (~20 KB) does not. A guard that caps compressed bytes
        // would let this through; the decompressed-byte cap rejects it.
        let cap: u64 = 100 * 1024;
        assert!(
            compressed_size as u64 <= cap,
            "compressed ({compressed_size}) must be under cap ({cap}) — capping compressed bytes would miss the bomb"
        );

        let result = parse_sitemap_with_cap(&gzipped, cap);
        assert!(result.is_err(), "gzip bomb must be rejected");

        // The error must name the limit (HttpError::BodyTooLarge Display).
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeded cap"),
            "error should name the cap: {err_msg}"
        );
        assert!(
            err_msg.contains(&cap.to_string()),
            "error should contain the limit value ({cap}): {err_msg}"
        );
    }
}
