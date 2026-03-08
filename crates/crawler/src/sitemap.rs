//! Sitemap XML parser and auto-discovery.

use anyhow::Result;
use flate2::read::GzDecoder;
use std::io::Read;

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
pub fn parse_sitemap(xml: &[u8]) -> Result<SitemapContent> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // Detect gzip (magic bytes 0x1f, 0x8b)
    let data = if xml.len() >= 2 && xml[0] == 0x1f && xml[1] == 0x8b {
        let mut decoder = GzDecoder::new(xml);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| anyhow::anyhow!("gzip decompression failed: {e}"))?;
        decompressed
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

fn parse_index(
    reader: &mut quick_xml::Reader<&[u8]>,
    buf: &mut Vec<u8>,
) -> Result<SitemapContent> {
    use quick_xml::events::Event;

    let mut urls = Vec::new();
    let mut in_loc = false;

    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(ref e)) if e.local_name().as_ref() == b"loc" => {
                in_loc = true;
            }
            Ok(Event::Text(ref e)) if in_loc => {
                urls.push(e.unescape()?.trim().to_string());
                in_loc = false;
            }
            Ok(Event::End(ref e)) if e.local_name().as_ref() == b"loc" => {
                in_loc = false;
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

    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(ref e)) => {
                let name =
                    String::from_utf8_lossy(e.local_name().as_ref()).to_string();
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
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                if let Some(ref mut entry) = current {
                    let text = e.unescape()?.trim().to_string();
                    match current_tag.as_str() {
                        "loc" => entry.url = text,
                        "lastmod" => entry.lastmod = Some(text),
                        "priority" => entry.priority = text.parse().ok(),
                        "changefreq" => entry.changefreq = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.local_name().as_ref().to_vec();
                if name == b"url" {
                    if let Some(entry) = current.take() {
                        if !entry.url.is_empty() {
                            entries.push(entry);
                        }
                    }
                }
                current_tag.clear();
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
        use flate2::write::GzEncoder;
        use flate2::Compression;
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
}
