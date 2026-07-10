use base64::{Engine, engine::general_purpose::STANDARD};
use once_cell::sync::Lazy;
use regex::Regex;

/// Legacy format: "ondemand.s":"<hash>" (old webpack, pre-2025)
static ONDEMAND_LEGACY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"['|"]{1}ondemand\.s['|"]{1}:\s*['|"]{1}([\w]*)['|"]{1}"#).unwrap());

/// New format step 1: find chunk ID for "ondemand.s" in name map (e.g. 20113:"ondemand.s")
static ONDEMAND_CHUNK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(\d+)\s*:\s*["']ondemand\.s["']"#).unwrap());

static INDICES_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\(\w{1}\[(\d{1,2})\],\s*16\)").unwrap());

static VERIFY_NC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta[^>]+name=["']twitter-site-verification["'][^>]+content=["']([^"']+)["']"#)
        .unwrap()
});

static VERIFY_CN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta[^>]+content=["']([^"']+)["'][^>]+name=["']twitter-site-verification["']"#)
        .unwrap()
});

static NUM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"-?\d+").unwrap());

/// Parse twitter-site-verification meta tag and base64-decode its content.
pub(crate) fn parse_verification_key(html: &str) -> Result<Vec<u8>, String> {
    let key = VERIFY_NC_RE
        .captures(html)
        .or_else(|| VERIFY_CN_RE.captures(html))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| "twitter-site-verification meta tag not found".to_string())?;

    STANDARD
        .decode(key)
        .map_err(|e| format!("base64 decode error: {e}"))
}

/// Find ondemand.s hash and build the full JS URL.
/// Supports both old format ("ondemand.s":"<hash>") and new webpack format
/// (name map: 20113:"ondemand.s", hash map: 20113:"<hash>").
pub(crate) fn parse_ondemand_url(html: &str) -> Result<String, String> {
    // Try legacy format first
    if let Some(hash) = ONDEMAND_LEGACY_RE
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .filter(|h| !h.is_empty())
    {
        return Ok(format!(
            "https://abs.twimg.com/responsive-web/client-web/ondemand.s.{hash}a.js"
        ));
    }

    // New format: find chunk ID, then look up hash
    let chunk_id = ONDEMAND_CHUNK_RE
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| "ondemand.s chunk ID not found in HTML".to_string())?;

    // Build regex to find hash for this chunk ID (second occurrence is the hash map)
    let hash_re = Regex::new(&format!(r#"{chunk_id}\s*:\s*["']([a-f0-9]+)["']"#))
        .map_err(|e| format!("hash regex error: {e}"))?;

    // Find all occurrences — first is the name map ("ondemand.s"), second is the hash map
    let hashes: Vec<&str> = hash_re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .filter(|v| *v != "ondemand.s" && v.chars().all(|c| c.is_ascii_hexdigit()))
        .collect();

    let hash = hashes
        .first()
        .ok_or_else(|| format!("hash for chunk {chunk_id} not found in HTML"))?;

    Ok(format!(
        "https://abs.twimg.com/responsive-web/client-web/ondemand.s.{hash}a.js"
    ))
}

/// Extract parseInt indices from ondemand JS.
/// Returns (first_index, rest_indices).
pub(crate) fn parse_key_indices(js: &str) -> Result<(usize, Vec<usize>), String> {
    let indices: Vec<usize> = INDICES_RE
        .captures_iter(js)
        .filter_map(|c| c.get(1))
        .filter_map(|m| m.as_str().parse::<usize>().ok())
        .collect();

    if indices.is_empty() {
        return Err("no parseInt indices found in JS".to_string());
    }

    Ok((indices[0], indices[1..].to_vec()))
}

/// Parse all 4 SVG loading animations from Twitter HTML.
/// Returns a 4-element vec; empty inner vec means the frame was missing.
pub(crate) fn parse_svg_frames(html: &str) -> Result<Vec<Vec<Vec<i32>>>, String> {
    let mut frames = vec![vec![]; 4];

    #[allow(clippy::needless_range_loop)] // index drives the regex pattern and the frame slot
    for i in 0..4usize {
        let svg_re = Regex::new(&format!(
            r#"(?s)<svg[^>]*id=["']loading-x-anim-{i}["'][^>]*>.*?</svg>"#
        ))
        .map_err(|e| format!("svg regex error: {e}"))?;

        let svg = match svg_re.find(html) {
            Some(m) => m.as_str(),
            None => continue,
        };

        let path_data = extract_path_data(svg);
        if let Some(d) = path_data {
            frames[i] = parse_path_data(d);
        }
    }

    Ok(frames)
}

/// Extract the `d` attribute from the invisible path inside an SVG.
/// Primary: `fill="#1d9bf008"` attribute on `<path`.
/// Fallback: second `<path` element inside a `<g>` group (positional).
fn extract_path_data(svg: &str) -> Option<&str> {
    // Primary: fill="#1d9bf008" before or after d=
    let primary_nd =
        Regex::new(r#"<path[^>]*d=["']([^"']+)["'][^>]*fill=["']#1d9bf008["']"#).ok()?;
    let primary_dn =
        Regex::new(r#"<path[^>]*fill=["']#1d9bf008["'][^>]*d=["']([^"']+)["']"#).ok()?;

    if let Some(c) = primary_nd
        .captures(svg)
        .or_else(|| primary_dn.captures(svg))
    {
        return c.get(1).map(|m| m.as_str());
    }

    // Positional fallback: second <path element within <g>
    let g_re = Regex::new(r"(?s)<g[^>]*>(.*?)</g>").ok()?;
    let path_d_re = Regex::new(r#"<path[^>]*d=["']([^"']+)["']"#).ok()?;

    for g_cap in g_re.captures_iter(svg) {
        let g_content = g_cap.get(1)?.as_str();
        let paths: Vec<&str> = path_d_re
            .captures_iter(g_content)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .collect();
        if paths.len() >= 2 {
            return Some(paths[1]);
        }
    }

    None
}

/// Split SVG path data on "C" curves and extract integer coordinates.
pub(crate) fn parse_path_data(d: &str) -> Vec<Vec<i32>> {
    d.split('C')
        .skip(1)
        .map(|part| {
            NUM_RE
                .find_iter(part)
                .filter_map(|m| m.as_str().parse::<i32>().ok())
                .collect::<Vec<i32>>()
        })
        .filter(|row| !row.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_verification_key_name_first() {
        let key = base64::engine::general_purpose::STANDARD.encode("hello");
        let html = format!(r#"<meta name="twitter-site-verification" content="{key}">"#);
        let result = parse_verification_key(&html).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_parse_verification_key_content_first() {
        let key = base64::engine::general_purpose::STANDARD.encode("world");
        let html = format!(r#"<meta content="{key}" name="twitter-site-verification">"#);
        let result = parse_verification_key(&html).unwrap();
        assert_eq!(result, b"world");
    }

    #[test]
    fn test_parse_verification_key_missing() {
        let result = parse_verification_key("<html></html>");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ondemand_url() {
        let html = r#"var a={'ondemand.s':'abc123'};"#;
        let url = parse_ondemand_url(html).unwrap();
        assert_eq!(
            url,
            "https://abs.twimg.com/responsive-web/client-web/ondemand.s.abc123a.js"
        );
    }

    #[test]
    fn test_parse_ondemand_url_new_webpack_format() {
        // Real Twitter format: name map + hash map as separate objects
        let html = r#"var o={20112:"bundle.Birdwatch",20113:"ondemand.s",20226:"react-stuff"};var h={20112:"f82919b",20113:"117abc8",20226:"afa0293"};"#;
        let url = parse_ondemand_url(html).unwrap();
        assert_eq!(
            url,
            "https://abs.twimg.com/responsive-web/client-web/ondemand.s.117abc8a.js"
        );
    }

    #[test]
    fn test_parse_ondemand_url_missing() {
        let result = parse_ondemand_url("<html></html>");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_key_indices() {
        let js = "var t=parseInt(e[3], 16)+parseInt(e[7], 16)+parseInt(e[11], 16);";
        let (first, rest) = parse_key_indices(js).unwrap();
        assert_eq!(first, 3);
        assert_eq!(rest, vec![7, 11]);
    }

    #[test]
    fn test_parse_key_indices_missing() {
        let result = parse_key_indices("var x = 42;");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_data() {
        let d = "M0 0C10 20 30 40 50 60C70 80 90 100 110 120";
        let result = parse_path_data(d);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], vec![10, 20, 30, 40, 50, 60]);
        assert_eq!(result[1], vec![70, 80, 90, 100, 110, 120]);
    }

    #[test]
    fn test_parse_path_data_negative() {
        let d = "M0 0C-10 -20 30 40 50 60";
        let result = parse_path_data(d);
        assert_eq!(result[0], vec![-10, -20, 30, 40, 50, 60]);
    }

    #[test]
    fn test_parse_svg_frames_with_fill() {
        let html = r##"<svg id="loading-x-anim-0" viewBox="0 0 100 100">
            <path d="M0 0C10 20 30 40 50 60" fill="#1d9bf008"/>
        </svg>"##;
        let frames = parse_svg_frames(html).unwrap();
        assert_eq!(frames.len(), 4);
        assert!(!frames[0].is_empty());
        assert!(frames[1].is_empty());
    }

    #[test]
    fn test_parse_svg_frames_positional_fallback() {
        // No fill="#1d9bf008" — second path in <g> should be used
        let html = r##"<svg id="loading-x-anim-1" viewBox="0 0 100 100">
            <g>
                <path d="M0 0C1 2 3 4 5 6" fill="#000"/>
                <path d="M0 0C7 8 9 10 11 12" fill="#fff"/>
            </g>
        </svg>"##;
        let frames = parse_svg_frames(html).unwrap();
        assert!(!frames[1].is_empty());
        assert_eq!(frames[1][0], vec![7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn test_parse_svg_frames_missing_all() {
        let frames = parse_svg_frames("<html></html>").unwrap();
        assert_eq!(frames.len(), 4);
        assert!(frames.iter().all(|f| f.is_empty()));
    }
}
