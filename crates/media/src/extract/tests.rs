use super::*;

// === Image tests (8 existing) ===

#[test]
fn extract_og_image() {
    let html = r#"<html><head>
        <meta property="og:image" content="https://example.com/hero.jpg"/>
        <meta property="og:title" content="Test Place"/>
    </head><body></body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/hero.jpg");
    assert_eq!(results[0].title, "Test Place");
    assert_eq!(results[0].media_kind, MediaKind::Image);
}

#[test]
fn extract_img_tags() {
    let html = r#"<html><body>
        <img src="https://example.com/photo1.jpg" width="1024" height="768" alt="Photo 1">
        <img src="https://example.com/photo2.webp" width="800" height="600">
        <img src="/logo.png" width="100" height="50">
        <img src="icon.svg">
    </body></html>"#;
    let results = extract_media(html, "https://example.com/page");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].url, "https://example.com/photo1.jpg");
    assert_eq!(results[0].width, 1024);
    assert_eq!(results[0].title, "Photo 1");
}

#[test]
fn extract_relative_urls() {
    let html = r#"<html><body>
        <img src="/uploads/photo.jpg" width="800" height="600">
    </body></html>"#;
    let results = extract_media(html, "https://example.com/about/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/uploads/photo.jpg");
}

#[test]
fn extract_srcset_largest() {
    let html = r#"<html><body>
        <img src="small.jpg" srcset="medium.jpg 800w, large.jpg 1600w">
    </body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/large.jpg");
}

#[test]
fn extract_background_image() {
    let html = r#"<html><body>
        <div style="background-image: url('https://example.com/bg.jpg')"></div>
    </body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/bg.jpg");
}

#[test]
fn skip_data_urls() {
    let html = r#"<html><body>
        <img src="data:image/gif;base64,R0lGODlhAQ">
        <img src="https://example.com/real.jpg">
    </body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/real.jpg");
}

#[test]
fn dedup_same_url() {
    let html = r#"<html><head>
        <meta property="og:image" content="https://example.com/hero.jpg"/>
    </head><body>
        <img src="https://example.com/hero.jpg">
    </body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
}

#[test]
fn skip_tracking_pixels() {
    let html = r#"<html><body>
        <img src="https://tracker.com/pixel.png" width="1" height="1">
        <img src="https://example.com/photo.jpg" width="800" height="600">
    </body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/photo.jpg");
}

// === Video tests ===

#[test]
fn extract_video_tag() {
    let html = r#"<html><body><video src="https://example.com/clip.mp4"></video></body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].media_kind, MediaKind::Video);
    assert_eq!(results[0].url, "https://example.com/clip.mp4");
}

#[test]
fn extract_video_source_tag() {
    let html = r#"<html><body><video><source src="https://example.com/clip.mp4" type="video/mp4"></video></body></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].media_kind, MediaKind::Video);
}

#[test]
fn extract_og_video() {
    let html = r#"<html><head><meta property="og:video" content="https://example.com/video.mp4"/></head></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert!(
        results
            .iter()
            .any(|r| r.media_kind == MediaKind::Video && r.url == "https://example.com/video.mp4")
    );
}

#[test]
fn extract_json_ld_video() {
    let html = r#"<html><head><script type="application/ld+json">{"@type":"VideoObject","contentUrl":"https://example.com/v.mp4","name":"Test"}</script></head></html>"#;
    let results = extract_media(html, "https://example.com/");
    let video = results
        .iter()
        .find(|r| r.media_kind == MediaKind::Video)
        .unwrap();
    assert_eq!(video.url, "https://example.com/v.mp4");
    assert_eq!(video.title, "Test");
}

#[test]
fn extract_twitter_player() {
    let html = r#"<html><head><meta name="twitter:player:stream" content="https://example.com/stream.mp4"/></head></html>"#;
    let results = extract_media(html, "https://example.com/");
    assert!(results.iter().any(|r| r.media_kind == MediaKind::Video));
}
