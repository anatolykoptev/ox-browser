use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    YouTube,
    Generic,
}

static YOUTUBE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"https?://(?:(?:www\.|m\.|music\.)?youtube\.com/(?:watch\?|shorts/|embed/)|youtu\.be/)",
    )
    .unwrap()
});

pub fn detect_platform(url: &str) -> Platform {
    if YOUTUBE_RE.is_match(url) {
        return Platform::YouTube;
    }
    Platform::Generic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_youtube_watch() {
        assert_eq!(
            detect_platform("https://www.youtube.com/watch?v=abc123"),
            Platform::YouTube
        );
    }

    #[test]
    fn detect_youtube_short() {
        assert_eq!(
            detect_platform("https://youtube.com/shorts/abc123"),
            Platform::YouTube
        );
    }

    #[test]
    fn detect_youtu_be() {
        assert_eq!(
            detect_platform("https://youtu.be/abc123"),
            Platform::YouTube
        );
    }

    #[test]
    fn detect_music_youtube() {
        assert_eq!(
            detect_platform("https://music.youtube.com/watch?v=abc123"),
            Platform::YouTube
        );
    }

    #[test]
    fn detect_generic() {
        assert_eq!(
            detect_platform("https://example.com/page"),
            Platform::Generic
        );
    }

    #[test]
    fn detect_instagram() {
        assert_eq!(
            detect_platform("https://www.instagram.com/reel/abc123/"),
            Platform::Generic
        );
    }
}
