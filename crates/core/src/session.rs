use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ox_http::{BrowserProfile, HttpClient, HttpConfig, HttpResponse, platform_matched_profile};
use rand::Rng;

use crate::Result;

/// Persistent browsing context with consistent fingerprint, request counting,
/// and idle time tracking. Ported from go-stealth's session/session.go.
pub struct Session {
    /// Unique session identifier (16 hex chars).
    pub id: String,
    /// When the session was created.
    pub created_at: Instant,
    last_used: RwLock<Instant>,
    request_count: AtomicU64,
    profile: &'static BrowserProfile,
    http: HttpClient,
}

/// Configuration for creating a [`Session`].
#[derive(Default)]
pub struct SessionConfig {
    /// Browser profile to use. If `None`, a platform-matched profile is chosen.
    pub profile: Option<&'static BrowserProfile>,
    /// HTTP client configuration. The `profile` field in `HttpConfig` will be
    /// overridden by the session's profile.
    pub http_config: HttpConfig,
}

impl Session {
    /// Create a new session with a consistent browser fingerprint.
    ///
    /// Generates a random 16-hex-char ID, picks a profile (explicit or
    /// platform-matched), and creates an `HttpClient` with that profile.
    pub fn new(config: SessionConfig) -> Result<Self> {
        let profile = config.profile.unwrap_or_else(platform_matched_profile);

        let http_config = HttpConfig {
            profile: Some(profile),
            ..config.http_config
        };
        let http = HttpClient::new(http_config)?;

        let now = Instant::now();
        Ok(Self {
            id: generate_id(),
            created_at: now,
            last_used: RwLock::new(now),
            request_count: AtomicU64::new(0),
            profile,
            http,
        })
    }

    /// Execute a GET request, updating counters and last-used timestamp.
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.touch();
        self.request_count.fetch_add(1, Ordering::Relaxed);
        Ok(self.http.get(url).await?)
    }

    /// Returns the session's browser profile.
    pub fn profile(&self) -> &BrowserProfile {
        self.profile
    }

    /// Returns the total number of requests made in this session.
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Returns the time of the last request (or creation if none yet).
    pub fn last_used(&self) -> Instant {
        *self.last_used.read().expect("last_used lock poisoned")
    }

    /// Returns how long this session has existed.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Returns how long since the last request.
    pub fn idle_time(&self) -> Duration {
        self.last_used().elapsed()
    }

    /// Update the last-used timestamp to now.
    fn touch(&self) {
        let mut last = self.last_used.write().expect("last_used lock poisoned");
        *last = Instant::now();
    }
}

/// Generate a random 16-hex-char session ID (8 random bytes).
fn generate_id() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes);
    hex::encode(&bytes)
}

/// Minimal hex encoding (avoids adding `hex` crate dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_id_length_and_hex() {
        let id = generate_id();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_id_unique() {
        let a = generate_id();
        let b = generate_id();
        assert_ne!(a, b);
    }
}
