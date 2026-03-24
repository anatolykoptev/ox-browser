//! CookieProvider trait for solving Cloudflare challenges.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::cloudflare::ChallengeType;

/// Result of a successfully solved Cloudflare challenge.
#[derive(Debug, Clone)]
pub struct SolvedChallenge {
    pub cookies: HashMap<String, String>,
    pub user_agent: String,
    /// Optional page body returned by the solver (e.g. Byparr response HTML).
    /// When present, consumers can use this directly instead of retrying the request.
    pub body: Option<String>,
}

/// Async trait for solving Cloudflare challenges and returning cookies.
#[async_trait]
pub trait CookieProvider: Send + Sync {
    async fn solve(
        &self,
        url: &str,
        challenge_type: ChallengeType,
    ) -> Result<SolvedChallenge, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        user_agent: String,
    }

    #[async_trait]
    impl CookieProvider for MockProvider {
        async fn solve(
            &self,
            _url: &str,
            _challenge_type: ChallengeType,
        ) -> Result<SolvedChallenge, String> {
            let mut cookies = HashMap::new();
            cookies.insert("cf_clearance".into(), "mock-token-abc123".into());
            Ok(SolvedChallenge {
                cookies,
                user_agent: self.user_agent.clone(),
                body: None,
            })
        }
    }

    #[tokio::test]
    async fn mock_provider_returns_cookies() {
        let provider = MockProvider {
            user_agent: "Mozilla/5.0 Test".into(),
        };
        let result = provider
            .solve("https://example.com", ChallengeType::JsChallenge)
            .await
            .unwrap();
        assert_eq!(
            result.cookies.get("cf_clearance").unwrap(),
            "mock-token-abc123"
        );
        assert_eq!(result.user_agent, "Mozilla/5.0 Test");
    }

    #[tokio::test]
    async fn provider_is_object_safe() {
        let provider: Box<dyn CookieProvider> = Box::new(MockProvider {
            user_agent: "Test/1.0".into(),
        });
        let result = provider
            .solve("https://example.com", ChallengeType::Turnstile)
            .await
            .unwrap();
        assert!(result.cookies.contains_key("cf_clearance"));
    }
}
