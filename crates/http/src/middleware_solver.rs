//! CF solver middleware — intercepts Cloudflare errors, solves via CookieProvider, retries.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use crate::cloudflare::ChallengeType;
use crate::cookie_cache::CookieCache;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that auto-solves CF challenges via a [`CookieProvider`].
///
/// On `HttpError::Cloudflare` (except `Block`), calls the provider, caches
/// the result, injects cookies, and retries the request once.
pub fn solver_middleware(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(SolverHandler {
            next,
            provider: Arc::clone(&provider),
            cache: Arc::clone(&cache),
        })
    })
}

struct SolverHandler {
    next: Arc<dyn Handler>,
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
}

/// Extract the domain (host) from a URL string.
fn domain_from_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default()
}

/// Build a `cookie` header value from a solved challenge.
fn cookie_header(solution: &SolvedChallenge) -> String {
    solution
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Inject cookies and user-agent from a solved challenge into the request.
/// CF binds cf_clearance to the UA — mismatch causes 403.
fn inject_solution(req: &mut Request, solution: &SolvedChallenge) {
    let value = cookie_header(solution);
    req.set_header("cookie", value);
    if !solution.user_agent.is_empty() {
        req.set_header("user-agent", solution.user_agent.clone());
    }
}

#[async_trait]
impl Handler for SolverHandler {
    async fn handle(&self, mut req: Request) -> Result<HttpResponse> {
        let domain = domain_from_url(&req.url);

        // Check cache first — inject cookies if we have a prior solution.
        if let Some(solution) = self.cache.get(&domain) {
            debug!(domain = %domain, "solver: using cached cookies");
            inject_solution(&mut req, &solution);
            return self.next.handle(req).await;
        }

        // No cached cookies — try the request normally.
        match self.next.handle(req.clone()).await {
            // Block errors are not solvable — pass through.
            Err(HttpError::Cloudflare(ChallengeType::Block, status, ray)) => {
                Err(HttpError::Cloudflare(ChallengeType::Block, status, ray))
            }
            // Solvable CF challenge — call provider, cache, retry once.
            Err(HttpError::Cloudflare(challenge_type, _status, _ray)) => {
                debug!(domain = %domain, challenge = %challenge_type, "solver: solving challenge");
                let solution = self
                    .provider
                    .solve(&req.url, challenge_type)
                    .await
                    .map_err(|e| HttpError::ProxyPool(format!("solver failed: {e}")))?;
                self.cache.put(&domain, solution.clone());

                // If solver returned the page body directly, use it (avoids IP mismatch on retry)
                if let Some(ref body) = solution.body {
                    debug!(domain = %domain, "solver: using body from solve response");
                    return Ok(HttpResponse {
                        status: 200,
                        url: req.url.clone(),
                        headers: wreq::header::HeaderMap::new(),
                        body: body.clone(),
                    });
                }

                // No body — retry with cookies + UA
                inject_solution(&mut req, &solution);
                self.next.handle(req).await
            }
            // Everything else passes through.
            other => other,
        }
    }
}

#[cfg(test)]
#[path = "middleware_solver_tests.rs"]
mod tests;
