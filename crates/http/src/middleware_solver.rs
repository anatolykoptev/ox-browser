//! CF solver middleware — intercepts Cloudflare errors, solves via CookieProvider, retries.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use crate::cloudflare::ChallengeType;
use crate::cookie_cache::CookieCache;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::middleware_retry::is_idempotent;
use crate::solver_negcache::{SolverNegCache, record_solver_giveup};
use crate::{HttpResponse, Result};

/// Returns a middleware that auto-solves CF challenges via a [`CookieProvider`].
///
/// On `HttpError::Cloudflare` (except `Block`), calls the provider, caches
/// the result, injects cookies, and retries the request once.
///
/// A shared [`SolverNegCache`] bounds the retry storm: a domain whose solves
/// keep failing is put on cooldown so we stop paying for doomed 15-25s solves.
pub fn solver_middleware(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
) -> MiddlewareFn {
    solver_middleware_with_negcache(provider, cache, Arc::new(SolverNegCache::default()))
}

/// Like [`solver_middleware`] but with an explicit (shared/testable) negative
/// cache.
pub fn solver_middleware_with_negcache(
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
    negcache: Arc<SolverNegCache>,
) -> MiddlewareFn {
    Arc::new(move |next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(SolverHandler {
            next,
            provider: Arc::clone(&provider),
            cache: Arc::clone(&cache),
            negcache: Arc::clone(&negcache),
        })
    })
}

struct SolverHandler {
    next: Arc<dyn Handler>,
    provider: Arc<dyn CookieProvider>,
    cache: Arc<CookieCache>,
    negcache: Arc<SolverNegCache>,
}

impl SolverHandler {
    /// Solve a CF challenge and retry the request once with the solution.
    /// Used for both genuine CF challenges (any method — CF intercepted the
    /// request, the origin never saw it) and inferred challenges (idempotent
    /// methods only — the caller gates the non-idempotent case before
    /// reaching here).
    async fn solve_and_retry(
        &self,
        mut req: Request,
        domain: &str,
        challenge_type: ChallengeType,
    ) -> Result<HttpResponse> {
        // Retry-storm guard: if this domain is on cooldown after repeated
        // solve failures, skip the 15-25s solver and surface the CF error
        // immediately. A success below clears the cooldown.
        if self.negcache.is_blocked(domain) {
            record_solver_giveup(domain);
            // Return ProxyPool (not Cloudflare) — this is a solver decision,
            // not a fresh CF challenge. Consistent with the N failures before
            // cooldown trips; the GiveUp gate in read_pipeline fast-fails either way.
            return Err(HttpError::ProxyPool(format!(
                "solver negcache: domain {domain} on cooldown"
            )));
        }

        debug!(domain = %domain, challenge = %challenge_type, "solver: solving challenge");
        let solution = match self.provider.solve(&req.url, challenge_type).await {
            Ok(s) => s,
            Err(e) => {
                // NOTE: we count all solver errors (including transient
                // 502/timeout) toward the cooldown. A go-browser blip trips
                // a 5-min per-domain cooldown which auto-recovers — acceptable
                // trade-off vs. the 20-143× retry storm that results from NOT
                // rate-limiting doomed solve attempts.
                self.negcache.record_failure(domain);
                return Err(HttpError::ProxyPool(format!("solver failed: {e}")));
            }
        };
        self.cache.put(domain, solution.clone());
        // A real solution ends any storm for this domain.
        self.negcache.record_success(domain);

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
}

/// Extract the domain (host) from a URL string (delegates to [`crate::url_util::extract_domain`]).
fn domain_from_url(url: &str) -> String {
    crate::url_util::extract_domain(url).unwrap_or_default()
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
        // This is the first (and only) send of the request with cached
        // cookies — not a re-send of a failed attempt, so the F1
        // idempotency gate does not apply here.
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
            // F1: inferred-from-status challenge on a non-idempotent method.
            // The origin MAY have processed the request — do not re-send.
            // Return the original response so the caller sees the real
            // status + body instead of a synthesised empty error.
            Err(HttpError::CloudflareInferred(_, resp)) if !is_idempotent(&req.method) => {
                debug!(
                    domain = %domain,
                    method = %req.method,
                    "solver: inferred challenge on non-idempotent method — returning original response, not re-sending"
                );
                Ok(*resp)
            }
            // Genuine CF challenge (any method) — solve and retry once.
            // CF intercepted the request; the origin never saw it, so
            // re-sending is safe even for POST.
            Err(HttpError::Cloudflare(challenge_type, _status, _ray)) => {
                self.solve_and_retry(req, &domain, challenge_type).await
            }
            // Inferred challenge on an idempotent method — solve as a
            // JsChallenge (the quality_check default) and retry once.
            Err(HttpError::CloudflareInferred(_, _)) => {
                self.solve_and_retry(req, &domain, ChallengeType::JsChallenge)
                    .await
            }
            // Everything else passes through.
            other => other,
        }
    }
}

#[cfg(test)]
#[path = "middleware_solver_tests.rs"]
mod tests;
