//! Hard red tests for CookieCache TTL and solver middleware timing.
//!
//! Each test exposes a real edge case in cookie caching / TTL behavior.
//! Focus: expiration races, cache invalidation, concurrent access,
//! solver re-solve after TTL, and multi-domain isolation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ox_http::cloudflare::ChallengeType;
use ox_http::cookie_cache::CookieCache;
use ox_http::cookie_provider::{CookieProvider, SolvedChallenge};
use ox_http::middleware::{chain, Handler, Request};
use ox_http::middleware_solver::solver_middleware;
use ox_http::{HttpError, HttpResponse, Result};
use wreq::header::HeaderMap;

fn make_solution(token: &str, ua: &str) -> SolvedChallenge {
    let mut cookies = HashMap::new();
    cookies.insert("cf_clearance".into(), token.into());
    SolvedChallenge { cookies, user_agent: ua.into() }
}

fn make_request(url: &str) -> Request {
    Request {
        method: "GET".into(),
        url: url.into(),
        headers: vec![],
        body: None,
        proxy: None,
    }
}

// ── Bug 1: Expired cache still counts in len() ────────────────────────
// len() returns raw count including expired entries.
// get() filters them, but len() doesn't — misleading.

#[test]
fn expired_entries_invisible_to_get_but_counted_in_len() {
    let cache = CookieCache::new(Duration::from_millis(1));
    cache.put("a.com", make_solution("tok-a", "UA"));
    cache.put("b.com", make_solution("tok-b", "UA"));
    std::thread::sleep(Duration::from_millis(5));
    // get() should return None (expired)
    assert!(cache.get("a.com").is_none(), "expired entry visible via get");
    assert!(cache.get("b.com").is_none(), "expired entry visible via get");
    // len() still shows 2 until evict_expired()
    assert_eq!(cache.len(), 2, "len should include stale entries before eviction");
    cache.evict_expired();
    assert_eq!(cache.len(), 0, "len should be 0 after eviction");
}

// ── Bug 2: Zero TTL means instant expiry ──────────────────────────────
// With TTL=0, `Instant::now() + Duration::ZERO` may equal `Instant::now()`,
// so the `<` comparison in get() might return the entry if clocks align.
// Verify zero TTL always expires immediately.

#[test]
fn zero_ttl_never_returns_cached_value() {
    let cache = CookieCache::new(Duration::ZERO);
    for i in 0..100 {
        cache.put("test.com", make_solution(&format!("tok-{i}"), "UA"));
        // Even without sleep, zero TTL should expire
    }
    // After 100 puts, at least the last one should be expired
    // (Instant::now() has progressed since the put)
    std::thread::sleep(Duration::from_millis(1));
    assert!(
        cache.get("test.com").is_none(),
        "zero TTL should always expire"
    );
}

// ── Bug 3: Overwrite resets TTL ───────────────────────────────────────
// Putting the same domain again should reset the TTL clock.
// A stale entry overwritten with a fresh one should be gettable.

#[test]
fn overwrite_resets_ttl() {
    let cache = CookieCache::new(Duration::from_millis(50));
    cache.put("example.com", make_solution("old-tok", "UA"));
    std::thread::sleep(Duration::from_millis(30));
    // Overwrite before expiry — TTL resets
    cache.put("example.com", make_solution("new-tok", "UA"));
    std::thread::sleep(Duration::from_millis(30));
    // 30ms after overwrite, still within 50ms TTL
    let sol = cache
        .get("example.com")
        .expect("overwritten entry should be fresh");
    assert_eq!(sol.cookies["cf_clearance"], "new-tok");
}

// ── Bug 4: Multi-domain isolation ─────────────────────────────────────
// Expiring domain A must not affect domain B.

#[test]
fn domain_isolation_on_expiry() {
    let cache = CookieCache::new(Duration::from_millis(20));
    cache.put("short.com", make_solution("short", "UA"));
    std::thread::sleep(Duration::from_millis(10));
    // Put B later — it has more TTL remaining
    cache.put("long.com", make_solution("long", "UA"));
    std::thread::sleep(Duration::from_millis(15));
    // short.com: 25ms elapsed > 20ms TTL → expired
    assert!(cache.get("short.com").is_none(), "short.com should be expired");
    // long.com: 15ms elapsed < 20ms TTL → still valid
    let sol = cache
        .get("long.com")
        .expect("long.com should still be valid");
    assert_eq!(sol.cookies["cf_clearance"], "long");
}

// ── Bug 5: Evict doesn't affect non-expired entries ───────────────────

#[test]
fn evict_preserves_fresh_entries() {
    let cache = CookieCache::new(Duration::from_millis(100));
    cache.put("fresh.com", make_solution("alive", "UA"));
    // Add and expire a different domain
    let short_cache_entry = CookieCache::new(Duration::from_millis(1));
    short_cache_entry.put("dead.com", make_solution("dead", "UA"));
    // Our main cache — put a short-lived one
    let cache = CookieCache::new(Duration::from_secs(60));
    cache.put("alive.com", make_solution("alive", "UA"));
    cache.evict_expired();
    assert_eq!(cache.len(), 1);
    assert!(cache.get("alive.com").is_some());
}

// ── Bug 6: Concurrent reads and writes ────────────────────────────────
// RwLock should handle concurrent access without panics or data corruption.

#[test]
fn concurrent_access_no_panic() {
    let cache = Arc::new(CookieCache::new(Duration::from_millis(10)));
    let mut handles = vec![];

    // 10 writer threads
    for i in 0..10 {
        let c = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            for j in 0..50 {
                c.put(
                    &format!("domain-{i}.com"),
                    make_solution(&format!("tok-{i}-{j}"), "UA"),
                );
            }
        }));
    }

    // 10 reader threads
    for i in 0..10 {
        let c = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                let _ = c.get(&format!("domain-{i}.com"));
            }
        }));
    }

    // 2 evictor threads
    for _ in 0..2 {
        let c = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            for _ in 0..20 {
                c.evict_expired();
                std::thread::sleep(Duration::from_millis(1));
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked during concurrent access");
    }
}

// ── Bug 7: Solver re-solves after cache TTL expires ───────────────────
// After TTL expires, the solver middleware must call the provider again,
// not silently fail or return stale cookies.

struct CountingProvider {
    call_count: Arc<AtomicUsize>,
    token_prefix: String,
}

#[async_trait]
impl CookieProvider for CountingProvider {
    async fn solve(
        &self,
        _url: &str,
        _ct: ChallengeType,
    ) -> std::result::Result<SolvedChallenge, String> {
        let n = self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(make_solution(
            &format!("{}-{n}", self.token_prefix),
            "SolverUA",
        ))
    }
}

/// Handler that returns 200 if cookies present, CF error if not.
struct CfUnlessCookieHandler;

#[async_trait]
impl Handler for CfUnlessCookieHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        if req.has_header("cookie") {
            let cookie = req.header("cookie").unwrap_or("").to_owned();
            Ok(HttpResponse {
                status: 200,
                url: req.url,
                headers: HeaderMap::new(),
                body: cookie,
            })
        } else {
            Err(HttpError::Cloudflare(
                ChallengeType::JsChallenge,
                503,
                "ray".into(),
            ))
        }
    }
}

#[tokio::test]
async fn solver_resolves_after_ttl_expires() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn CookieProvider> = Arc::new(CountingProvider {
        call_count: calls.clone(),
        token_prefix: "ttl".into(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_millis(20)));
    let base: Arc<dyn Handler> = Arc::new(CfUnlessCookieHandler);
    let handler = chain(vec![solver_middleware(provider, cache.clone())], base);

    // First request: solver called, cookies cached
    let resp = handler.handle(make_request("https://cf.com/a")).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("cf_clearance=ttl-0"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Second request within TTL: uses cache, no solve call
    let resp = handler.handle(make_request("https://cf.com/b")).await.unwrap();
    assert!(resp.body.contains("cf_clearance=ttl-0"), "should use cached token");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "should not re-solve within TTL");

    // Wait for TTL to expire
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Third request after TTL: cache miss, solver called again
    let resp = handler.handle(make_request("https://cf.com/c")).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("cf_clearance=ttl-1"), "should get fresh token");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "should re-solve after TTL");
}

// ── Bug 8: Different domains get independent solves ───────────────────

#[tokio::test]
async fn different_domains_solved_independently() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn CookieProvider> = Arc::new(CountingProvider {
        call_count: calls.clone(),
        token_prefix: "dom".into(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
    let base: Arc<dyn Handler> = Arc::new(CfUnlessCookieHandler);
    let handler = chain(vec![solver_middleware(provider, cache)], base);

    // Solve for domain A
    let resp = handler
        .handle(make_request("https://alpha.com/page"))
        .await
        .unwrap();
    assert!(resp.body.contains("cf_clearance=dom-0"));

    // Solve for domain B — must call provider again (different domain)
    let resp = handler
        .handle(make_request("https://beta.com/page"))
        .await
        .unwrap();
    assert!(resp.body.contains("cf_clearance=dom-1"));
    assert_eq!(calls.load(Ordering::SeqCst), 2, "each domain needs its own solve");

    // Domain A again — should use cache
    let resp = handler
        .handle(make_request("https://alpha.com/other"))
        .await
        .unwrap();
    assert!(resp.body.contains("cf_clearance=dom-0"), "should use cached A token");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "cache hit, no re-solve");
}

// ── Bug 9: Solver failure doesn't cache bad result ────────────────────

struct FailOnceProvider {
    call_count: Arc<AtomicUsize>,
}

#[async_trait]
impl CookieProvider for FailOnceProvider {
    async fn solve(
        &self,
        _url: &str,
        _ct: ChallengeType,
    ) -> std::result::Result<SolvedChallenge, String> {
        let n = self.call_count.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Err("solver temporarily unavailable".into())
        } else {
            Ok(make_solution("recovered-tok", "UA"))
        }
    }
}

#[tokio::test]
async fn solver_failure_not_cached() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn CookieProvider> = Arc::new(FailOnceProvider {
        call_count: calls.clone(),
    });
    let cache = Arc::new(CookieCache::new(Duration::from_secs(60)));
    let base: Arc<dyn Handler> = Arc::new(CfUnlessCookieHandler);
    let handler = chain(vec![solver_middleware(provider, cache.clone())], base);

    // First request: solver fails
    let err = handler
        .handle(make_request("https://fail.com/page"))
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains("solver failed"),
        "should propagate solver error"
    );
    // Cache must be empty — failed result not cached
    assert!(cache.get("fail.com").is_none(), "failed solve must not be cached");

    // Second request: solver succeeds
    let resp = handler
        .handle(make_request("https://fail.com/page"))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("cf_clearance=recovered-tok"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
