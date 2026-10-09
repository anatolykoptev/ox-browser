//! End-to-end tests of the `.onion` routing (ox-browser#188).
//!
//! Every test drives the PRODUCTION chain (`HttpClient` → `build_middlewares`
//! → `WreqHandler` with its real wreq clients). The only substitutions are a
//! counting pre-resolve DNS lookup (`HttpClient::with_lookup`), local TCP
//! stubs standing in for Tor, and — in the leak tests — a mock terminal
//! handler under the real middleware stack.
//!
//! Each test names the single edit that must turn it RED; the mutation log is
//! in the PR description.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wreq::dns::{Addrs, Name, Resolve, Resolving};
use wreq::header::HeaderMap;

use crate::cloudflare::ChallengeType;
use crate::cookie_provider::{CookieProvider, SolvedChallenge};
use crate::middleware::{Handler, Request};
use crate::middleware_ssrf::LookupHost;
use crate::{CookieCache, HttpClient, HttpConfig, HttpError, HttpResponse, WreqHandler};

const TOR_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
const TOR_REFUSES: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

/// A TCP stub: counts accepted connections, records each connection's first
/// request line, and answers with a canned reply.
struct Stub {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    first_lines: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    async fn spawn(reply: &'static [u8]) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        let accepts = Arc::new(AtomicUsize::new(0));
        let first_lines = Arc::new(Mutex::new(Vec::new()));
        let (a, l) = (Arc::clone(&accepts), Arc::clone(&first_lines));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                a.fetch_add(1, Ordering::SeqCst);
                let l = Arc::clone(&l);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 512];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&buf);
                    let line = text.lines().next().unwrap_or("").to_owned();
                    l.lock().expect("lines lock").push(line);
                    let _ = sock.write_all(reply).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        Stub {
            addr,
            accepts,
            first_lines,
        }
    }

    fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn lines(&self) -> Vec<String> {
        self.first_lines.lock().expect("lines lock").clone()
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

/// Counting pre-resolve lookup that fails like an unresolvable name would.
fn counting_lookup() -> (LookupHost, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let lookup: LookupHost = Arc::new(move |_host: &str, _port: u16| {
        c.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("no dns in tests"))
    });
    (lookup, calls)
}

fn config(tor_proxy: Option<String>) -> HttpConfig {
    HttpConfig {
        timeout: Duration::from_secs(5),
        max_redirects: 0,
        quality_check: false,
        tor_proxy,
        ..HttpConfig::default()
    }
}

fn get(url: &str, proxy: Option<String>) -> Request {
    Request {
        method: "GET".into(),
        url: url.into(),
        headers: vec![("user-agent".into(), "tor-test".into())],
        body: None,
        proxy,
        authenticated: false,
    }
}

fn is_requires_tor(r: &Result<HttpResponse, HttpError>) -> bool {
    matches!(r, Err(HttpError::OnionRequiresTor))
}

/// `.onion` + OX_TOR_PROXY unset: refused, zero DNS lookups, zero sockets.
/// A per-request proxy pointing at a live stub is supplied so "zero sockets"
/// is observable: the stub must never be dialled.
///
/// RED when the `.onion` early branch in `validate_url_with`
/// (middleware_ssrf.rs, `if crate::tor::is_onion_host(host)`) is removed: the
/// name then reaches the counting lookup (`lookups` == 1).
#[tokio::test]
async fn onion_without_tor_is_refused_with_zero_dns_and_zero_sockets() {
    let decoy = Stub::spawn(TOR_REFUSES).await;
    for url in [
        "https://foo.onion/",
        "https://FOO.ONION./",
        "http://foo.onion/",
    ] {
        let (lookup, lookups) = counting_lookup();
        let client = HttpClient::with_lookup(config(None), lookup).expect("client");
        let res = client.execute(get(url, Some(decoy.proxy_url()))).await;
        assert!(
            is_requires_tor(&res),
            "{url}: expected onion_requires_tor, got {res:?}"
        );
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            0,
            "{url}: DNS lookups for an onion name"
        );
        assert_eq!(decoy.accepts(), 0, "{url}: a socket was opened");
    }
}

/// Positive control for the counter above: a clearnet name DOES reach the
/// lookup, so a count of 0 for `.onion` is a real absence.
#[tokio::test]
async fn clearnet_name_reaches_the_counting_lookup() {
    let (lookup, lookups) = counting_lookup();
    let _ = crate::middleware_ssrf::validate_url_with(
        "https://clearnet.example/",
        false,
        lookup.as_ref(),
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

/// `.onion` + OX_TOR_PROXY = CONNECT stub: the stub receives
/// `CONNECT <name>.onion:443`; zero local DNS lookups. Case and the trailing
/// dot (`FOO.ONION.`) behave the same.
///
/// RED when `validate_url_with` stops short-circuiting `.onion` (same edit as
/// above: lookups becomes 1) or when `execute_tor` stops using the tor client
/// (the stub sees no CONNECT).
#[tokio::test]
async fn onion_goes_through_the_tor_stub_with_connect_and_no_dns() {
    for (url, want) in [
        ("https://foo.onion/", "connect foo.onion:443 "),
        ("https://FOO.ONION./", "connect foo.onion"),
    ] {
        let tor = Stub::spawn(TOR_REFUSES).await;
        let (lookup, lookups) = counting_lookup();
        let client =
            HttpClient::with_lookup(config(Some(tor.proxy_url())), lookup).expect("client");
        let res = client.execute(get(url, None)).await;
        assert!(
            res.is_err(),
            "{url}: the stub refuses the tunnel, got {res:?}"
        );
        let lines = tor.lines();
        assert_eq!(
            lines.len(),
            1,
            "{url}: exactly one CONNECT expected, got {lines:?}"
        );
        assert!(
            lines[0].to_ascii_lowercase().starts_with(want),
            "{url}: stub saw {:?}, wanted a line starting {want:?}",
            lines[0]
        );
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            0,
            "{url}: local DNS lookup for an onion name"
        );
    }
}

/// The Tor proxy given as a HOSTNAME (`localhost`, the `tor` service in
/// production) resolves although the answer is loopback/private: the Tor
/// client's resolver admits its own proxy host. A 127.0.0.1 literal would skip
/// DNS and hide this.
///
/// RED when `build_tor_client` (client.rs) wires `SsrfGuardedResolver` instead
/// of `tor.resolver()`: the private answer is dropped and the stub never sees a
/// CONNECT.
#[tokio::test]
async fn tor_proxy_hostname_resolves_to_a_private_address() {
    let tor = Stub::spawn(TOR_REFUSES).await;
    let proxy = format!("http://localhost:{}", tor.addr.port());
    let (lookup, _) = counting_lookup();
    let client = HttpClient::with_lookup(config(Some(proxy)), lookup).expect("client");
    let res = client.execute(get("https://foo.onion/", None)).await;
    assert!(res.is_err());
    assert_eq!(tor.lines().len(), 1, "stub saw {:?}", tor.lines());
}

/// A caller-supplied per-request proxy cannot override Tor routing.
///
/// RED when `execute_tor` (handler_reqwest.rs) passes `skip_proxy = false`:
/// the per-request proxy is then vetted/attached instead of ignored, the
/// loopback decoy is refused, and the Tor stub gets nothing.
#[tokio::test]
async fn per_request_proxy_cannot_override_tor() {
    let tor = Stub::spawn(TOR_REFUSES).await;
    let decoy = Stub::spawn(TOR_REFUSES).await;
    let (lookup, _) = counting_lookup();
    let client = HttpClient::with_lookup(config(Some(tor.proxy_url())), lookup).expect("client");
    let _ = client
        .execute(get("https://foo.onion/", Some(decoy.proxy_url())))
        .await;
    assert_eq!(tor.lines().len(), 1, "tor stub saw {:?}", tor.lines());
    assert!(
        tor.lines()[0]
            .to_ascii_lowercase()
            .starts_with("connect foo.onion:443")
    );
    assert_eq!(decoy.accepts(), 0, "the per-request proxy was dialled");
}

/// `http://` onion: wreq sends a forward-proxy request (absolute-form request
/// line) to the proxy in front of Tor, which resolves the name itself. Zero
/// local DNS lookups, one request at the stub, and the stub's answer comes back.
///
/// RED when `validate_url_with`'s onion branch stops covering http (e.g.
/// `if is_onion_host(host) && scheme == "https"` in middleware_ssrf.rs): the
/// name then reaches the counting lookup (`lookups` == 1).
#[tokio::test]
async fn http_onion_reaches_the_tor_stub_as_a_forward_proxy_request() {
    for (url, want) in [
        ("http://foo.onion/", "get http://foo.onion/ http/1.1"),
        ("http://FOO.ONION./x", "get http://foo.onion./x http/1.1"),
    ] {
        let tor = Stub::spawn(TOR_OK).await;
        let (lookup, lookups) = counting_lookup();
        let client =
            HttpClient::with_lookup(config(Some(tor.proxy_url())), lookup).expect("client");
        let res = client.execute(get(url, None)).await;
        assert!(
            matches!(&res, Ok(r) if r.status == 200 && r.body == "ok"),
            "{url}: expected the stub's 200, got {res:?}"
        );
        let lines: Vec<String> = tor.lines().iter().map(|l| l.to_ascii_lowercase()).collect();
        assert_eq!(lines, vec![want.to_owned()], "{url}: stub request lines");
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            0,
            "{url}: local DNS lookup for an onion name"
        );
    }
}

/// wreq resolver that maps every name to one address (the "direct" listener).
#[derive(Clone)]
struct MapAll(SocketAddr);

impl Resolve for MapAll {
    fn resolve(&self, _name: Name) -> Resolving {
        let addr = self.0;
        Box::pin(async move { Ok(Box::new(vec![addr].into_iter()) as Addrs) })
    }
}

/// A failing Tor proxy is an error, and a "direct" listener (reachable through
/// the handler's direct-fallback sibling) receives nothing. Two shapes: an
/// `http://` onion whose Tor proxy is DEAD (connection refused — exactly what
/// `looks_like_proxy_dial_failure` treats as fallback-eligible for an http
/// target at `max_redirects == 0`), and an `https://` onion whose tunnel the
/// proxy refuses.
///
/// RED when the `if tor_bound { return primary; }` gate in `handle_hop`
/// (handler_reqwest.rs) is removed: the http case then falls back to the
/// direct sibling and `direct.accepts()` becomes 1.
#[tokio::test]
async fn tor_failure_never_falls_back_to_direct() {
    for scheme in ["http", "https"] {
        let direct = Stub::spawn(TOR_REFUSES).await;
        let tor = Stub::spawn(TOR_REFUSES).await;
        let tor_proxy = if scheme == "http" {
            // A port nobody listens on: the proxy dial itself fails.
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = l.local_addr().expect("addr").port();
            drop(l);
            format!("http://127.0.0.1:{port}")
        } else {
            tor.proxy_url()
        };
        let cfg = config(Some(tor_proxy));
        let tor_client = HttpClient::build_tor_client(&cfg, None)
            .expect("tor client")
            .expect("configured");
        let direct_client = wreq::Client::builder()
            .dns_resolver(MapAll(direct.addr))
            .timeout(Duration::from_secs(3))
            .no_proxy()
            .build()
            .expect("direct client");
        let base: Arc<dyn Handler> = Arc::new(
            WreqHandler::new(direct_client.clone(), false, 0, 1 << 20)
                .with_tor(tor_client)
                .with_direct_fallback(direct_client),
        );
        let client = HttpClient::with_chain(base, cfg);
        let url = format!("{scheme}://foo.onion:{}/", direct.addr.port());
        let res = client.execute(get(&url, None)).await;
        assert_eq!(
            direct.accepts(),
            0,
            "{scheme}: the Tor failure fell back to a direct connection"
        );
        assert!(
            res.is_err(),
            "{scheme}: a failing Tor proxy must be an error, got {res:?}"
        );
    }
}

// ── leak tests: the layers above the terminal handler ─────────────────────

struct CountingProvider(Arc<AtomicUsize>);

#[async_trait]
impl CookieProvider for CountingProvider {
    async fn solve(
        &self,
        _url: &str,
        _ct: ChallengeType,
        _authenticated: bool,
    ) -> Result<SolvedChallenge, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(SolvedChallenge {
            cookies: HashMap::new(),
            user_agent: String::new(),
            body: None,
        })
    }
}

/// Terminal mock: records every request, answers with a fixed result.
struct Recorder {
    seen: Mutex<Vec<Request>>,
    status: u16,
    cf_error: bool,
}

#[async_trait]
impl Handler for Recorder {
    async fn handle(&self, req: Request) -> crate::Result<HttpResponse> {
        let url = req.url.clone();
        self.seen.lock().expect("seen lock").push(req);
        if self.cf_error {
            return Err(HttpError::Cloudflare(
                ChallengeType::JsChallenge,
                503,
                "ray".into(),
            ));
        }
        Ok(HttpResponse {
            status: self.status,
            url,
            headers: HeaderMap::new(),
            body: "hidden service says no".into(),
        })
    }
}

fn leak_config() -> (HttpConfig, Arc<AtomicUsize>) {
    let solves = Arc::new(AtomicUsize::new(0));
    let cfg = HttpConfig {
        cloudflare_detect: true,
        quality_check: true,
        cookie_provider: Some(Arc::new(CountingProvider(Arc::clone(&solves)))),
        cookie_cache: Some(Arc::new(CookieCache::new(Duration::from_secs(60)))),
        residential_proxy: Some("http://203.0.113.9:8080".into()),
        tor_proxy: Some("http://127.0.0.1:9".into()),
        ..HttpConfig::default()
    };
    (cfg, solves)
}

/// A challenge-shaped error for an onion URL must not reach the solver
/// (Byparr/go-wowa would fetch the name outside Tor) or the residential
/// middleware (it would rewrite the proxy).
///
/// RED when the onion passthrough at the top of `SolverHandler::handle`
/// (middleware_solver.rs) or `ResidentialHandler::handle`
/// (middleware_residential.rs) is removed.
#[tokio::test]
async fn onion_challenge_error_never_reaches_solver_or_residential() {
    let (cfg, solves) = leak_config();
    let rec = Arc::new(Recorder {
        seen: Mutex::new(Vec::new()),
        status: 200,
        cf_error: true,
    });
    let client = HttpClient::with_chain(Arc::clone(&rec) as Arc<dyn Handler>, cfg);
    let res = client.execute(get("https://foo.onion/", None)).await;
    assert!(matches!(res, Err(HttpError::Cloudflare(..))), "got {res:?}");
    assert_eq!(
        solves.load(Ordering::SeqCst),
        0,
        "solver was handed an onion URL"
    );
    let seen = rec.seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 1, "the request was re-sent");
    assert_eq!(
        seen[0].proxy, None,
        "residential proxy was applied to an onion request"
    );
}

/// An onion 403 is the hidden service speaking, not an anti-bot challenge; the
/// clearnet twin IS classified, which proves the harness would catch it.
///
/// RED when the onion passthrough in `QualityHandler::handle`
/// (middleware_quality.rs) is removed.
#[tokio::test]
async fn onion_403_is_not_classified_as_a_challenge() {
    let (cfg, solves) = leak_config();
    let rec = Arc::new(Recorder {
        seen: Mutex::new(Vec::new()),
        status: 403,
        cf_error: false,
    });
    let client = HttpClient::with_chain(Arc::clone(&rec) as Arc<dyn Handler>, cfg);
    let onion = client.execute(get("https://foo.onion/", None)).await;
    assert!(
        matches!(&onion, Ok(r) if r.status == 403),
        "onion: {onion:?}"
    );
    assert_eq!(solves.load(Ordering::SeqCst), 0);
    let clearnet = client.execute(get("https://example.com/", None)).await;
    assert!(
        clearnet.is_err() || solves.load(Ordering::SeqCst) > 0,
        "control: a clearnet 403 must be classified (error or solve), got {clearnet:?}"
    );
}

// ── connect-time tier and redirect routing (pure seams) ───────────────────

/// The shared connect-time resolver refuses `.onion` WITHOUT calling the
/// lookup; a clearnet name does call it (positive control).
///
/// RED when the onion branch at the top of `resolve_guarded`
/// (ssrf_connect.rs) is removed: `calls` becomes 1 for the onion names.
#[tokio::test]
async fn connect_time_resolver_never_looks_up_onion() {
    let calls = Arc::new(AtomicUsize::new(0));
    let lookup = |_h: String| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(vec![SocketAddr::from(([93, 184, 216, 34], 0))]) }
    };
    for name in ["foo.onion", "FOO.ONION."] {
        assert!(
            crate::ssrf_connect::resolve_guarded(name, &lookup)
                .await
                .is_err(),
            "{name}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "onion name reached the lookup"
    );
    assert!(
        crate::ssrf_connect::resolve_guarded("example.com", &lookup)
            .await
            .is_ok()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "control: clearnet must look up"
    );
}

fn redirect_resp(status: u16, from: &str, location: &str) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert("location", location.parse().expect("location"));
    HttpResponse {
        status,
        url: from.into(),
        headers,
        body: String::new(),
    }
}

/// A redirect leaving `.onion` (and one entering it) is re-routed; one that
/// stays on its side is not touched (wreq follows those internally).
///
/// RED when the `crosses_onion_boundary` guard in `onion_boundary_redirect`
/// (handler_reqwest.rs) is removed.
#[test]
fn redirects_are_rerouted_only_across_the_onion_boundary() {
    use crate::handler_reqwest::onion_boundary_redirect as hop;
    let mut post = get("https://a.onion/form", None);
    post.method = "POST".into();
    post.body = Some(b"x=1".to_vec());
    post.headers.push(("cookie".into(), "s=1".into()));
    post.headers
        .push(("content-type".into(), "text/plain".into()));

    // onion -> clearnet, 302 on POST: becomes a bodiless GET, credentials dropped.
    let r = hop(
        &post,
        &redirect_resp(302, "https://a.onion/form", "https://example.com/x"),
    )
    .expect("reroute");
    assert_eq!(
        (r.method.as_str(), r.url.as_str(), r.body.is_none()),
        ("GET", "https://example.com/x", true)
    );
    assert!(
        r.headers
            .iter()
            .all(|(k, _)| !matches!(k.as_str(), "cookie" | "content-type"))
    );
    // 307 keeps method and body.
    let r = hop(
        &post,
        &redirect_resp(307, "https://a.onion/form", "https://example.com/x"),
    )
    .expect("reroute");
    assert_eq!(
        (r.method.as_str(), r.body.as_deref()),
        ("POST", Some(&b"x=1"[..]))
    );
    // clearnet -> onion is re-routed too (relative Location resolved against the hop).
    let clear = get("https://example.com/", None);
    let r = hop(
        &clear,
        &redirect_resp(301, "https://example.com/", "https://b.onion/"),
    )
    .expect("reroute");
    assert_eq!(r.url, "https://b.onion/");
    // Same side: left to wreq. Non-redirect status: ignored.
    assert!(hop(&post, &redirect_resp(302, "https://a.onion/form", "/other")).is_none());
    assert!(
        hop(
            &clear,
            &redirect_resp(302, "https://example.com/", "https://example.org/")
        )
        .is_none()
    );
    assert!(
        hop(
            &clear,
            &redirect_resp(200, "https://example.com/", "https://b.onion/")
        )
        .is_none()
    );
}
