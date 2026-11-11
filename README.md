# ox-browser

Self-hosted web data extraction in Rust. Turns arbitrary pages into clean, LLM-ready text, with a robots-aware crawler, SPA content recovery, and quality gates that catch a bad extraction instead of shipping it. Also does image search, reverse image search, media download and security scanning. Exposes both a REST API and an MCP server for AI agents.

## Features

- **Content extraction** — Readability-style scoring (text density, semantic-tag bonus, link-density penalty) with recovery passes for H1s, hero paragraphs, section headings and footer content. Noise filtering matches class *tokens*, not substrings.
- **LLM-ready output** — strips CSS class names, empty headings, alt-text noise and bare-number lines before the text reaches a model. Per-call body caps.
- **SPA recovery** — JSON data islands (Next.js, Contentful) plus a QuickJS sandbox (250 ms timeout, 64 MB cap, interrupt handler) that runs inline scripts to capture `window.__PRELOADED_STATE__` and Next.js flight data from shells that ship no server HTML.
- **Extraction quality gate** — a post-extraction check compares visible text in against visible text out, tripping only when the source is above an absolute floor *and* the extraction falls below a fraction of it. A page that yields its loading overlay instead of its content is reported, not returned as content.
- **Image search** — Bing, DuckDuckGo, Brave, Pexels, Openverse. Reciprocal Rank Fusion across engines.
- **Reverse image search** — Google Lens + Yandex. Stock photo detection.
- **Media download** — YouTube via InnerTube API, DASH audio+video merge via ffmpeg. Generic media extraction from HTML.
- **Web crawler** — BFS with robots.txt respect, per-domain rate limiting, crawl budget, dedup, configurable depth/concurrency.
- **Stealth HTTP** — wreq + BoringSSL TLS fingerprinting emulating real browsers (Chrome, Safari, Edge). SSRF-safe with redirect validation.
- **Cloudflare and anti-bot handling** — integrates [Byparr](https://github.com/V4NSF/Byparr) (Camoufox-based) and [GoBrowser](https://github.com/gospider007/gobrowser) solvers. Optional Chromium fallback for hard challenges.
- **Security scanning** — headers (CSP, HSTS, X-Frame-Options), cookies, CORS, SRI, supply chain, redirect chains, body content scan.
- **Site audit** — tech stack fingerprinting (Wappalyzer), SEO analysis, performance metrics, accessibility checks.
- **MCP server** — 13 tools for AI agents (Claude Desktop, Claude Code, any MCP client).
- **Proxy support** — Webshare pool with health tracking, residential proxy, per-domain rate limiting with wildcard matching.

## Architecture

```
ox-browser/
  crates/
    core/          # wreq+BoringSSL HTTP client, TLS fingerprinting
    http/          # Content extraction, LLM cleanup, SPA recovery, stealth client, SSRF middleware, solvers, metrics
    js/            # REST API routes (Axum)
    mcp/           # MCP server (rmcp, Streamable HTTP)
    security/      # Security scanning (headers, cookies, CORS, SRI, supply chain)
    intelligence/  # Site tech analysis (Wappalyzer, SEO, performance, accessibility)
    crawler/       # BFS web crawler with robots.txt + dedup
    imagesearch/   # Image search (Bing, DDG, Brave, Pexels, Openverse)
    reverse/       # Reverse image search (Google Lens, Yandex)
    media/         # Media download (YouTube InnerTube, generic), ffmpeg DASH merge
    twitter/       # Twitter/X x-client-transaction-id generator
```

## Quick start

### Docker

```bash
docker build -t ox-browser .
docker run -p 8901:8901 -e OX_MCP_TOKEN -e INTERNAL_SERVICE_SECRET ox-browser
```

The server rejects every request except `GET /health` unless a credential is configured; see
[Inbound authentication](#inbound-authentication). Each `-e NAME` above passes the variable through
from your shell.

### From source

```bash
cargo build --release
./target/release/ox-browser serve --config config.toml
```

The binary also has one-shot subcommands: `fetch <url>`, `read <url>`, `version` and `doctor`
(a live self-check of the fingerprint, configuration and solver reachability).

### Configuration

See [`config.toml`](config.toml) for all options. Secrets are passed via environment variables:

| Env var | Purpose |
|---------|---------|
| `BYPARR_URL` | Byparr solver URL (e.g. `http://localhost:8191`) |
| `GO_BROWSER_URL` | GoBrowser solver URL; also enables the Chrome-render escalation |
| `PROXY_URL` | HTTP/HTTPS proxy URL |
| `PROXY_DISABLED` | When set, every outbound proxy is disabled and fetches go direct |
| `OX_PORT` | Listen port; overrides `config.toml` |
| `OX_BROWSER_CONFIG` | Path of the config file (default `config.toml`) |
| `PEXELS_API_KEY`, `OPENVERSE_ACCESS_TOKEN` | Credentials for the Pexels and Openverse image-search engines |
| `OUTPUT_DIR` | Directory for downloaded media |
| `RESIDENTIAL_PROXY_URL` | Residential proxy for CF bypass |
| `WEBSHARE_API_KEY` | Webshare proxy pool API key |
| `MEDIA_PROXY_URL` | Proxy for media downloads |
| `OX_HTTP_PRIVATE_ALLOWLIST` | SSRF allowlist (e.g. `127.0.0.1:80,10.0.0.1:80`) |
| `OX_TOR_PROXY` | HTTP proxy in front of Tor for `.onion` targets, `http://host:port` (explicit port; the one place a private address is accepted). Unset → `.onion` is refused with `onion_requires_tor`; fleet value `http://tor-privoxy:8118`. See [Onion services](#onion-services-via-tor) |

### Inbound authentication

One middleware guards every route (REST, `/mcp`, `/metrics`); only `GET` and `HEAD` on `/health` are
exempt. A request is accepted with either credential:

| Credential | Sent as | Configured by |
|---|---|---|
| Internal service secret | `X-Internal-Secret` header | `INTERNAL_SERVICE_SECRET` |
| MCP token | `Authorization: Bearer <token>` | `OX_MCP_TOKEN` |

`OX_AUTH_MODE` is `enforce` (default; unknown values also enforce) or `soft`, a rollout aid that lets
a request with no credential through, counted and logged, while a wrong credential is still 401. With
neither credential configured every request except `/health` is refused; `OX_AUTH_ALLOW_INSECURE=true`
is the development opt-out. The internal secret is also what authorises the endpoints that relay to
a headless Chrome service, so keep both values out of logs and images.

### Onion services via Tor

`.onion` targets are never resolved locally (RFC 7686 §2) and are sent **only** through `OX_TOR_PROXY`: an HTTP proxy that forwards to Tor's SOCKS port with remote name resolution. In the fleet that is the `tor-privoxy` service (Privoxy `forward-socks5t / tor:9050 .`), so `OX_TOR_PROXY=http://tor-privoxy:8118`. It must speak forward-proxy HTTP as well as CONNECT: Tor's own `HTTPTunnelPort` is CONNECT-only and cannot carry `http://` onions.

- `OX_TOR_PROXY` unset -> refused up front as `onion_requires_tor` (before any DNS or socket activity).
- Both `http://` and `https://` onion targets work.
- A per-request `proxy`, the proxy pool and the direct fallback never apply to a Tor-bound request; a Tor failure is an error, not a reason to go direct.
- A redirect that crosses the onion boundary (onion to clearnet or back) is re-routed through normal routing, never followed in place.
- Onion URLs never reach a third party. `/fetch`, `/read` and the other endpoints that fetch through the shared client skip the CF solver, the residential retry, the challenge classifiers and `/read`'s Chrome fallback for them. The endpoints that would hand the caller's URL to a third party refuse an onion URL up front with `onion_requires_tor` (REST and MCP): `/solve` (`solve_cf`), `/chrome/interact` (`chrome_interact`, including URLs nested in actions), `/images/reverse` (`reverse_image_search`) and readability's headless-solver fallback. `/media/download` has no Tor path and refuses them too.
- Default call timeout for `.onion` is 60 s (circuit build) unless the caller sets `timeout`.
- Metrics: `oxbrowser_tor_requests_total`, `oxbrowser_onion_refused_total`.

### REST

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/read` | POST | Fetch + extract content (markdown/HTML/text) |
| `/readability` | POST | **DEPRECATED** — use `/read` instead |
| `/fetch` | POST | Raw HTTP fetch |
| `/fetch-smart` | POST | Fetch with automatic Chrome fallback for JS-rendered pages |
| `/solve` | POST | Solve Cloudflare challenge for URL |
| `/crawl` | POST | Crawl a site (BFS) |
| `/images/search` | POST | Multi-engine image search |
| `/images/reverse` | POST | Reverse image search |
| `/media/download` | POST | Download media (YouTube, generic) |
| `/security` | POST | Security scan |
| `/site-audit` | POST | Full site audit |
| `/analyze` | POST | Tech stack analysis |
| `/chrome/interact` | POST | Drive a headless Chrome session (relayed; needs the internal secret) |
| `/chrome/session/:id` | DELETE | Close a Chrome session |
| `/metrics` | GET | Prometheus metrics |

### MCP

```
claude mcp add -s user -t http ox-browser http://localhost:8901/mcp
```

Send the MCP token as `Authorization: Bearer <token>` (see
[Inbound authentication](#inbound-authentication)). 13 tools: `fetch`, `read`, `analyze`, `solve_cf`, `security_scan`, `crawl`, `chrome_interact`, `image_search`, `reverse_image_search`, `media_download`, `site_audit` (+ deprecated `fetch_smart`, `readability`).

## Build

```bash
make build      # cargo build --workspace
make test       # cargo nextest run (needs cargo-nextest) plus doctests
make lint       # cargo clippy --workspace --all-targets -- -D warnings
make check      # fmt + lint + test
make preflight  # the CI gate, see CONTRIBUTING.md
```

Rust 1.97 or newer, edition 2024. Every document is indexed in [docs/INDEX.md](docs/INDEX.md);
contributor notes are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Releasing

Releases are automated via [release-please](https://github.com/googleapis/release-please). Conventional commits (`feat:`, `fix:`, `perf:`, etc.) on `main` trigger a release PR that bumps the version and updates the changelog. **Merge the release PR to cut a release** — release-please creates the tag and GitHub Release, then `release.yml` builds and attaches the x86_64/aarch64 binaries.

**Never `git tag` by hand** — a manual tag desyncs `.release-please-manifest.json` from the actual released version and breaks the automated changelog baseline.

## License

[MIT](LICENSE)
