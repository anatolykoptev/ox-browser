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
- **MCP server** — 11 tools for AI agents (Claude Desktop, Claude Code, any MCP client).
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
docker run -p 8901:8901 ox-browser
```

### From source

```bash
cargo build --release
./target/release/ox-browser serve --config config.toml
```

### Configuration

See [`config.toml`](config.toml) for all options. Secrets are passed via environment variables:

| Env var | Purpose |
|---------|---------|
| `BYPARR_URL` | Byparr solver URL (e.g. `http://localhost:8191`) |
| `GOBROWSER_URL` | GoBrowser solver URL |
| `PROXY_URL` | HTTP/SOCKS proxy URL |
| `RESIDENTIAL_PROXY_URL` | Residential proxy for CF bypass |
| `WEBSHARE_API_KEY` | Webshare proxy pool API key |
| `MEDIA_PROXY_URL` | Proxy for media downloads |
| `OX_HTTP_PRIVATE_ALLOWLIST` | SSRF allowlist (e.g. `127.0.0.1:80,10.0.0.1:80`) |

## API

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
| `/metrics` | GET | Prometheus metrics |

### MCP

```
claude mcp add -s user -t http ox-browser http://localhost:8901/mcp
```

13 tools: `fetch`, `read`, `analyze`, `solve_cf`, `security_scan`, `crawl`, `chrome_interact`, `image_search`, `reverse_image_search`, `media_download`, `site_audit` (+ deprecated `fetch_smart`, `readability`).

## Build

```bash
make build    # cargo build --workspace
make test     # cargo test --workspace
make lint     # cargo clippy -- -D warnings
make check    # fmt + lint + test
```

## Releasing

Releases are automated via [release-please](https://github.com/googleapis/release-please). Conventional commits (`feat:`, `fix:`, `perf:`, etc.) on `main` trigger a release PR that bumps the version and updates the changelog. **Merge the release PR to cut a release** — release-please creates the tag and GitHub Release, then `release.yml` builds and attaches the x86_64/aarch64 binaries.

**Never `git tag` by hand** — a manual tag desyncs `.release-please-manifest.json` from the actual released version and breaks the automated changelog baseline.

## License

[MIT](LICENSE)
