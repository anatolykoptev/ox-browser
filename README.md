# ox-browser

Self-hosted stealth HTTP client with Cloudflare bypass, image search, reverse image search, media download, and security scanning. Exposes both a REST API and an MCP server for AI agents.

## Features

- **Stealth HTTP** — wreq + BoringSSL TLS fingerprinting emulating real browsers (Chrome, Safari, Edge). SSRF-safe with redirect validation.
- **Cloudflare bypass** — integrates [Byparr](https://github.com/V4NSF/Byparr) (Camoufox-based) and [GoBrowser](https://github.com/gospider007/gobrowser) solvers. Optional Chromium fallback for hard challenges.
- **Image search** — Bing, DuckDuckGo, Brave, Pexels, Openverse. Reciprocal Rank Fusion across engines.
- **Reverse image search** — Google Lens + Yandex. Stock photo detection.
- **Media download** — YouTube via InnerTube API, DASH audio+video merge via ffmpeg. Generic media extraction from HTML.
- **Web crawler** — BFS with robots.txt respect, per-domain rate limiting, dedup, configurable depth/concurrency.
- **Security scanning** — headers (CSP, HSTS, X-Frame-Options), cookies, CORS, SRI, supply chain, redirect chains, body content scan.
- **Site audit** — tech stack fingerprinting (Wappalyzer), SEO analysis, performance metrics, accessibility checks.
- **MCP server** — 11 tools for AI agents (Claude Desktop, Claude Code, any MCP client).
- **Proxy support** — Webshare pool with health tracking, residential proxy, per-domain rate limiting with wildcard matching.

## Architecture

```
ox-browser/
  crates/
    core/          # wreq+BoringSSL HTTP client, TLS fingerprinting
    http/          # Stealth client, SSRF middleware, CF solvers, caches, metrics
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

11 tools: `fetch`, `read`, `analyze`, `solve_cf`, `security_scan`, `crawl`, `image_search`, `reverse_image_search`, `media_download`, `site_audit` (+ deprecated `fetch_smart`, `readability`).

## Build

```bash
make build    # cargo build --workspace
make test     # cargo test --workspace
make lint     # cargo clippy -- -D warnings
make check    # fmt + lint + test
```

## License

[MIT](LICENSE)
