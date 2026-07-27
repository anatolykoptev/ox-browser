# ox-browser — Stealth HTTP Client + CF Bypass

**Port**: 8901 | **Rust** 1.97 edition 2024

## Crates

| Crate | Role |
|-------|------|
| root (`src/main.rs`) | Axum server, route wiring |
| `crates/core` | wreq+BoringSSL HTTP client, TLS fingerprinting |
| `crates/http` | SSRF middleware, request validation, CF solvers, caches, metrics |
| `crates/js` | REST API routes |
| `crates/mcp` | MCP server (rmcp, Streamable HTTP) |
| `crates/security` | Security scanning |
| `crates/intelligence` | Site tech analysis |
| `crates/crawler` | BFS web crawler |
| `crates/imagesearch` | Image search (Bing, DDG, Openverse, Pexels, Brave) |
| `crates/reverse` | Reverse image search (Google Lens, Yandex) |
| `crates/media` | Media download (YouTube, generic), DASH merge via ffmpeg |

## API

**REST**: `/health`, `/solve`, `/fetch`, `/fetch-smart`, `/read`, `/readability`, `/analyze`, `/security`, `/crawl`, `/images/search`, `/images/reverse`, `/media/download`, `/site-audit`

**MCP**: `/mcp` — 11 tools: fetch, fetch_smart (deprecated→use read), **read**, analyze, solve_cf, security_scan, readability (deprecated→use read), crawl, image_search, reverse_image_search, media_download, site_audit

## Build

```bash
make build    # cargo build --workspace
make test     # cargo test --workspace
make lint     # cargo clippy -- -D warnings
make check    # fmt + lint + test
```

## Gotchas

- Cookie cache is in-memory — restarts clear CF sessions
- `/media/download` writes to `/tmp/ox-browser/media/` (tmpfs in Docker)
- MCP registration: `claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp`
- Docker build uses cargo-chef — `--no-cache` recompiles ALL deps. Omit it for code-only changes
- Chromium solver: `chromium_enabled=true` in config.toml, needs `shm_size:256m` and no `cap_drop:ALL` in compose
