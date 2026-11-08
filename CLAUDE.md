# ox-browser — Stealth HTTP Client + CF Bypass

**Port**: 8901 | **Rust** 1.97 edition 2024

Every document is indexed in [docs/INDEX.md](docs/INDEX.md).

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

**MCP**: `/mcp` — 13 tools: fetch, fetch_smart (deprecated→use read), **read**, analyze, solve_cf, security_scan, readability (deprecated→use read), crawl, image_search, reverse_image_search, media_download, site_audit, chrome_interact

## Build

```bash
make build    # cargo build --workspace
make test     # cargo nextest run --workspace, then doctests
make lint     # cargo clippy -- -D warnings
make check    # fmt + lint + test
make preflight  # the CI gate (see below)
```

## Gate

CI (`.github/workflows/ci.yml`, job `preflight`, Rust 1.97, `ubuntu-24.04-arm`) runs `make preflight`:
the Cargo.lock version backstop (`lock-version-check`), `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --locked --all-targets
--workspace`, doctests, and clippy on `ox-http` with `--features fingerprint`. A pull request that
changes only documents (Markdown, `docs/`, licence, issue and PR templates) skips the job through the
`docs-scope` block in `ci.yml`; that block is canonical across the fleet and compared byte for byte,
so do not edit it here. `fingerprint-oracle.yml` is a scheduled live self-check and never gates a
merge.

## Invariants that are easy to break

- **Inbound auth is fail-closed.** One middleware (`crates/js/src/inbound_auth.rs`) wraps every
  route, `/mcp` and `/metrics` included; only `GET`/`HEAD /health` is exempt. The internal secret it
  accepts is also forwarded to the Chrome service, so a new route must stay behind the middleware and
  nothing may print either credential.
- **Onion targets never leave through clearnet.** `.onion` goes only through `OX_TOR_PROXY`, is
  never resolved locally, and endpoints that would hand the URL to a third party refuse it. Keep
  that when adding an endpoint or a fallback.
- **SSRF checks apply to every outbound fetch**, redirects included. Do not build a client that
  skips the validation middleware.
- **Versions come from release-please** (Conventional Commits, `release-type: simple`). Never
  `git tag` by hand, and keep `Cargo.lock`'s `ox-browser` version equal to the workspace version
  (`make lock-version-check`).
- **The TLS profile is measured, not claimed.** `crates/http/tests/fixtures/reference_chrome_*.json`
  are captures of real browsers that the offline fingerprint tests compare against; refresh them from
  a real browser, never by editing them to match the code.
- **This repository is public.** No hostnames, operator paths, account names, tokens or personal
  data in any tracked file, fixtures and plans included.

## Gotchas

- Cookie cache is in-memory — restarts clear CF sessions
- `/media/download` writes to `/tmp/ox-browser/media/` (tmpfs in Docker)
- MCP registration: `claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp`
- Docker build uses cargo-chef — `--no-cache` recompiles ALL deps. Omit it for code-only changes
- Chromium solver: `chromium_enabled=true` in config.toml, needs `shm_size:256m` and no `cap_drop:ALL` in compose
