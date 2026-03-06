# ox-browser: Approach B — CF Detection + /fetch + Smart Fallback

**Date:** 2026-03-06
**Status:** Approved

## Problem

1. `detect_cloudflare` only checks HTTP 403/503 — misses Turnstile/Managed Challenge at HTTP 200
2. No HTTP fetch endpoint — ox-browser only has `/solve` (headless) and CLI `fetch`
3. No two-stage strategy: TLS-first (fast) → headless-fallback (slow but reliable)
4. ox-browser not deployed as Docker service

## Design

### 1. Extend CF Detection (ox-http crate)

Add body/header markers for HTTP 200 challenges:

- **Header**: `cf-mitigated: challenge`
- **Body markers**: `_cf_chl_opt`, `window._cf_chl_opt`, `"Just a moment..."`, `cf-browser-verification`, `challenge-platform`
- **Meta refresh**: `<meta http-equiv="refresh"` with short delay to `/cdn-cgi/`

Update `detect_cloudflare()` in `crates/http/src/cloudflare.rs`:
- Current: only checks `status == 403 || status == 503`
- New: also check response headers + body content for 200 challenges

### 2. POST /fetch Endpoint (ox-js crate)

Add to existing Axum server (`crates/js/src/lib.rs`):

```
POST /fetch
{
  "url": "https://example.com",
  "headers": {"key": "value"},  // optional
  "timeout": 15,                // optional, seconds
  "proxy": "socks5://..."       // optional
}

Response:
{
  "status": 200,
  "headers": {...},
  "body": "<html>...",
  "cf_detected": false,
  "elapsed_ms": 150
}
```

Uses wreq+BoringSSL (Chrome TLS fingerprint), no headless browser. Fast path (~150ms vs ~5s for headless).

### 3. POST /fetch-smart Endpoint

Two-stage strategy:

1. Try `/fetch` (wreq, fast)
2. If `cf_detected` → automatically run headless solve → get cf_clearance cookie → retry wreq with cookie
3. Cache cf_clearance per domain (existing `cookie_cache.rs`, TTL 30min)

```
POST /fetch-smart
{
  "url": "https://example.com",
  "proxy": "socks5://...",      // optional
  "timeout": 30                 // optional
}

Response:
{
  "status": 200,
  "body": "<html>...",
  "method": "direct|solved",    // which path succeeded
  "cf_detected": true,
  "elapsed_ms": 5200
}
```

### 4. Docker Service

- Image: multi-stage Rust build (cargo-chef for caching)
- Port: 8901
- Service in docker-compose.yml: `ox-browser`
- Health check: `GET /health` (already exists)
- Env: `OX_BROWSER_PORT`, `OX_BROWSER_LOG_LEVEL`

### 5. go-engine Integration

New fallback in `fetch.Fetcher`:

```
proxy (go-stealth) → ox-browser /fetch-smart → Byparr (last resort)
```

- New option: `WithOxBrowser(baseURL string)`
- New method: `fetchViaOxBrowser(ctx, url) ([]byte, error)`
- Wired between proxy failure and Byparr fallback

## Fallback Chain

```
go-stealth proxy (TLS fingerprint, residential IP)
  ↓ fail
ox-browser /fetch-smart (wreq+BoringSSL, headless if CF detected)
  ↓ fail
Byparr (FlareSolverr, Camoufox, last resort)
```

## Out of Scope

- Behavioral emulation (mouse/keyboard/scroll)
- Canvas/WebGL fingerprint manipulation
- Per-customer ML bypass
- ox-mcp, ox-crawler, ox-security crates
