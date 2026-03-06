# Phase 5: MCP Server — Design Document

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expose ox-browser as a native MCP service for AI agents via Streamable HTTP.

**Architecture:** Mount `rmcp` MCP service alongside existing Axum REST API on the same port (8901).
Reuse existing handler logic from `ox-js` crate. Start with 4 tools mirroring REST endpoints,
expand as `ox-intelligence` and `ox-security` modules are built.

**Tech Stack:** `rmcp` v1.1.0 (official Rust MCP SDK), Axum 0.8, tokio, serde

## Research Summary

### SDK Choice: `rmcp` v1.1.0 (official)

- 3.1k stars, Anthropic-maintained, conformance tests against JS/Python SDK
- Proc-macro tool registration: `#[tool]` + `#[tool_router]` + `#[tool_handler]`
- Streamable HTTP via Axum Tower service: `.nest("/mcp", mcp_service)`
- Feature flags: `server`, `transport-streamable-http-server`
- Spec compliance: 2025-11-25 (latest), includes Elicitation, OAuth 2.1, Tasks

### Competitive Landscape

Browser MCP servers (Chrome DevTools 29 tools, Playwright 35+ tools) all require a real browser.
ox-browser occupies a unique niche: **web intelligence + stealth extraction** without browser overhead.
No existing MCP server offers tech detection, SEO audit, or CF bypass.

### Key Patterns Adopted

1. **Slim tool set** — 4 tools now, expand later (Chrome DevTools slim=3 tools for token efficiency)
2. **Modular files** — one file per tool group (Playwright pattern)
3. **Streamable HTTP stateless** — no session state, Kubernetes-friendly
4. **Capability-based expansion** — future tools gated by available modules

## Architecture

```
ox-browser serve --port 8901
  ├── GET  /health              (existing — liveness probe)
  ├── POST /solve               (existing — CF challenge solver)
  ├── POST /fetch               (existing — stealth fetch)
  ├── POST /fetch-smart         (existing — three-tier fetch chain)
  ├── POST /analyze             (existing — tech stack detection)
  └── POST /mcp                 (NEW — rmcp Streamable HTTP)
  └── GET  /mcp                 (NEW — rmcp Streamable HTTP)
        ├── tool: fetch           — stealth HTTP fetch with proxy + BoringSSL
        ├── tool: fetch_smart     — three-tier chain: proxy → ox-browser → Byparr
        ├── tool: analyze         — tech stack detection from HTML + headers
        └── tool: solve_cf        — Cloudflare challenge solver → cookies
```

REST API stays unchanged — 100% backward compatible. MCP mounts alongside via Axum `.merge()`.

## Crate Structure

```
crates/mcp/
├── Cargo.toml
└── src/
    ├── lib.rs              — build_mcp_router(state) → Router, server info
    ├── state.rs            — McpState wrapping AppState for tool access
    └── tools/
        ├── mod.rs          — tool router impl block
        ├── fetch.rs        — fetch tool handler
        ├── fetch_smart.rs  — fetch_smart tool handler
        ├── analyze.rs      — analyze tool handler
        └── solve.rs        — solve_cf tool handler
```

## Tool Specifications

### `fetch`

Stealth HTTP fetch with proxy rotation and Chrome TLS fingerprint.

**Input:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| url | string | yes | — | URL to fetch |
| headers | object | no | {} | Custom request headers |
| timeout | integer | no | 15 | Request timeout in seconds |

**Output:** status, headers, body, cf_detected, cf_type?, elapsed_ms, error?

### `fetch_smart`

Three-tier fetch chain with automatic CF bypass escalation.

**Input:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| url | string | yes | — | URL to fetch |
| timeout | integer | no | 30 | Request timeout in seconds |

**Output:** status, body, method (direct/solved), cf_detected, elapsed_ms, error?

### `analyze`

Detect website technology stack from HTML and response headers.

**Input:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| url | string | yes | — | URL to analyze |

**Output:** url, status, technologies[], meta{generator,server,powered_by,title}, assets{scripts[],stylesheets[]}, method, cf_detected, elapsed_ms, error?

### `solve_cf`

Solve Cloudflare challenge and return clearance cookies.

**Input:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| url | string | yes | — | URL behind Cloudflare |
| challenge_type | string | yes | — | js_challenge, managed_challenge, turnstile, managed_challenge_200 |

**Output:** status (ok/error), cookies?, user_agent?, error?

## Integration Points

### serve.rs Changes

```rust
// Current:
let app = ox_js::router(state);

// New:
let rest_router = ox_js::router(state.clone());
let mcp_router = ox_mcp::build_mcp_router(state);
let app = rest_router.merge(mcp_router);
```

### Cargo.toml Changes

```toml
# Workspace members — add ox-mcp
members = ["crates/core", "crates/http", "crates/js", "crates/security", "crates/crawler", "crates/mcp"]

# Root binary dependencies — add ox-mcp
ox-mcp = { path = "crates/mcp" }

# New dependency
rmcp = { version = "1.1", features = ["server", "transport-streamable-http-server"] }
```

### Docker / Deploy

No changes needed — same port 8901, same container. MCP endpoint automatically available.

Registration:
```bash
claude mcp add -s user -t http ox-browser http://127.0.0.1:8901/mcp
```

## Testing Strategy

1. Unit tests: each tool handler with mock AppState
2. Integration test: start server, call MCP endpoint with JSON-RPC
3. Smoke test: `claude mcp add` + invoke tool from Claude Code

## Future Expansion

Tools added as modules become available (no breaking changes):

| Tool | Module | Phase |
|------|--------|-------|
| seo_audit | ox-intelligence/seo.rs | 2.5b |
| performance_audit | ox-intelligence/performance.rs | 2.5c |
| accessibility_audit | ox-intelligence/accessibility.rs | 2.5d |
| site_intelligence | ox-intelligence (all) | 2.5g |
| security_scan | ox-security | 3 |

## Non-Goals

- stdio transport (ox-browser is a daemon, not a subprocess)
- click/fill/screenshot (no real browser)
- slim/full mode toggle (4 tools is already slim)
- OAuth/auth (internal service, not exposed to internet)

## Depends On

- Phase 2 (v0.2.0) — completed
- `rmcp` v1.1.0 crate available on crates.io — confirmed
