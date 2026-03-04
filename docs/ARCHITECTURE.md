# ox-browser Architecture

## Problem

Existing Rust headless browser options fall into two categories:

1. **Chrome wrappers** (`headless_chrome`, `chromiumoxide`) — require 200MB+ Chromium binary
2. **From-scratch attempts** (kalamari) — 16K LOC, Grade D quality, 60% dead code, incomplete CSS selectors

Neither provides a lightweight, self-contained browser suitable for security scanning,
web scraping, and headless automation without external binary dependencies.

## Solution

Build on battle-tested Servo-ecosystem crates (html5ever, selectors) via `dom_query`,
add JS execution through Boa (pure Rust) with optional QuickJS, and wrap in
a clean workspace architecture with MCP server interface.

## Crate Dependency Graph

```
                    ┌─────────┐
                    │   mcp   │  MCP server (port 8901)
                    └────┬────┘
                         │
                    ┌────┴────┐
              ┌─────┤   cli   ├─────┐
              │     └────┬────┘     │
              │          │          │
         ┌────┴───┐ ┌────┴───┐ ┌───┴─────┐
         │crawler │ │security│ │         │
         └────┬───┘ └────┬───┘ │         │
              │          │     │         │
              └─────┬────┘     │         │
                    │          │         │
               ┌────┴────┐    │         │
               │  core   │────┘         │
               └──┬───┬──┘              │
                  │   │                 │
            ┌─────┘   └──────┐          │
            │                │          │
       ┌────┴───┐       ┌───┴───┐      │
       │  http  │       │  js   │──────┘
       └────────┘       └───────┘

External crates:
  core     → dom_query (html5ever + selectors)
  http     → reqwest, cookie_store
  js       → boa_engine (default), rquickjs (feature "quickjs")
```

## Core Interfaces

```rust
/// Browser manages HTTP client, JS engine, and page pool.
pub trait BrowserEngine: Send + Sync {
    fn render(&self, ctx: Context, url: &str) -> Result<Page>;
    fn available(&self) -> bool;
    fn close(&mut self) -> Result<()>;
}

/// Page represents a loaded document with mutable DOM.
pub struct Page {
    pub url: String,
    pub status: u16,
    pub title: String,
    dom: dom_query::Document,    // mutable DOM tree
    session: Session,            // cookies + auth
}

/// JsEngine abstracts JavaScript execution backends.
pub trait JsEngine: Send + Sync {
    fn execute(&mut self, code: &str) -> Result<JsValue>;
    fn bind_dom(&mut self, dom: &dom_query::Document) -> Result<()>;
    fn clear(&mut self);
}

/// Sentinel errors.
pub enum BrowserError {
    Navigate(String),     // DNS, TLS, HTTP failure
    Timeout,              // render exceeded deadline
    Selector(String),     // invalid CSS selector
    Script(String),       // JS execution error
}
```

## Crate Structure

```
ox-browser/
├── Cargo.toml                      # workspace definition
├── crates/
│   ├── core/                       # Browser + Page + DOM + Session + Pool
│   ├── js/                         # JsEngine trait + Boa + QuickJS backends
│   ├── http/                       # reqwest wrapper + proxy + cookies
│   ├── security/                   # XSS, CSP, SRI, headers (standalone)
│   ├── crawler/                    # Queue, dedup, robots.txt, rate limit
│   └── mcp/                       # MCP server (HTTP+SSE transport)
├── src/
│   └── main.rs                     # CLI: fetch, scan, crawl subcommands
└── docs/
    ├── ARCHITECTURE.md
    ├── ROADMAP.md
    └── plans/
```

## DOM Layer

`dom_query` provides mutable DOM over html5ever + selectors:

```rust
use dom_query::Document;

let doc = Document::from("<html><body><h1>Hello</h1></body></html>");

// CSS selector queries
let h1 = doc.select("h1");
assert_eq!(h1.text(), "Hello");

// Mutable operations
let mut node = doc.select_single("h1").unwrap();
node.set_attr("class", "title");
node.set_html("<span>World</span>");
```

Key advantage over scraper: full mutation support (add, remove, rename, move elements).

## JS Integration

Two backends behind `JsEngine` trait:

| Backend | Crate | Binary size | ES conformance | Use case |
|---------|-------|-------------|---------------|----------|
| Boa (default) | `boa_engine` 0.21 | ~5MB | ES2023 94% | General pages, security scanning |
| QuickJS (opt-in) | `rquickjs` 0.10 | ~1.3MB | ES2020 ~100% | Lightweight, fast startup |

DOM bindings expose `document`, `window`, `element` objects to JS via Boa's `boa_class` macro.
This maps JS DOM calls to `dom_query` operations (e.g. `document.querySelector()` calls
`dom_query::Document::select_single()`).

## Concurrency Model

```
Pool (channel-based semaphore)
├── Acquire(ctx) → release fn or error
├── Context cancellation supported
├── Default: 3 concurrent pages
└── Graceful shutdown on close
```

Same pattern as go-browser's `pool.go` — proven in production.

## HTTP Layer

- `reqwest` with async runtime (tokio)
- `cookie_store` for persistent cookie jar
- Proxy support (Webshare via env vars, same as go-stealth pattern)
- Request/response interceptor trait for logging, modification

## Configuration

| Env Var | Default | Purpose |
|---------|---------|---------|
| `OX_BROWSER_PORT` | `8901` | MCP server port |
| `OX_BROWSER_CONCURRENCY` | `3` | Max concurrent pages |
| `OX_BROWSER_TIMEOUT` | `20s` | Page load timeout |
| `OX_BROWSER_JS` | `boa` | JS engine: `boa`, `quickjs`, `none` |
| `OX_BROWSER_USER_AGENT` | ox-browser/0.1 | Custom User-Agent |
| `WEBSHARE_API_KEY` | — | Proxy authentication |

## Testing Strategy

- Unit tests per crate (target 30%+ coverage)
- Integration tests in `tests/` with real HTML fixtures
- `dom_query` + Boa tested together via DOM binding tests
- No external services needed for unit tests (mock HTTP responses)
- `cargo test --workspace` runs everything
