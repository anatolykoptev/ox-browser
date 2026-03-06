# Rust Libraries Research for ox-browser

**Date:** 2026-03-06
**Current stack:** wreq, dom_query, rswappalyzer, regex-based security scanner, rmcp, axum

---

## Tier 1: Embarrassing NOT to use

### 1. `content-security-policy` -- CSP Parser

| Field | Value |
|-------|-------|
| Crate | [content-security-policy](https://crates.io/crates/content-security-policy) 0.6.0 |
| Downloads | 323K |
| Repo | [rust-ammonia/rust-content-security-policy](https://github.com/rust-ammonia/rust-content-security-policy) |
| What | Full CSP Level 3 parser and validator per W3C spec |
| Replaces | Hand-rolled regex CSP parsing in `ox-security/src/csp/` |
| Integration | **Easy** -- parse CSP string, call `should_request_be_blocked()`, inspect directives programmatically |

**Why multiplicative:** ox-browser currently uses regex to parse CSP headers. This crate implements the actual W3C CSP Level 3 algorithms -- parsing, directive matching, request blocking decisions, nonce validation, hash matching. It handles edge cases (multiple policies, report-only vs enforce, fallback chains like `script-src` falling back to `default-src`) that regex fundamentally cannot. Same maintainer as ammonia (the HTML sanitizer), so quality is high. Replaces hundreds of lines of fragile regex with spec-compliant behavior.

---

### 2. `semver` -- Semantic Version Comparison

| Field | Value |
|-------|-------|
| Crate | [semver](https://crates.io/crates/semver) 1.0.27 |
| Downloads | 600M |
| Repo | [dtolnay/semver](https://github.com/dtolnay/semver) (dtolnay = Rust ecosystem legend) |
| What | Parse and compare semantic versions, version requirements |
| Replaces | Any hand-rolled version string comparison in vuln JS detection |
| Integration | **Easy** -- `Version::parse("1.2.3")`, compare with `VersionReq` |

**Why multiplicative:** ox-browser's security scanner detects vulnerable JavaScript libraries by matching version strings. Without proper semver parsing, version comparison is fragile (is "1.9.0" < "1.10.0"? regex says no). This crate handles pre-release versions, build metadata, range expressions (`>=1.2.0, <2.0.0`). 600M downloads -- it IS the Rust standard for version handling.

---

### 3. `ipnet` -- IP Network / CIDR Types

| Field | Value |
|-------|-------|
| Crate | [ipnet](https://crates.io/crates/ipnet) 2.12.0 |
| Downloads | 326M |
| Repo | [krisprice/ipnet](https://github.com/krisprice/ipnet) |
| What | IPv4/IPv6 network types, CIDR containment checks, iteration |
| Replaces | Regex-based private IP detection in security scanner |
| Integration | **Easy** -- `"10.0.0.0/8".parse::<Ipv4Net>()`, then `.contains(addr)` |

**Why multiplicative:** ox-browser's security scanner checks for private IP addresses leaked in headers/body (information disclosure). Currently this is done with regex patterns for 10.x.x.x, 192.168.x.x, etc. `ipnet` provides proper CIDR containment checks, handles IPv6 private ranges (fc00::/7, fe80::/10, ::1), and edge cases like 127.0.0.0/8 that regex misses. Builds on stdlib `IpAddr`, zero overhead.

---

### 4. `psl` -- Public Suffix List

| Field | Value |
|-------|-------|
| Crate | [psl](https://crates.io/crates/psl) 2.1.196 |
| Downloads | 22M |
| Repo | [addr-rs/psl](https://github.com/addr-rs/psl) |
| What | Mozilla Public Suffix List -- extract registrable domain from any hostname |
| Replaces | Manual domain comparison logic for cookie scoping, SRI same-origin |
| Integration | **Easy** -- `psl::domain("www.example.co.uk")` returns `example.co.uk` |

**Why multiplicative:** Cookie security analysis needs to know the registrable domain to validate cookie domain scoping (is `.co.uk` a valid cookie domain? No -- it's a public suffix). SRI same-origin checks need domain comparison. Without PSL, ox-browser cannot correctly determine that `github.io` is a public suffix (each `user.github.io` is a separate origin). The PSL is compiled into the binary -- no network requests, no file loading.

---

### 5. `lol_html` -- Streaming HTML Rewriter

| Field | Value |
|-------|-------|
| Crate | [lol_html](https://crates.io/crates/lol_html) 2.7.2 |
| Downloads | 2.7M |
| Repo | [cloudflare/lol-html](https://github.com/cloudflare/lol-html) |
| What | Streaming HTML parser/rewriter with CSS selector API. Powers Cloudflare Workers. |
| Adds | Streaming HTML analysis without loading full DOM into memory |
| Integration | **Medium** -- different paradigm from dom_query (streaming vs DOM tree) |

**Why multiplicative:** dom_query loads the entire document into memory and builds a tree. For ox-browser's analysis tasks (find all `<script>` tags, extract `<meta>` tags, check `<a>` hrefs), streaming is faster and uses constant memory. lol_html processes HTML as a stream with CSS selector handlers -- perfect for single-pass extraction of security/intelligence data. Does NOT replace dom_query (still needed for complex DOM traversal), but should be the primary analysis engine for large pages. Cloudflare uses this in production on billions of pages.

---

### 6. `oxc_parser` -- JavaScript/TypeScript AST Parser

| Field | Value |
|-------|-------|
| Crate | [oxc_parser](https://crates.io/crates/oxc_parser) (part of [oxc](https://crates.io/crates/oxc) 0.116.0) |
| Downloads | 655K (oxc umbrella) |
| Repo | [oxc-project/oxc](https://github.com/oxc-project/oxc) |
| What | Fastest JS/TS parser written in Rust. Full AST, error recovery, 3x faster than swc. |
| Replaces | Regex-based inline JS analysis for dangerous patterns |
| Integration | **Medium** -- parse inline `<script>` content to AST, walk for patterns |

**Why multiplicative:** ox-browser currently uses regex to detect dangerous JavaScript patterns (eval, innerHTML assignment, etc.). AST parsing catches patterns that regex cannot: `window["eval"](code)`, `Function("return this")()`, obfuscated property access. Also enables: detecting crypto miners, identifying framework versions from code patterns, finding API endpoints in fetch/XMLHttpRequest calls. oxc is the fastest JS parser in any language -- parsing jQuery takes ~1ms.

---

## Tier 2: Strong improvements

### 7. `ammonia` -- HTML Sanitization

| Field | Value |
|-------|-------|
| Crate | [ammonia](https://crates.io/crates/ammonia) 4.1.2 |
| Downloads | 9.8M |
| Repo | [rust-ammonia/ammonia](https://github.com/rust-ammonia/ammonia) |
| What | HTML sanitizer that strips dangerous tags/attributes (XSS prevention) |
| Adds | XSS pattern detection in scanned pages |
| Integration | **Easy** -- compare sanitized output vs original to detect XSS vectors |

**Use case:** Feed page HTML through ammonia, diff against original. Any content stripped = potential XSS vector. Can report: "page contains N unsanitized script injection points". Also useful for the MCP server's content extraction -- return sanitized HTML to AI agents.

---

### 8. `hickory-resolver` -- DNS-over-HTTPS

| Field | Value |
|-------|-------|
| Crate | [hickory-resolver](https://crates.io/crates/hickory-resolver) 0.25.2 |
| Downloads | 37M |
| Repo | [hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns) (formerly trust-dns) |
| What | Async DNS resolver with DoH, DoT, DNSSEC support |
| Adds | DNS intelligence: CNAME chains, MX records, DNSSEC validation, CAA records |
| Integration | **Medium** -- async resolver, configure DoH upstream |

**Use case:** Add DNS intelligence module: resolve target domain, check DNSSEC, query CAA records (certificate authority authorization), detect CDN via CNAME chains (e.g., `example.com CNAME d111111.cloudfront.net`), check for dangling DNS records. DoH prevents DNS snooping by network observers.

---

### 9. `texting_robots` -- robots.txt Parser

| Field | Value |
|-------|-------|
| Crate | [texting_robots](https://crates.io/crates/texting_robots) 0.2.2 |
| Downloads | 466K |
| Repo | [Smerity/texting_robots](https://github.com/Smerity/texting_robots) |
| What | RFC-compliant robots.txt parser with thorough testing |
| Adds | Crawler compliance, sitemap URL discovery from robots.txt |
| Integration | **Easy** -- parse robots.txt content, check `is_allowed(url)` |

**Why important for Phase 5 (crawler):** The crawler crate is currently empty. `texting_robots` is the clear winner for robots.txt parsing -- well-tested, handles crawl-delay, sitemap directives, wildcard patterns. Essential for polite crawling.

---

### 10. `spider` -- Web Crawler Framework

| Field | Value |
|-------|-------|
| Crate | [spider](https://crates.io/crates/spider) 2.46.0 |
| Downloads | 2M |
| Repo | [spider-rs/spider](https://github.com/spider-rs/spider) |
| What | Full-featured async web crawler: concurrent fetching, link extraction, robots.txt, sitemap |
| Adds | Complete crawler implementation for Phase 5 |
| Integration | **Hard** -- large dependency, may conflict with ox-browser's custom HTTP layer |

**Consideration:** spider is the dominant Rust crawler, but it brings its own HTTP client (reqwest-based). ox-browser uses wreq with custom TLS fingerprinting. Two options: (1) use spider for link extraction/queue logic but replace its HTTP client, (2) build crawler logic from scratch using `texting_robots` + custom queue. Option 2 is likely better given ox-browser's stealth requirements. Research spider's architecture for patterns, but don't depend on it directly.

---

### 11. `x509-parser` -- Certificate Analysis

| Field | Value |
|-------|-------|
| Crate | [x509-parser](https://crates.io/crates/x509-parser) 0.18.1 |
| Downloads | 89M |
| Repo | [rusticata/x509-parser](https://github.com/rusticata/x509-parser) |
| What | Parse X.509 v3 certificates, extract all fields |
| Adds | TLS certificate intelligence (issuer, validity, SANs, key size, signature algo) |
| Integration | **Medium** -- need to extract cert from TLS connection (wreq may expose this) |

**Use case:** After TLS handshake, parse the server certificate: check expiry, key size (flag RSA < 2048 bits), signature algorithm (flag SHA-1), Subject Alternative Names, certificate chain length, issuer (Let's Encrypt vs DigiCert vs self-signed). This is a common Observatory/Qualys SSL Labs feature that ox-browser currently lacks.

---

### 12. `sourcemap` -- JavaScript Source Map Parser

| Field | Value |
|-------|-------|
| Crate | [sourcemap](https://crates.io/crates/sourcemap) 9.3.2 |
| Downloads | 29M |
| Repo | [getsentry/rust-sourcemap](https://github.com/getsentry/rust-sourcemap) |
| What | Parse JavaScript source maps (V3 format). By Sentry. |
| Adds | Detect exposed source maps (security finding), map minified code back to original |
| Integration | **Easy** -- parse `.map` file content, check for source file paths |

**Use case:** Exposed source maps are a security finding (leak original source code, file paths, sometimes secrets in comments). ox-browser can: (1) detect `//# sourceMappingURL=` in JS files, (2) try to fetch the source map, (3) parse it to report what's exposed (file list, original source availability). Sentry maintains this crate -- production quality.

---

### 13. `whois-rust` -- WHOIS Lookup

| Field | Value |
|-------|-------|
| Crate | [whois-rust](https://crates.io/crates/whois-rust) 1.6.0 |
| Downloads | 868K |
| Repo | [magiclen/whois-rust](https://github.com/magiclen/whois-rust) |
| What | WHOIS client -- query domain registration info |
| Adds | Domain intelligence: registrar, creation date, expiry, name servers |
| Integration | **Easy** -- `WhoIs::lookup(domain)`, parse response |

**Use case:** Add domain intelligence: registration age (new domains = higher risk), registrar, expiry date, privacy protection status. Useful for phishing detection and trust scoring.

---

## Tier 3: Nice to have

### 14. `wasmparser` -- WebAssembly Analysis

| Field | Value |
|-------|-------|
| Crate | [wasmparser](https://crates.io/crates/wasmparser) 0.245.1 |
| Downloads | 79M |
| Repo | [bytecodealliance/wasm-tools](https://github.com/bytecodealliance/wasm-tools) |
| What | Parse WebAssembly binary format. By Bytecode Alliance. |
| Adds | Detect WASM usage, analyze imports (crypto mining detection) |
| Integration | **Medium** -- parse `.wasm` files found via intelligence module |

**Use case:** Detect WebAssembly on pages (increasingly used for crypto miners). Parse WASM binary to check imports -- crypto mining WASM typically imports memory and has specific function signatures. Also detect legitimate WASM usage (image processing, games) for tech fingerprinting.

---

### 15. `lonkero` -- Web Scanner (Competitor Reference)

| Field | Value |
|-------|-------|
| Crate | [lonkero](https://crates.io/crates/lonkero) 3.7.3 |
| Downloads | 420K |
| Repo | [bountyyfi/lonkero](https://github.com/bountyyfi/lonkero) |
| What | Modular web scanner for pentesting |
| License | Non-standard (check before any code reference) |

**Note:** This is a competitor, not a dependency. Worth studying its module architecture for ideas, but non-standard license means no code borrowing. It appeared in 2026-01 with 420K downloads in 2 months -- likely bot-inflated or bundled in a toolchain. Evaluate with caution.

---

### 16. `html5ever` -- Browser-Grade HTML Parser

| Field | Value |
|-------|-------|
| Crate | [html5ever](https://crates.io/crates/html5ever) 0.38.0 |
| Downloads | 46M |
| Repo | [servo/html5ever](https://github.com/servo/html5ever) |
| What | HTML5 spec-compliant parser from Mozilla's Servo project |
| Note | dom_query already uses html5ever internally. No need to add directly. |

---

### 17. `ct-logs` -- Certificate Transparency Logs

| Field | Value |
|-------|-------|
| Crate | [ct-logs](https://crates.io/crates/ct-logs) 0.9.0 |
| Downloads | 12M |
| Repo | [ctz/ct-logs](https://github.com/ctz/ct-logs) |
| What | Google's CT log list for SCT validation |
| Integration | **Hard** -- requires access to TLS handshake data from wreq |

**Use case:** Validate Signed Certificate Timestamps from TLS handshake. Lower priority since Chrome already rejects certs without SCTs. Unmaintained since 2021.

---

### 18. `sitemaps` -- Sitemap XML Parser

| Field | Value |
|-------|-------|
| Crate | [sitemaps](https://crates.io/crates/sitemaps) 0.2.0 |
| Downloads | 17K |
| Repo | [blackerby/sitemaps-rs](https://github.com/blackerby/sitemaps-rs) |
| What | Parse sitemap.xml and sitemap index files |
| Adds | URL discovery for crawler (Phase 5) |
| Integration | **Easy** -- parse XML, iterate URLs |

**Use case:** Crawler Phase 5 needs sitemap parsing for URL discovery. Parse `sitemap.xml`, handle sitemap indexes, extract URLs with lastmod/priority/changefreq.

---

## Summary: Priority Implementation Order

| Priority | Crate | Effort | Impact | Category |
|----------|-------|--------|--------|----------|
| **P0** | `content-security-policy` | Easy | Replaces fragile regex CSP parser | Security |
| **P0** | `semver` | Easy | Correct vuln JS version matching | Security |
| **P0** | `ipnet` | Easy | Proper private IP detection | Security |
| **P0** | `psl` | Easy | Cookie domain scoping, SRI origin | Security + Intel |
| **P1** | `lol_html` | Medium | Streaming HTML analysis, constant memory | Performance |
| **P1** | `oxc_parser` | Medium | JS AST analysis replaces regex patterns | Security + Intel |
| **P1** | `ammonia` | Easy | XSS detection capability | Security |
| **P1** | `sourcemap` | Easy | Exposed source map detection | Security |
| **P2** | `hickory-resolver` | Medium | DNS intelligence (DNSSEC, CAA, CNAME) | Intel |
| **P2** | `x509-parser` | Medium | Certificate analysis | Security |
| **P2** | `whois-rust` | Easy | Domain registration intelligence | Intel |
| **P3** | `texting_robots` | Easy | robots.txt for crawler | Crawler |
| **P3** | `sitemaps` | Easy | Sitemap parsing for crawler | Crawler |
| **P3** | `wasmparser` | Medium | WASM crypto miner detection | Security |

### Not recommended

| Crate | Reason |
|-------|--------|
| `spider` | Too heavy, conflicts with wreq stealth HTTP layer. Build crawler from scratch. |
| `html5ever` | Already used by dom_query internally. |
| `lonkero` | Competitor with non-standard license. Study architecture only. |
| `ct-logs` | Unmaintained since 2021, niche use case. |

### Missing in Rust ecosystem

| Capability | Status |
|------------|--------|
| Retire.js equivalent | No Rust crate exists. Use Retire.js JSON DB directly (MIT-licensed data file) with `semver` for matching. |
| HTTP/2 fingerprint analysis | No standalone crate. wreq handles fingerprinting at the client side. |
| Screenshot without Chrome | No pure-Rust solution. Would need headless Chrome/Firefox. Out of scope. |
| PDF generation from HTML | `printpdf` + `wkhtmltopdf` exist but not browser-grade. Out of scope. |
