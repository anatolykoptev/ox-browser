# Competitor Passive Security Scanner Analysis

**Date:** 2026-03-06
**Purpose:** Identify gaps in ox-browser's security scanner vs. competitors, prioritize improvements.

## 1. Competitor Overview

### Mozilla Observatory (github.com/mozilla/http-observatory)

**Scoring**: Base 100, penalties/bonuses. Min 0, max 135. Bonuses only if score >= 90.

| Grade | Range | Grade | Range |
|-------|-------|-------|-------|
| A+    | 100+  | C+    | 60-64 |
| A     | 90-99 | C     | 50-59 |
| A-    | 85-89 | D+    | 40-44 |
| B+    | 80-84 | D     | 30-39 |
| B     | 70-79 | F     | 0-24  |

**10 test categories**, each with granular sub-results and score modifiers:

1. **Cookies** (range: +5 to -40) -- Secure, HttpOnly, SameSite flags. Anti-CSRF without SameSite (-20). Session cookies without Secure (-40). HSTS-protected mitigation (-5 vs -20).
2. **CORS** (range: 0 to -50) -- Checks `Access-Control-Allow-Origin`, also fetches `/crossdomain.xml` and `/clientaccesspolicy.xml` (Flash/Silverlight legacy). Universal access = -50.
3. **CSP** (range: +10 to -25) -- `default-src 'none'` bonus (+10). Unsafe-inline in style-src only = 0 (no penalty). Insecure scheme in passive content only = -10. Missing CSP = -25.
4. **HSTS** (range: +5 to -20) -- Preload bonus (+5). Checks against actual HSTS preload list. Max-age < 6 months = -10. Invalid cert chain detection.
5. **Redirection** (range: +5 to -20) -- HTTP-to-HTTPS redirect chain analysis. All redirects preloaded = bonus. Off-host initial redirect penalized. Checks that initial redirect stays on same host.
6. **Referrer-Policy** (range: +5 to -5) -- `no-referrer`/`same-origin` = bonus. `unsafe-url` = penalty.
7. **SRI** (range: +5 to -50) -- Parses HTML, checks all `<script>` and `<link>` tags for `integrity` attribute. Uses PublicSuffixList for same-origin detection. Distinguishes external vs same-SLD scripts.
8. **X-Content-Type-Options** (range: 0 to -10)
9. **X-Frame-Options** (range: 0 to -20) -- Checks for `DENY`/`SAMEORIGIN`, plus validates that CSP `frame-ancestors` is also present.
10. **X-XSS-Protection** (range: 0 to -10) -- Deprecated header, but checks for harmful settings.

**Key features ox-browser lacks:**
- Redirection chain analysis (HTTP->HTTPS, same-host check)
- HSTS preload list lookup (actual Chrome preload list check)
- `/crossdomain.xml` and `/clientaccesspolicy.xml` fetching
- Anti-CSRF token detection in cookies (naming heuristics: `csrf`, `xsrf`, `token`)
- HSTS-protected cookie mitigation scoring (reduced penalty if HSTS covers)
- `X-XSS-Protection` harmful configuration check (value `0` is actually safer than `1`)
- Referrer-Policy bonus scoring

---

### OWASP ZAP Passive Scanner

~60+ passive rules extracted from response data alone. Key rules ox-browser does NOT have:

| ZAP Rule ID | Check | ox-browser? |
|-------------|-------|-------------|
| 10009 | In-page banner info leak (server version in HTML body) | Partial (meta generator) |
| 10015 | Cache-Control directives review (sensitive data caching) | NO |
| 10017 | Cross-domain JS source file inclusion (JS from foreign domains) | Partial (supply chain) |
| 10023 | Debug error messages in response body | YES (stack traces) |
| 10024 | Sensitive information in URL (password, token, SSN in query) | Partial (session in URL) |
| 10025 | Sensitive info in HTTP Referrer header | NO |
| 10026 | HTTP Parameter Override (HPP) | NO |
| 10027 | Suspicious comments (TODO, FIXME, HACK, BUG, XXX) | YES |
| 10028 | Off-site redirect (open redirect detection) | NO |
| 10029 | Cookie poisoning (user-controllable cookie values) | NO |
| 10032 | ASP.NET Viewstate analysis (IPs, emails, missing MAC) | NO |
| 10033 | Directory browsing detection from response body | YES |
| 10034 | Heartbleed indicative (from server header version) | NO |
| 10039 | X-Backend-Server header leak | NO |
| 10041 | HTTP-to-HTTPS insecure transition in form POST | YES (insecure form action) |
| 10042 | HTTPS-to-HTTP insecure transition in form POST | NO (only one direction) |
| 10044 | Big redirect with sensitive data leak | NO |
| 10050 | Retrieved from cache (Age/X-Cache headers) | NO |
| 10054 | Cookie without SameSite | YES |
| 10055 | CSP wildcard directive | YES (broad sources) |
| 10056 | CSP script-src unsafe-inline | YES |
| 10057 | CSP style-src unsafe-inline | YES |
| 10058 | CSP wildcard in script-src | YES |
| 10061 | X-AspNet-Version header disclosure | NO |
| 10062 | Permissions-Policy (formerly Feature-Policy) | YES |
| 10063 | Permissions-Policy deprecated header | Partial |
| 10096 | Timestamp disclosure (Unix timestamps in headers/body) | NO |
| 10097 | Hash disclosure (MD5/SHA in response suggesting crypto use) | NO |
| 10098 | Cross-domain misconfiguration (CORS with credentials) | YES |
| 10109 | Modern web app (checks for JS frameworks in page) | Partial (vuln JS) |
| 10110 | Dangerous JS functions in inline scripts | NO |
| 10202 | Absence of anti-CSRF tokens in HTML forms | NO |
| 90004 | Insecure authentication (Basic auth over HTTP) | NO |
| 90033 | Loosely scoped cookie (domain too broad) | NO |

---

### SecurityHeaders.com (Scott Helme)

**Graded headers** (F to A+):

1. Content-Security-Policy
2. Strict-Transport-Security
3. X-Frame-Options
4. X-Content-Type-Options
5. Referrer-Policy
6. Permissions-Policy
7. Cross-Origin-Resource-Policy (CORP)
8. Cross-Origin-Embedder-Policy (COEP)
9. Cross-Origin-Opener-Policy (COOP)

**Also reports but doesn't grade:**
- X-XSS-Protection (deprecated warning)
- Server header (info leak warning)
- X-Powered-By (info leak warning)

**Gap vs ox-browser:** SecurityHeaders checks the same headers ox-browser already has. Our coverage here is strong. The main difference is their simpler grading (just presence/absence), while ox-browser does deeper analysis (CSP parsing, bypass detection).

---

### Qualys SSL Labs

Primarily TLS-focused (certificate, protocol, cipher analysis). **Passive checks extractable from headers only:**

| Check | Can do passively? | ox-browser? |
|-------|-------------------|-------------|
| HSTS presence + max-age adequacy | YES (header) | YES |
| HSTS preload status | YES (preload list) | NO |
| HSTS includeSubDomains | YES (header) | YES |
| Certificate Transparency (Expect-CT) | YES (header) | NO |
| TLS version from response | NO (need TLS handshake) | N/A |
| OCSP stapling | NO (TLS level) | N/A |
| Cipher suite | NO (TLS level) | N/A |

Most SSL Labs checks require TLS handshake inspection, not applicable to passive header scanning.

---

### Retire.js

**Three detection methods:**

1. **Filename-based** (`js-file-name.js`): Regex patterns on script URLs (e.g., `jquery-1.2.3.min.js`). ox-browser already does this.
2. **File content-based** (`js-file-content.js`): Regex patterns on actual JS file content, extracting version strings from comments, variable declarations, and function calls (e.g., `jQuery.fn.jquery = "1.2.3"`). ox-browser does NOT do this.
3. **Hash-based** (`hash.js`): SHA1 hashes of known vulnerable file content. Exact match. ox-browser does NOT do this.

**Vulnerability database** (`jsrepository.json`): Each library entry contains:
- `extractors.uri` -- regex patterns for URL matching
- `extractors.filecontent` -- regex patterns for content matching with capture groups for version
- `extractors.filename` -- regex patterns for filename matching
- `extractors.hashes` -- SHA1 hashes of specific vulnerable builds
- `vulnerabilities[]` -- CVE IDs, severity, affected version ranges (semver)

**Key gap:** ox-browser only matches library URLs. Retire.js also:
- Downloads and inspects JS file content for embedded version strings
- Matches SHA1 hashes of minified files
- Has a comprehensive, CVE-linked vulnerability database with 500+ entries

---

### Snyk / Detectify

**Snyk Website Scanner:**
- AI-powered code analysis (Snyk Code neural network)
- Dependency vulnerability database (most comprehensive, frequently updated)
- SPDX v3.20 support for detailed vulnerability classification
- Container image scanning for base image vulnerabilities
- Automated remediation suggestions (version upgrade paths)

**Detectify:**
- Crowdsourced vulnerability research (ethical hackers submit new checks)
- Regular updates against emerging threats
- Detailed remediation steps with risk levels

**Novel passive techniques from both:**
- Technology fingerprinting from response patterns (not just headers)
- JS bundle analysis for embedded dependency versions
- Source map detection and analysis
- API endpoint discovery from inline scripts

---

## 2. Gap Analysis Summary

### Checks competitors have that ox-browser LACKS

| Category | Check | Source | Difficulty |
|----------|-------|--------|------------|
| **Redirection** | HTTP->HTTPS redirect chain analysis | Observatory | Medium |
| **Redirection** | Initial redirect same-host validation | Observatory | Easy |
| **HSTS** | Preload list lookup (actual chromium list) | Observatory, SSL Labs | Medium |
| **Cookies** | Anti-CSRF token without SameSite detection | Observatory | Easy |
| **Cookies** | HSTS-mitigated scoring (reduced penalties) | Observatory | Easy |
| **Cookies** | Loosely scoped domain | ZAP | Easy |
| **CORS** | crossdomain.xml / clientaccesspolicy.xml | Observatory | Medium |
| **Cache** | Cache-Control for sensitive pages | ZAP | Easy |
| **Info Leak** | X-Backend-Server header | ZAP | Easy |
| **Info Leak** | Timestamp disclosure in headers/body | ZAP | Medium |
| **Info Leak** | Hash disclosure (MD5/SHA patterns) | ZAP | Easy |
| **Info Leak** | Sensitive info in Referrer header | ZAP | Easy |
| **Info Leak** | Heartbleed indicative from server version | ZAP | Easy |
| **Info Leak** | ASP.NET version header | ZAP | Easy |
| **Body** | Dangerous JS functions (dynamic code execution) | ZAP | Medium |
| **Body** | Anti-CSRF tokens absent in forms | ZAP | Medium |
| **Body** | HTTPS->HTTP form transition (reverse) | ZAP | Easy |
| **Body** | Open redirect detection | ZAP | Medium |
| **Body** | Basic auth over HTTP | ZAP | Easy |
| **JS Vuln** | File content version extraction | Retire.js | Hard |
| **JS Vuln** | SHA1 hash matching | Retire.js | Medium |
| **JS Vuln** | CVE-linked vulnerability database | Retire.js | Hard |
| **Headers** | Expect-CT (Certificate Transparency) | SSL Labs | Easy |
| **Headers** | X-XSS-Protection harmful config | Observatory | Easy |
| **Headers** | Referrer-Policy bonus scoring | Observatory | Easy |
| **Scoring** | Bonus-only-above-threshold model | Observatory | Easy |

---

## 3. Priority Recommendations (Top 10)

### Rank 1: Redirection Chain Analysis
**Impact: HIGH | Effort: MEDIUM**
Observatory's signature check. Verify HTTP->HTTPS redirect, same-host initial redirect, final destination HTTPS. Penalize missing redirects, off-host redirects, HTTP-only sites. This is a fundamental security signal that every scanner checks.

### Rank 2: HSTS Preload List Lookup
**Impact: HIGH | Effort: MEDIUM**
Download and embed the Chromium HSTS preload list (~150K entries). Award bonus for preloaded domains. This is a +5 bonus in Observatory and a core SSL Labs check. The list is publicly available as a JSON file.

### Rank 3: Cache-Control Audit for Sensitive Pages
**Impact: HIGH | Effort: EASY**
Check for `Cache-Control: no-store` or `no-cache, private` on pages that set cookies or contain forms. Flag `public` or missing Cache-Control on authenticated content. ZAP rule 10015.

### Rank 4: Retire.js Content-Based Detection
**Impact: HIGH | Effort: HARD**
Go beyond URL-pattern matching. When JS files are fetched (ox-browser already does HTTP requests), apply regex extractors from Retire.js's `jsrepository.json` to file content. Extract version strings from comments/variables. This catches minified/renamed files that URL matching misses.

### Rank 5: Anti-CSRF Token Detection
**Impact: MEDIUM | Effort: EASY**
Two checks: (a) Cookie names matching `csrf`/`xsrf`/`token` patterns without SameSite flag (Observatory). (b) HTML forms without hidden CSRF token fields (ZAP 10202). Both are purely passive.

### Rank 6: Dangerous JS Function Detection
**Impact: MEDIUM | Effort: MEDIUM**
Scan inline `<script>` blocks for dangerous patterns: dynamic code execution calls, direct DOM manipulation via innerHTML/outerHTML assignment, string-based timer calls. ZAP rule 10110. These indicate XSS-prone code patterns.

### Rank 7: Loosely Scoped Cookie Detection
**Impact: MEDIUM | Effort: EASY**
Flag cookies with `Domain=` set to a parent domain (e.g., `.example.com` on `app.example.com`). This exposes cookies to sibling subdomains. ZAP rule 90033.

### Rank 8: Additional Info Disclosure Headers
**Impact: LOW | Effort: EASY**
Add detection for: `X-Backend-Server`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Powered-By-Plesk`, `X-Turbo-Charged-By`, `X-Generator`, `Expect-CT`. Low effort, fills gaps vs. all competitors. Single-line checks each.

### Rank 9: Open Redirect Detection
**Impact: MEDIUM | Effort: MEDIUM**
Check `Location` header on 3xx responses for redirects to external domains. Flag when the redirect target comes from a query parameter (e.g., `?redirect=https://evil.com`). ZAP rule 10028.

### Rank 10: Basic Auth Over HTTP Detection
**Impact: MEDIUM | Effort: EASY**
Flag `WWW-Authenticate: Basic` on non-HTTPS responses. Credentials sent in cleartext. ZAP rule 90004. Simple header check.

---

## 4. Novel Ideas (Innovation Opportunities)

### 4.1 CSP Effectiveness Score (nobody does well)
All scanners check CSP _presence_ and obvious bypasses. None compute a **CSP effectiveness score** that considers:
- Percentage of directives covered (script-src, style-src, img-src, font-src, connect-src, frame-src, object-src, base-uri, form-action)
- Source granularity (specific domains vs. broad `https:`)
- Nonce/hash usage vs. allowlisting
- Report-URI / report-to configuration
- `upgrade-insecure-requests` presence

Ox-browser could score CSP on a 0-100 effectiveness scale, not just pass/fail.

### 4.2 Security Header Age Detection
Detect outdated security configurations by checking:
- `Expect-CT` present (deprecated since 2021, suggests stale config)
- `X-XSS-Protection: 1` present (deprecated, signals old setup)
- `Feature-Policy` instead of `Permissions-Policy` (renamed 2020)
- `Public-Key-Pins` present (removed from browsers 2018)
- CSP using `child-src` without `worker-src` (split in CSP3)

This tells users their security headers are maintained vs. abandoned.

### 4.3 Supply Chain Depth Analysis
Go beyond checking if SRI exists. Analyze:
- How many unique third-party domains load scripts
- CDN diversity risk (all scripts from one CDN = single point of failure)
- Known compromised CDN detection (beyond polyfill.io -- cdnjs incidents, unpkg risks)
- Script loading chain depth (script A loads script B loads script C)
- Inline script volume vs. external (indicates CSP feasibility)

### 4.4 Privacy Header Scoring (emerging area)
No scanner scores privacy-specific headers well:
- `Permissions-Policy` completeness (how many features restricted)
- `Referrer-Policy` strictness level
- DNT response (`Tk` header)
- `Clear-Site-Data` support
- Cookie `Partitioned` attribute (CHIPS, new in 2024)
- `Sec-Fetch-*` header validation

### 4.5 Composite Risk Indicators
Instead of individual checks, compute composite signals:
- **Attack Surface Score**: number of third-party domains + form actions + external resources
- **Maintenance Signal**: deprecated headers present + outdated library versions + missing modern headers
- **Defense-in-Depth Score**: how many independent security layers are active (CSP + SRI + CORS + HSTS + cookie flags)

---

## 5. Scoring Comparison

| Aspect | ox-browser | Observatory | SecurityHeaders.com |
|--------|-----------|-------------|---------------------|
| **Base score** | 100 | 100 | Not public (letter grade) |
| **Max score** | 135 | 135 | A+ |
| **Grading** | F to A+ | F to A+ | F to A+ (with R for redirect) |
| **Categories scored** | 9 (headers, CSP, cookies, CORS, SRI, supply chain, mixed content, info disclosure, vuln JS, body scan) | 10 (cookies, CORS, CSP, HSTS, redirection, referrer-policy, SRI, XCTO, XFO, X-XSS-Protection) | ~10 headers (presence/absence only) |
| **CSP depth** | Deep (parser + bypass detection + 10 bypass types) | Deep (parser + multi-policy intersection + scheme checks) | Shallow (presence only) |
| **Cookie depth** | Good (Secure, HttpOnly, SameSite, prefixes) | Excellent (+ anti-CSRF, HSTS mitigation, session detection) | None |
| **Body analysis** | Yes (IPs, stack traces, comments, dir listing, forms) | No body scanning | No |
| **JS vulnerability** | URL pattern matching | No | No |
| **Supply chain** | Yes (SRI + risky domains) | SRI only | No |
| **Bonus system** | Yes | Yes (only if >= 90) | Unknown |

### Scoring Alignment
ox-browser's scoring range and grade thresholds are already Observatory-compatible (both use 0-135 range, same letter grade boundaries). The main scoring differences:
- Observatory has more granular cookie scoring (9 levels vs. ox-browser's ~5)
- Observatory awards bonuses for HSTS preload (+5) and Referrer-Policy strictness (+5)
- Observatory penalizes redirection failures (-20), which ox-browser doesn't check
- Observatory checks `crossdomain.xml` for CORS (-50 penalty possible)

### Recommendation
Keep the Observatory-compatible scoring model. Add the missing penalty/bonus categories (redirection, HSTS preload, referrer-policy bonus) to reach full scoring parity. Our body scan, supply chain, and vuln JS checks are differentiators that Observatory lacks.

---

## 6. Source References

- Mozilla Observatory source: `github.com/mozilla/http-observatory` (scoring.md, grade.py, headers.py, content.py, misc.py)
- ZAP alert index: `zaproxy.org/docs/alerts/` (60+ passive rules cataloged)
- Retire.js: `github.com/retirejs/retire.js` (3 detection methods: URI, filecontent, hash)
- SecurityHeaders.com: 9 graded headers + deprecated warnings
- Qualys SSL Labs: primarily TLS-level, limited passive applicability
- Snyk/Detectify: AI-powered analysis, crowdsourced checks (not directly replicable)
