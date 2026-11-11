# Documentation index

| Document | Description |
|---|---|
| [README](../README.md) | What ox-browser is, features, quick start, configuration, inbound auth, REST and MCP surface, releasing |
| [CLAUDE](../CLAUDE.md) | Notes for coding agents: crates, API, build and gate commands, invariants, gotchas |
| [CHANGELOG](../CHANGELOG.md) | Release history, written by release-please |
| [SECURITY](../SECURITY.md) | How to report a vulnerability privately |
| [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md) | Contributor Covenant Code of Conduct |
| [LICENSE](../LICENSE) | MIT licence |
| [ARCHITECTURE](ARCHITECTURE.md) | Early architecture sketch: crate layout and dependency graph (predates several crates) |
| [ROADMAP](ROADMAP.md) | Phase-by-phase roadmap from the core MVP onward, with completed items ticked |
| [plans/2026-03-04-v0.1.0-design](plans/2026-03-04-v0.1.0-design.md) | Design of the v0.1.0 core MVP: fetch, parse and extract without JavaScript |
| [plans/2026-03-04-v0.1.0-plan](plans/2026-03-04-v0.1.0-plan.md) | Task-by-task implementation plan for v0.1.0 |
| [plans/2026-03-05-phase2-cloudflare-bypass](plans/2026-03-05-phase2-cloudflare-bypass.md) | Phase 2 plan for handling Cloudflare challenges |
| [plans/2026-03-06-approach-b-cf-bypass-design](plans/2026-03-06-approach-b-cf-bypass-design.md) | Design of Cloudflare challenge detection, the /fetch endpoint and smart fallback |
| [plans/2026-03-06-approach-b-implementation](plans/2026-03-06-approach-b-implementation.md) | Implementation plan for challenge detection, /fetch and the smart fallback |
| [plans/2026-03-06-phase4-security-scanner-plan](plans/2026-03-06-phase4-security-scanner-plan.md) | Plan for the v0.4.0 security scanner |
| [plans/2026-03-06-phase45-deep-security-scanner-plan](plans/2026-03-06-phase45-deep-security-scanner-plan.md) | Plan for the deeper security scanner checks |
| [plans/2026-03-06-phase46-imagesearch-plan](plans/2026-03-06-phase46-imagesearch-plan.md) | Plan for the multi-engine image search |
| [plans/2026-03-06-phase5-imagesearch-design](plans/2026-03-06-phase5-imagesearch-design.md) | Design of the image search engine |
| [plans/2026-03-06-phase5-mcp-server-design](plans/2026-03-06-phase5-mcp-server-design.md) | Design of the MCP server |
| [plans/2026-03-06-phase5-mcp-server-plan](plans/2026-03-06-phase5-mcp-server-plan.md) | Implementation plan for the MCP server |
| [plans/2026-03-06-site-analyze-v2](plans/2026-03-06-site-analyze-v2.md) | Plan for the web-intelligence (tech stack, SEO, performance) analysis |
| [plans/2026-03-07-phase5-crawler-design](plans/2026-03-07-phase5-crawler-design.md) | Design of the breadth-first site crawler |
| [plans/2026-03-07-phase5-crawler-plan](plans/2026-03-07-phase5-crawler-plan.md) | Implementation plan for the site crawler |
| [plans/2026-03-08-output-denoising](plans/2026-03-08-output-denoising.md) | Plan for stripping noise from extracted text before it reaches a model |
| [plans/2026-03-08-sitemap-crawl-bugfix](plans/2026-03-08-sitemap-crawl-bugfix.md) | Plan for fixing sitemap-driven crawling bugs |
| [plans/2026-03-08-sitemap-crawl-design](plans/2026-03-08-sitemap-crawl-design.md) | Design of sitemap-driven crawling |
| [plans/2026-03-08-sitemap-crawl-plan](plans/2026-03-08-sitemap-crawl-plan.md) | Implementation plan for sitemap-driven crawling |
| [plans/2026-03-09-media-download-design](plans/2026-03-09-media-download-design.md) | Design of the unified media download endpoint |
| [plans/2026-03-09-media-download-plan](plans/2026-03-09-media-download-plan.md) | Implementation plan for the media download endpoint |
| [plans/2026-03-09-reverse-image-search-plan](plans/2026-03-09-reverse-image-search-plan.md) | Implementation plan for reverse image search |
| [plans/2026-03-09-site-audit-design](plans/2026-03-09-site-audit-design.md) | Design of the site_audit tool: SEO, performance, accessibility and security scores |
| [plans/2026-03-09-site-audit-plan](plans/2026-03-09-site-audit-plan.md) | Implementation plan for the site_audit tool |
| [plans/2026-03-09-youtube-innertube-plan](plans/2026-03-09-youtube-innertube-plan.md) | Plan to read YouTube through its Innertube API so downloads work from datacenter addresses |
| [plans/2026-03-16-reverse-search-v2-plan](plans/2026-03-16-reverse-search-v2-plan.md) | Quality upgrade plan for reverse image search: Lens, Yandex parsing, richer results |
| [research/2026-03-06-competitor-analysis](research/2026-03-06-competitor-analysis.md) | Gap analysis of competing passive security scanners |
| [research/2026-03-06-rust-libraries](research/2026-03-06-rust-libraries.md) | Survey of Rust libraries considered for the project |
| [CONTRIBUTING](../CONTRIBUTING.md) | Build, the CI gate, commit style and pull-request expectations |
