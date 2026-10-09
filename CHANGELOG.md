# Changelog

## [0.8.19](https://github.com/anatolykoptev/ox-browser/compare/v0.8.18...v0.8.19) (2026-10-09)


### Added

* **fetch:** reach .onion services through a Tor HTTP tunnel ([#188](https://github.com/anatolykoptev/ox-browser/issues/188)) ([#191](https://github.com/anatolykoptev/ox-browser/issues/191)) ([344fb94](https://github.com/anatolykoptev/ox-browser/commit/344fb9414f4fd755c668e86be2a7e3b846085b14))

## [0.8.18](https://github.com/anatolykoptev/ox-browser/compare/v0.8.17...v0.8.18) (2026-10-08)


### Fixed

* **proxy:** refuse SOCKS proxy schemes wreq is not built to dial ([#179](https://github.com/anatolykoptev/ox-browser/issues/179)) ([#187](https://github.com/anatolykoptev/ox-browser/issues/187)) ([1a2ab43](https://github.com/anatolykoptev/ox-browser/commit/1a2ab4332b0d39850ff1b4d63507025d0fb5cf20))

## [0.8.17](https://github.com/anatolykoptev/ox-browser/compare/v0.8.16...v0.8.17) (2026-10-08)


### Fixed

* **doctor:** probe proxies through the canonical builder and redact credentials ([#178](https://github.com/anatolykoptev/ox-browser/issues/178)) ([#184](https://github.com/anatolykoptev/ox-browser/issues/184)) ([15ed677](https://github.com/anatolykoptev/ox-browser/commit/15ed677b9586a6ad81f3cf68500e1edfd20635b7))

## [0.8.16](https://github.com/anatolykoptev/ox-browser/compare/v0.8.15...v0.8.16) (2026-10-08)


### Fixed

* **solver:** send the go-wowa secret only for authenticated inbound callers ([#177](https://github.com/anatolykoptev/ox-browser/issues/177)) ([#181](https://github.com/anatolykoptev/ox-browser/issues/181)) ([54a618f](https://github.com/anatolykoptev/ox-browser/commit/54a618f3f851cdb4e77f137928f76f9dd5f828e8))

## [0.8.15](https://github.com/anatolykoptev/ox-browser/compare/v0.8.14...v0.8.15) (2026-10-07)


### Added

* **security:** inbound auth on every route, fail closed; refuse private literal proxies ([86311f8](https://github.com/anatolykoptev/ox-browser/commit/86311f844b4a458334f892e84cbc928eac443fa6))
* **security:** inbound auth on every route, fail closed; refuse private literal proxies ([83d17ad](https://github.com/anatolykoptev/ox-browser/commit/83d17ad0761198cc9e68dc900fda8981ed0daeab))


### Fixed

* **gobrowser:** send X-Internal-Secret on every go-wowa call ([#172](https://github.com/anatolykoptev/ox-browser/issues/172)) ([849bf9b](https://github.com/anatolykoptev/ox-browser/commit/849bf9bae5796268172ae34edcfe02d992d2902e))
* **http:** refuse proxy path/query/fragment on raw text, strip trailing dot on localhost, de-race allowlist test ([edaddc5](https://github.com/anatolykoptev/ox-browser/commit/edaddc55d0a0001643648ab2ced37fb9a3c5dc2d))
* **llm:** tolerate nested parens in link destinations ([#170](https://github.com/anatolykoptev/ox-browser/issues/170)) ([817da42](https://github.com/anatolykoptev/ox-browser/commit/817da42c29211835d59ca59e0df47004ff85e0fb))
* **security:** allowlist proxy schemes; explicit SOCKS ports vetted at 1080 ([92ce54a](https://github.com/anatolykoptev/ox-browser/commit/92ce54aeef5d908edbf71cdae6c6d7e9d11aa3c7))
* **security:** canonicalise every proxy before wreq dials it ([cc617c1](https://github.com/anatolykoptev/ox-browser/commit/cc617c1276a24cc68616cc83e041de781df734b2))
* **security:** cap User-Agents per IP in sightings; test the served app ([8e5a7c5](https://github.com/anatolykoptev/ox-browser/commit/8e5a7c50808a30bb107eeaea6a20f0b8addec810))
* **security:** close the proxy parser differential; per-IP cap warns once ([ea6357e](https://github.com/anatolykoptev/ox-browser/commit/ea6357ebe515ac5a3e743804df0b676892b0769a))
* **security:** mark authenticated requests; subtle compare; redact proxy creds in logs ([8dc6356](https://github.com/anatolykoptev/ox-browser/commit/8dc63566b356249f3a45ccd8de17e72a47c41949))
* **security:** no proxy creds in errors; trim configured creds; per-IP cap; canonical socks5 hosts ([f4751b0](https://github.com/anatolykoptev/ox-browser/commit/f4751b07a420e1b70fd6be489e1ac7a7d4882aab))
* **security:** refuse userinfo parsed outside the authority (SEC-CR-021) ([6fb7b58](https://github.com/anatolykoptev/ox-browser/commit/6fb7b58cbd54d93d8f0e374dbf97c3e6bed05ee4))
* **security:** strict proxy grammar decided from one parse (SEC-CR-022..025) ([1658cee](https://github.com/anatolykoptev/ox-browser/commit/1658ceec8dfba3d5797bab8909cd9c10a3815f9a))


### Documentation

* **security:** SEC-CR-013 test falsification matches the one-parse canonicaliser ([8340fa3](https://github.com/anatolykoptev/ox-browser/commit/8340fa3e97f2c4a182f291249849a08c7132ef05))

## [0.8.14](https://github.com/anatolykoptev/ox-browser/compare/v0.8.13...v0.8.14) (2026-09-27)


### Fixed

* **build:** regenerate Cargo.lock for v0.8.13 ([#167](https://github.com/anatolykoptev/ox-browser/issues/167)) ([83e1b9f](https://github.com/anatolykoptev/ox-browser/commit/83e1b9f9703f8212fbc967eafb4f15c6a2943cea))

## [0.8.13](https://github.com/anatolykoptev/ox-browser/compare/v0.8.12...v0.8.13) (2026-09-26)


### Added

* **http:** consume go-browser solve body, serve it for GET instead of replaying cookies ([#163](https://github.com/anatolykoptev/ox-browser/issues/163)) ([13721d2](https://github.com/anatolykoptev/ox-browser/commit/13721d2df4618838c89c402521b455d7ae1ac8de))

## [0.8.12](https://github.com/anatolykoptev/ox-browser/compare/v0.8.11...v0.8.12) (2026-09-26)


### Fixed

* **http:** label post-solve rechallenge, pin inferred_passthrough, wire timeout defaults ([#160](https://github.com/anatolykoptev/ox-browser/issues/160)) ([107a28f](https://github.com/anatolykoptev/ox-browser/commit/107a28f78a69a46e69e96bc11c14d88a26f5d28f))

## [0.8.11](https://github.com/anatolykoptev/ox-browser/compare/v0.8.10...v0.8.11) (2026-09-26)


### Fixed

* **deps:** quick-xml 0.41 + 50k URL cap for sitemap parsing ([#158](https://github.com/anatolykoptev/ox-browser/issues/158)) ([14eeca4](https://github.com/anatolykoptev/ox-browser/commit/14eeca4af52dfca7026a8f4f144d29d5da9d8e6d))

## [0.8.10](https://github.com/anatolykoptev/ox-browser/compare/v0.8.9...v0.8.10) (2026-09-26)


### Fixed

* **api:** bound every remaining outbound surface at router/dispatch level ([#155](https://github.com/anatolykoptev/ox-browser/issues/155)) ([6d246fc](https://github.com/anatolykoptev/ox-browser/commit/6d246fc327e5a5c70b650ec820880d5ca3d44cd1))

## [0.8.9](https://github.com/anatolykoptev/ox-browser/compare/v0.8.8...v0.8.9) (2026-09-26)


### Fixed

* **http:** make CF-solver decisions observable, bound one solve per request ([#152](https://github.com/anatolykoptev/ox-browser/issues/152)) ([77a78f8](https://github.com/anatolykoptev/ox-browser/commit/77a78f80c5165047346e2870503ea953245f7b70))


### Documentation

* **readme:** correct the MCP tool count and add the missing route ([ac02a03](https://github.com/anatolykoptev/ox-browser/commit/ac02a03a765de825f812705732c147cb46ea3ffd))
* **readme:** lead with content extraction and the quality gate ([4f7c714](https://github.com/anatolykoptev/ox-browser/commit/4f7c714b241ffe16deeaa25b3f2841561719b4eb))
* **readme:** put Cloudflare back in the solver bullet ([fea9f05](https://github.com/anatolykoptev/ox-browser/commit/fea9f05cb345a02cb8e7d81485e92bfb825ad733))

## [0.8.8](https://github.com/anatolykoptev/ox-browser/compare/v0.8.7...v0.8.8) (2026-07-29)


### Added

* **http:** bound every outbound call and meter /fetch ([#140](https://github.com/anatolykoptev/ox-browser/issues/140)) ([7b48c58](https://github.com/anatolykoptev/ox-browser/commit/7b48c5836b1f8edb3bdfd1d2d3ad2c6f2e385454))


### Fixed

* **api:** unify per-call deadline field to `timeout` on all read/fetch surfaces ([#144](https://github.com/anatolykoptev/ox-browser/issues/144)) ([bb7cf4e](https://github.com/anatolykoptev/ox-browser/commit/bb7cf4e511ea13aa4d7c62e746f046f3cc07238e))
* **read:** reject a wrong-container extraction instead of returning it as content ([#138](https://github.com/anatolykoptev/ox-browser/issues/138)) ([405a542](https://github.com/anatolykoptev/ox-browser/commit/405a542c4363c07d54440f4feeb081a12dfa3170))

## [0.8.7](https://github.com/anatolykoptev/ox-browser/compare/v0.8.6...v0.8.7) (2026-07-29)


### Added

* **fetch:** method and body on /fetch and the CLI, with retries gated on idempotency ([#126](https://github.com/anatolykoptev/ox-browser/issues/126)) ([75db1b4](https://github.com/anatolykoptev/ox-browser/commit/75db1b43d5983873338411fc74414a0988f93f18))


### Fixed

* **twitter:** route client through fleet chrome_emulation seam ([#96](https://github.com/anatolykoptev/ox-browser/issues/96)) ([#134](https://github.com/anatolykoptev/ox-browser/issues/134)) ([76eb7ce](https://github.com/anatolykoptev/ox-browser/commit/76eb7ce259504ea62240b88bae2451aaacabc7df))

## [0.8.6](https://github.com/anatolykoptev/ox-browser/compare/v0.8.5...v0.8.6) (2026-07-29)


### Fixed

* cap unbounded response bodies on four neighbour paths ([#122](https://github.com/anatolykoptev/ox-browser/issues/122)) ([8bd7db4](https://github.com/anatolykoptev/ox-browser/commit/8bd7db47cab3eb170990257327019453bbd77424))
* **doctor:** probe internal endpoints without the SSRF guard ([#124](https://github.com/anatolykoptev/ox-browser/issues/124)) ([e60916a](https://github.com/anatolykoptev/ox-browser/commit/e60916a2cfd3a263701c6ed829a19ace5e89f352))

## [0.8.5](https://github.com/anatolykoptev/ox-browser/compare/v0.8.4...v0.8.5) (2026-07-29)


### Added

* **doctor:** move the fingerprint oracle into the shipped binary ([#121](https://github.com/anatolykoptev/ox-browser/issues/121)) ([ffb5877](https://github.com/anatolykoptev/ox-browser/commit/ffb5877145364c3ad31ab39bd4f8e642702e3217))


### Fixed

* **http:** enforce a response body ceiling ([#118](https://github.com/anatolykoptev/ox-browser/issues/118)) ([38732f7](https://github.com/anatolykoptev/ox-browser/commit/38732f7599dffc1f85eefd23de8e1f28f0d7b41c))

## [0.8.4](https://github.com/anatolykoptev/ox-browser/compare/v0.8.3...v0.8.4) (2026-07-29)


### Fixed

* **ci:** set git identity before the lockfile-regen commit ([#116](https://github.com/anatolykoptev/ox-browser/issues/116)) ([c900471](https://github.com/anatolykoptev/ox-browser/commit/c9004710ba336c87e2efac7aff23745f0c58d42f))
* **release:** derive Cargo.lock from the bumped version instead of annotating it ([#112](https://github.com/anatolykoptev/ox-browser/issues/112)) ([d820dd8](https://github.com/anatolykoptev/ox-browser/commit/d820dd813580b78a7b101592373e7c7adf4ad7c8))


### Changed

* **cli:** extract fetch and the shared CLI helpers into modules ([#115](https://github.com/anatolykoptev/ox-browser/issues/115)) ([3704002](https://github.com/anatolykoptev/ox-browser/commit/370400201b3990bc69d335503d0ae45a0c65c8f1))

## [0.8.3](https://github.com/anatolykoptev/ox-browser/compare/v0.8.2...v0.8.3) (2026-07-29)


### Added

* **cli:** add read subcommand exposing the extraction pipeline ([#104](https://github.com/anatolykoptev/ox-browser/issues/104)) ([794ebdc](https://github.com/anatolykoptev/ox-browser/commit/794ebdc53a1fdfe1983bc0f87e0ea5831fb00c4a))


### Fixed

* **cli:** default fetch and read to the service identity ([#108](https://github.com/anatolykoptev/ox-browser/issues/108)) ([3641982](https://github.com/anatolykoptev/ox-browser/commit/3641982df275211a604a09b15e7115358a50d561))
* **media:** route media downloads through the shared browser-identity constructor ([#107](https://github.com/anatolykoptev/ox-browser/issues/107)) ([1295ac3](https://github.com/anatolykoptev/ox-browser/commit/1295ac357bffe3e29763a38305e5f06e5d466887))

## [0.8.2](https://github.com/anatolykoptev/ox-browser/compare/v0.8.1...v0.8.2) (2026-07-29)


### Added

* **content_detect:** trigger JS render for SSR shells with low text ratio ([b4993c8](https://github.com/anatolykoptev/ox-browser/commit/b4993c85e12fc972c6b19cf6d7d7194aed28511a))
* data island + JS eval — SPA content recovery ([#60](https://github.com/anatolykoptev/ox-browser/issues/60)) ([5df29ba](https://github.com/anatolykoptev/ox-browser/commit/5df29ba4a84e085044d53fd41cdaf58af9b03419))
* **docker:** add sccache + mold для signal-grade build cache ([#5](https://github.com/anatolykoptev/ox-browser/issues/5)) ([2ed3737](https://github.com/anatolykoptev/ox-browser/commit/2ed3737a2f6d5b3324dba8726ab56da9eceb9b6e))
* enable TLS/HTTP2 fingerprinting via profile_to_emulation ([#77](https://github.com/anatolykoptev/ox-browser/issues/77)) ([58b2b2f](https://github.com/anatolykoptev/ox-browser/commit/58b2b2f0655e0385605f4d4c7de4314a3b164b88))
* **http:** Webshare 402 → direct-connection fallback ([#2](https://github.com/anatolykoptev/ox-browser/issues/2)) ([c9232eb](https://github.com/anatolykoptev/ox-browser/commit/c9232eb472dd3f31e6772699895e887df9a2c727))
* LLM cleanup pipeline + DOM noise filter ([#58](https://github.com/anatolykoptev/ox-browser/issues/58), [#59](https://github.com/anatolykoptev/ox-browser/issues/59)) ([467a25a](https://github.com/anatolykoptev/ox-browser/commit/467a25acaf67014c96034e009febc74b55e5f2dd))
* **metrics:** add gauge support to hand-rolled Prometheus registry ([caa7cff](https://github.com/anatolykoptev/ox-browser/commit/caa7cff83e68b8d77e6eac10e9ba388d014439f1))
* **metrics:** add gauge support to hand-rolled Prometheus registry ([4e6745c](https://github.com/anatolykoptev/ox-browser/commit/4e6745c21d40966d5733392f712819b9e8a96826))
* **proxy:** PROXY_DISABLED env kill-switch for direct fetch (Webshare bypass) ([00da21e](https://github.com/anatolykoptev/ox-browser/commit/00da21e6cf5a72d7e38ba8829021906e33656f5a))
* Readability-style extractor + token-based noise filter ([#65](https://github.com/anatolykoptev/ox-browser/issues/65)) ([719655a](https://github.com/anatolykoptev/ox-browser/commit/719655a0f04ba06789057b4b4d292a51aee33180))
* **security:** add cargo-deny config + deny Makefile target ([#4](https://github.com/anatolykoptev/ox-browser/issues/4)) ([0ee78d4](https://github.com/anatolykoptev/ox-browser/commit/0ee78d4848ad2b9b2b4960d87ac65d1a496b79d7))
* **security:** connect-time + redirect-hop SSRF guard for outbound fetch ([#14](https://github.com/anatolykoptev/ox-browser/issues/14)) ([1b4de45](https://github.com/anatolykoptev/ox-browser/commit/1b4de45168533dfc355d21ef5cd91176ca0f44c5))
* **tls:** one profile owns TLS, HTTP/2, headers and User-Agent ([#97](https://github.com/anatolykoptev/ox-browser/issues/97)) ([39a6cdc](https://github.com/anatolykoptev/ox-browser/commit/39a6cdc2894a48bf356d3a994b6b1724a0029c85))
* **tls:** send the trust_anchors extension to match Chrome 148 ([#84](https://github.com/anatolykoptev/ox-browser/issues/84)) ([92544ae](https://github.com/anatolykoptev/ox-browser/commit/92544ae3e9a68aca7175fbf2e6e658603557a775))


### Fixed

* build Chrome TLS/HTTP2 fingerprint from scratch ([#80](https://github.com/anatolykoptev/ox-browser/issues/80)) ([fcba98e](https://github.com/anatolykoptev/ox-browser/commit/fcba98e83726a0f066b6a5befd5368261cc882c6))
* clippy --all-targets errors in test code ([c50daeb](https://github.com/anatolykoptev/ox-browser/commit/c50daeba81663e4e6f8a112776271b6ed4c0325b))
* close 5 pr-review-council follow-up NITs ([#72](https://github.com/anatolykoptev/ox-browser/issues/72)-[#76](https://github.com/anatolykoptev/ox-browser/issues/76)) ([de5ced5](https://github.com/anatolykoptev/ox-browser/commit/de5ced594626aa10c48fc77691502258bdb2a400))
* **config:** warn + gauge when NoOpProvider is selected — no silent solver misconfiguration ([36e25c5](https://github.com/anatolykoptev/ox-browser/commit/36e25c5d8a49e763b4fba0b09b62d44f58da5756))
* **cookie-cache:** add eviction task + max_size cap to prevent unbounded growth ([9c84481](https://github.com/anatolykoptev/ox-browser/commit/9c84481f77ccda5f0d6fc8389832b573b3ca96c8))
* **cookie-cache:** add eviction task + max_size cap to prevent unbounded growth ([1e660ef](https://github.com/anatolykoptev/ox-browser/commit/1e660efbfef40fefad5f1a9f67a719e7fa8ef266))
* **crawler:** bound Budget counts with max_capacity + reset() to prevent unbounded growth ([41ac9ff](https://github.com/anatolykoptev/ox-browser/commit/41ac9ff9046e198167a4fc73338ecff6372c9c47)), closes [#23](https://github.com/anatolykoptev/ox-browser/issues/23)
* **crawler:** bound dedup sets with max_capacity + clear() to prevent OOM on large crawls ([e5192dd](https://github.com/anatolykoptev/ox-browser/commit/e5192ddbcbae64d48c37e87c76dd032cd8e992f3))
* **crawler:** bound dedup sets with max_capacity + clear() to prevent OOM on large crawls ([f1b6a78](https://github.com/anatolykoptev/ox-browser/commit/f1b6a787fb6ce2d6945c98daa1f49c0c5229e11e)), closes [#19](https://github.com/anatolykoptev/ox-browser/issues/19)
* **crawler:** bound RobotsCache with max_capacity + TTL to prevent unbounded growth ([ab1393e](https://github.com/anatolykoptev/ox-browser/commit/ab1393e28efdd7b51fc8d4e9d2c85d317b295865))
* **crawler:** frontier push returns bool + warns on capacity drop instead of silent data loss ([a036476](https://github.com/anatolykoptev/ox-browser/commit/a036476d1ab821b39d27ee7a8d4c3f51f52f7711))
* **crawler:** frontier push returns bool + warns on capacity drop instead of silent data loss ([44b6128](https://github.com/anatolykoptev/ox-browser/commit/44b61289e82d060e939c3e224db32509d031af8d))
* **crawler:** serialize concurrent robots.txt fetches per host to prevent TOCTOU double-fetch ([fce01d3](https://github.com/anatolykoptev/ox-browser/commit/fce01d31b5c87e4451135cb380834c75bee3c66b)), closes [#25](https://github.com/anatolykoptev/ox-browser/issues/25)
* **mcp,js:** forward chrome_interact to go-wowa /api/v1 path ([b5c6b75](https://github.com/anatolykoptev/ox-browser/commit/b5c6b75b5db47529da047dd5ae88e5094d2a5215))
* **media:** add tmpfs quota check + reduce cleanup interval to prevent exhaustion ([cc60ffd](https://github.com/anatolykoptev/ox-browser/commit/cc60ffd72753375dd3c41e5d366770bfdbcda06c))
* **metrics:** add oxbrowser_proxy_disabled gauge for PROXY_DISABLED state visibility ([c51dc70](https://github.com/anatolykoptev/ox-browser/commit/c51dc709778f34e05330cafb3ee8364f3cb4d692)), closes [#27](https://github.com/anatolykoptev/ox-browser/issues/27)
* pin rquickjs to =0.12.1 (0.12.2 published &lt;7 days ago) ([649f64f](https://github.com/anatolykoptev/ox-browser/commit/649f64ff36671f436e7c3fab837a75a61f290343))
* pr-review-council medium BUGs — safety valve + char boundary ([3824b2b](https://github.com/anatolykoptev/ox-browser/commit/3824b2bd72ac58dab6833e613291618f1790e13e))
* **proxy-health:** add evict_stale + spawn_eviction_task to bound health map growth ([276bdeb](https://github.com/anatolykoptev/ox-browser/commit/276bdeb6a32c40dc3e5dac0e58c9b59b96df9e66))
* **proxy:** fail closed on proxy-attach failure, drop the unsound 402 degradation heuristic ([#85](https://github.com/anatolykoptev/ox-browser/issues/85)) ([634171f](https://github.com/anatolykoptev/ox-browser/commit/634171f62bd3a87c4c34a5904c554ab315ed689c))
* **ratelimit:** add evict_expired + spawn_eviction_task to bound DomainLimiter growth ([b66084b](https://github.com/anatolykoptev/ox-browser/commit/b66084b545bec7afb5036226b72b48b5ffa97a3b))
* **ratelimit:** publish gauge in mark_rate_limited + add RATELIMIT_DOMAINS render test ([206254d](https://github.com/anatolykoptev/ox-browser/commit/206254d33d093c32ea0ed838bc1079ddd97ffccc))
* recover content from React Suspense boundaries + H1 inside &lt;header&gt; ([278c08c](https://github.com/anatolykoptev/ox-browser/commit/278c08c1bfa00eb257e96fb08dfaa58210385ca2))
* **render-cache:** add eviction task + max_size cap to prevent unbounded growth ([4962b9d](https://github.com/anatolykoptev/ox-browser/commit/4962b9dba37c1f9c2ee636aa9684be2da96c1e90))
* **render-cache:** add eviction task + max_size cap to prevent unbounded growth ([3f9c7a0](https://github.com/anatolykoptev/ox-browser/commit/3f9c7a04325eda1e8072ef9e38955e481f4edda0))
* skip dialog/modal H1 in recover_h1 ([c5c0615](https://github.com/anatolykoptev/ox-browser/commit/c5c0615b3716ce444719dcb4253c12255cc56fcd))
* **solver:** gate retry-storm negcache on chrome_fallback hot path + repair metrics wiring ([#13](https://github.com/anatolykoptev/ox-browser/issues/13)) ([24e44fd](https://github.com/anatolykoptev/ox-browser/commit/24e44fd91ae7f932ddf024123c30a7cde126934d))


### Documentation

* **tls:** correct the 51764 misdiagnosis and make the fingerprint oracle falsifiable ([#83](https://github.com/anatolykoptev/ox-browser/issues/83)) ([0870f4f](https://github.com/anatolykoptev/ox-browser/commit/0870f4fcfce8c063e3bd472cf33cd1f92485b7b4))
