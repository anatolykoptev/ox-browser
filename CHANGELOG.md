# Changelog

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
