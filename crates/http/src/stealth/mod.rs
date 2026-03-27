//! Stealth patches for headless Chrome — assembled from modular JS files.
//!
//! Two profiles:
//! - `STEALTH_JS` — full patches for stock Chromium (overrides everything)
//! - `STEALTH_JS_LITE` — minimal patches for CloakBrowser (only complements C++ patches)

/// Full stealth for stock Chromium. Overrides platform, GPU, screen, UA, etc.
pub const STEALTH_JS: &str = concat!(
    include_str!("js/cdp_cleanup.js"),
    "\n",
    include_str!("js/navigator.js"),
    "\n",
    include_str!("js/webgl.js"),
    "\n",
    include_str!("js/ua_hints.js"),
    "\n",
    include_str!("js/chrome_object.js"),
    "\n",
    include_str!("js/screen.js"),
    "\n",
    include_str!("js/media.js"),
    "\n",
    include_str!("js/canvas.js"),
    "\n",
    include_str!("js/worker.js"),
);

/// Lite stealth for CloakBrowser. Only CDP cleanup + chrome stubs + worker patches.
/// CloakBrowser already handles: platform, GPU, webdriver, plugins, mimeTypes, screen via C++.
pub const STEALTH_JS_LITE: &str = concat!(
    include_str!("js/cdp_cleanup.js"),
    "\n",
    include_str!("js/chrome_object.js"),
    "\n",
    include_str!("js/media.js"),
    "\n",
    include_str!("js/worker.js"),
);

/// Full UA for stock Chromium (Mac profile).
pub const STEALTH_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

/// When using CloakBrowser, don't override UA — let the binary set it.
pub const STEALTH_UA_NONE: &str = "";
