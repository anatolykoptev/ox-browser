//! Stealth patches for headless Chrome — assembled from modular JS files.

/// Stealth bootstrap script. Injected via `evaluate_on_new_document` before
/// any page JS runs. Each section is an independent IIFE.
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

/// User-Agent matching the Client Hints in ua_hints.js.
pub const STEALTH_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
