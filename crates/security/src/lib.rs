// ox-security: CF detection, request hardening, technology fingerprinting, and security analysis.

pub mod body_scan;
pub mod cookies;
pub mod cors;
pub mod csp;
pub mod dangerous_js;
pub mod fingerprint;
pub mod headers;
pub mod info_disclosure;
pub mod mixed_content;
pub mod protection;
pub mod redirect;
pub mod scoring;
pub mod sri;
pub mod supply_chain;
pub mod types;
pub mod vuln_js;

// Re-export main entry point.
pub use scoring::{analyze_security, SecurityReport};
pub use types::ScanMode;
