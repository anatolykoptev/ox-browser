// ox-security: CF detection, request hardening, technology fingerprinting, and security analysis.

pub mod cookies;
pub mod cors;
pub mod csp;
pub mod fingerprint;
pub mod headers;
pub mod mixed_content;
pub mod scoring;
pub mod sri;
pub mod supply_chain;
pub mod types;

// Re-export main entry point.
pub use scoring::{analyze_security, SecurityReport};
