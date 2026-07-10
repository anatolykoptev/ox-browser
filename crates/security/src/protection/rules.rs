//! Embedded protection detection rules.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

const RULES_JSON: &str = include_str!("../protection_rules.json");

#[derive(Debug, Deserialize)]
pub struct RulesDB {
    pub categories: HashMap<String, String>,
    pub rules: Vec<Rule>,
    pub mode_findings: HashMap<String, HashMap<String, ModeFinding>>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub name: String,
    pub category: String,
    pub signals: Signals,
    #[allow(dead_code)] // deserialized from the rules config; not yet consumed by matching
    pub severity: HashMap<String, String>,
    pub confidence_boost: HashMap<String, u8>,
}

#[derive(Debug, Deserialize)]
pub struct Signals {
    #[serde(default)]
    pub cookies: Vec<String>,
    #[serde(default)]
    pub cookies_prefix: Vec<String>,
    #[serde(default)]
    pub cookies_regex: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub headers_regex: Vec<String>,
    #[serde(default)]
    pub scripts: Vec<String>,
    #[serde(default)]
    pub html_patterns: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)] // deserialized from the rules config; not yet consumed by matching
    pub dom_classes: Vec<String>,
    #[serde(default)]
    pub url_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ModeFinding {
    pub severity: String,
    pub message: String,
}

pub static DB: LazyLock<RulesDB> = LazyLock::new(|| {
    serde_json::from_str(RULES_JSON).expect("embedded protection_rules.json is valid")
});

/// Pre-compiled regexes for a single rule.
pub struct CompiledRule {
    pub cookies_regex: Vec<Regex>,
    pub headers_regex: Vec<Regex>,
    pub scripts: Vec<Regex>,
    pub html_patterns: Vec<Regex>,
    pub url_patterns: Vec<Regex>,
}

pub static COMPILED: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    DB.rules
        .iter()
        .map(|rule| {
            let compile = |patterns: &[String]| -> Vec<Regex> {
                patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
            };
            CompiledRule {
                cookies_regex: compile(&rule.signals.cookies_regex),
                headers_regex: compile(&rule.signals.headers_regex),
                scripts: compile(&rule.signals.scripts),
                html_patterns: compile(&rule.signals.html_patterns),
                url_patterns: compile(&rule.signals.url_patterns),
            }
        })
        .collect()
});
