//! Score bonuses — Observatory-compatible bonus modifiers.

use std::collections::HashMap;

/// Apply bonuses if base score >= 90 (Observatory rule).
pub(super) fn apply_bonuses(score: i32, resp_headers: &HashMap<String, String>) -> i32 {
    if score < 90 {
        return score;
    }

    let mut bonus = 0;

    // Referrer-Policy bonus: +5 for no-referrer or same-origin
    if let Some(rp) = resp_headers.get("referrer-policy") {
        let lower = rp.to_lowercase();
        if lower == "no-referrer" || lower == "same-origin" {
            bonus += 5;
        }
    }

    // HSTS preload bonus: +5 if preload-ready
    if let Some(hsts) = resp_headers.get("strict-transport-security") {
        let lower = hsts.to_lowercase();
        if lower.contains("preload") && lower.contains("includesubdomains") {
            let age = extract_max_age(hsts);
            if age >= 31_536_000 {
                bonus += 5;
            }
        }
    }

    score + bonus
}

fn extract_max_age(val: &str) -> u64 {
    val.split(';')
        .map(str::trim)
        .find(|p| p.to_lowercase().starts_with("max-age"))
        .and_then(|p| p.split('=').nth(1))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}
