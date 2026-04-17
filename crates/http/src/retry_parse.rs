//! Parsing helpers for retry-related HTTP headers.
//!
//! Handles `Retry-After` header values: integer seconds and IMF-fixdate
//! (RFC 7231 section 7.1.3).

use std::time::Duration;

/// Parse a `Retry-After` header value into a [`Duration`].
///
/// Supports integer seconds (e.g. `"120"`) and HTTP-date format
/// (e.g. `"Thu, 01 Dec 1994 16:00:00 GMT"`).
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    // Try integer seconds first.
    if let Ok(secs) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    // Try HTTP-date (RFC 7231 / RFC 2616).
    parse_http_date(value).and_then(|target| {
        let now = std::time::SystemTime::now();
        target.duration_since(now).ok()
    })
}

/// Attempt to parse an HTTP-date string (IMF-fixdate only).
///
/// Format: `"Sun, 06 Nov 1994 08:49:37 GMT"`.
fn parse_http_date(value: &str) -> Option<std::time::SystemTime> {
    use std::time::UNIX_EPOCH;

    let value = value.trim();
    // We only parse IMF-fixdate: "Day, DD Mon YYYY HH:MM:SS GMT"
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 6 || parts[5] != "GMT" {
        return None;
    }

    let day: u64 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: u64 = parts[3].parse().ok()?;
    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = time_parts[2].parse().ok()?;

    // Convert to Unix timestamp (simplified, no leap-second handling).
    let days = days_from_civil(year, month, day)?;
    let ts = days * 86400 + hour * 3600 + min * 60 + sec;

    Some(UNIX_EPOCH + Duration::from_secs(ts))
}

/// Days from Unix epoch to given civil date (year, month 1-12, day 1-31).
///
/// Uses the algorithm from Howard Hinnant's date library.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    if !(1970..=9999).contains(&year) {
        return None;
    }
    if !(1..=12).contains(&month) || day == 0 || day > max_day(year, month) {
        return None;
    }
    let (y, m) = if month <= 2 {
        (year.wrapping_sub(1), month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe;
    // Unix epoch is 1970-01-01 = civil day 719468.
    days.checked_sub(719_468)
}

fn max_day(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_retry_after_seconds() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after(" 5 "), Some(Duration::from_secs(5)));
    }

    #[test]
    fn parse_retry_after_invalid() {
        assert_eq!(parse_retry_after("not-a-number"), None);
        assert_eq!(parse_retry_after(""), None);
    }
}
