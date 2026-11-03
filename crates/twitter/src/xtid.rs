//! ClientTransaction: the x-client-transaction-id generator.
//!
//! The animation key is what X's own script prints after running a CSS animation
//! in a browser, so the oracle is a browser: `testdata/browser` holds Chromium's
//! answers for 1000 keys and `xtid_browser_test` holds this code to them exactly.
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::xtid_cubic::{Cubic, interpolate, rotation_to_matrix};
use crate::xtid_parser::{parse_key_indices, parse_svg_frames, parse_verification_key};

const KEYWORD: &str = "obfiowerehiring";
const ADDITIONAL_RANDOM_NUMBER: u8 = 3;
const EPOCH_MS: u64 = 1_682_924_400_000;
const TOTAL_TIME: f64 = 4096.0;

pub(crate) struct ClientTransaction {
    key_bytes: Vec<u8>,
    animation_key: String,
    #[allow(dead_code)]
    row_index: usize,
    #[allow(dead_code)]
    key_bytes_indices: Vec<usize>,
}

impl ClientTransaction {
    pub(crate) fn new(html: &str, js: &str) -> Result<Self, String> {
        let key_bytes = parse_verification_key(html)?;
        let (row_index, key_bytes_indices) = parse_key_indices(js)?;
        let svg_frames = parse_svg_frames(html)?;

        let animation_key =
            Self::build_animation_key(&key_bytes, row_index, &key_bytes_indices, &svg_frames)?;

        Ok(Self {
            key_bytes,
            animation_key,
            row_index,
            key_bytes_indices,
        })
    }

    #[cfg(test)]
    pub(crate) fn animation_key(&self) -> &str {
        &self.animation_key
    }

    pub(crate) fn generate_id(&self, method: &str, path: &str) -> String {
        let path = match path.find('?') {
            Some(i) => &path[..i],
            None => path,
        };

        let time_now = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64)
            .saturating_sub(EPOCH_MS)
            / 1000;
        let time_now = time_now as u32;

        let mut time_bytes = [0u8; 4];
        #[allow(clippy::needless_range_loop)] // index also drives the bit-shift
        for i in 0..4 {
            time_bytes[i] = ((time_now >> (i * 8)) & 0xFF) as u8;
        }

        let hash_input = format!("{method}!{path}!{time_now}{KEYWORD}{}", self.animation_key);
        let hash = Sha256::digest(hash_input.as_bytes());
        let hash_bytes = &hash[..16];

        let mut bytes_arr = Vec::with_capacity(self.key_bytes.len() + 4 + 16 + 1);
        bytes_arr.extend_from_slice(&self.key_bytes);
        bytes_arr.extend_from_slice(&time_bytes);
        bytes_arr.extend_from_slice(hash_bytes);
        bytes_arr.push(ADDITIONAL_RANDOM_NUMBER);

        let random_num: u8 = rand::thread_rng().r#gen();
        let mut out = vec![0u8; bytes_arr.len() + 1];
        out[0] = random_num;
        for (i, b) in bytes_arr.iter().enumerate() {
            out[i + 1] = b ^ random_num;
        }

        let encoded = STANDARD.encode(&out);
        encoded.trim_end_matches('=').to_string()
    }

    fn build_animation_key(
        key_bytes: &[u8],
        row_index: usize,
        key_indices: &[usize],
        svg_frames: &[Vec<Vec<i32>>],
    ) -> Result<String, String> {
        if key_indices.is_empty() {
            return Err("no key byte indices".to_string());
        }
        if key_bytes.len() < 6 {
            return Err("key_bytes too short (need at least 6)".to_string());
        }

        // Step 1: Select which of the 4 SVG frames to use
        let frame_idx = (key_bytes[5] as usize) % 4;
        if frame_idx >= svg_frames.len() || svg_frames[frame_idx].is_empty() {
            return Err("SVG frame not available".to_string());
        }
        let frame_2d = &svg_frames[frame_idx];

        // Step 2: Select which row within that frame. An index outside the key
        // means the page and the script do not belong together (or the key is
        // truncated): a different byte than X reads would give a well-formed id
        // that X rejects silently for the whole life of the keys, so fail and let
        // the manager keep its previous keys.
        if row_index >= key_bytes.len() {
            return Err(format!(
                "row index {row_index} outside the {}-byte verification key",
                key_bytes.len()
            ));
        }
        let row_idx = (key_bytes[row_index] as usize) % 16;

        // Step 3: Compute frameTime from key indices
        let mut frame_time = 1.0_f64;
        for &idx in key_indices {
            if idx >= key_bytes.len() {
                return Err(format!(
                    "key byte index {idx} outside the {}-byte verification key",
                    key_bytes.len()
                ));
            }
            frame_time *= (key_bytes[idx] as usize % 16) as f64;
        }
        frame_time = js_round(frame_time / 10.0) * 10.0;

        if row_idx >= frame_2d.len() {
            return Err("row index out of bounds in SVG frame".to_string());
        }

        let row = &frame_2d[row_idx];
        let target_time = frame_time / TOTAL_TIME;
        Self::animate(row, target_time)
    }

    fn animate(row: &[i32], target_time: f64) -> Result<String, String> {
        // Single row must have at least 11 values: [r,g,b, r,g,b, rot, c0,c1,c2,c3]
        if row.len() < 11 {
            return Err(format!(
                "SVG row has {} values, need at least 11",
                row.len()
            ));
        }

        let from_color = [row[0] as f64, row[1] as f64, row[2] as f64, 1.0];
        let to_color = [row[3] as f64, row[4] as f64, row[5] as f64, 1.0];
        let from_rotation = [0.0_f64];
        let to_rotation = [solve(row[6] as f64, 60.0, 360.0, true)];

        let curve_frames = &row[7..];
        let curves: Vec<f64> = curve_frames
            .iter()
            .enumerate()
            .map(|(i, &v)| solve(v as f64, is_odd(i), 1.0, false))
            .collect();

        let c = Cubic::new(&curves);
        let val = c.get_value(target_time);

        let color = interpolate(&from_color, &to_color, val);
        let clamped: Vec<f64> = color.iter().map(|&v| v.clamp(0.0, 255.0)).collect();

        let rotation = interpolate(&from_rotation, &to_rotation, val);
        let matrix = rotation_to_matrix(rotation[0]);

        let mut parts: Vec<String> = (0..3)
            .map(|i| format!("{:x}", clamped[i].round() as u8))
            .collect();

        for &v in &matrix {
            for token in matrix_numbers(v) {
                let hex = float_to_hex(to_fixed2(token).abs());
                if hex.starts_with('.') {
                    parts.push(format!("0{}", hex.to_lowercase()));
                } else if hex.is_empty() {
                    parts.push("0".to_string());
                } else {
                    parts.push(hex.to_lowercase());
                }
            }
        }

        parts.push("0".to_string());
        parts.push("0".to_string());

        let result = parts.join("");
        Ok(result.replace(['.', '-'], ""))
    }
}

/// The number tokens X's script reads from one matrix entry. The script reads
/// the entry from `getComputedStyle`, where Chromium prints it with six
/// significant digits ("0.719009", and "5.68575e-05" for small values), then
/// matches `/[\d.-]+/g` over that string: the exponent of "5.68575e-05" comes out
/// as a second number, "-05". Both effects change the key.
fn matrix_numbers(v: f64) -> Vec<f64> {
    let s = format_g6(v);
    let mut out = Vec::new();
    let mut tok = String::new();
    for ch in s.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() || ch == '.' || ch == '-' {
            tok.push(ch);
        } else if !tok.is_empty() {
            if let Ok(n) = tok.parse::<f64>() {
                out.push(n);
            }
            tok.clear();
        }
    }
    out
}

/// `%g` with six significant digits and trailing zeros removed, the way
/// Chromium serialises a matrix entry: exponent form (at least two exponent
/// digits) below 1e-4 or from 1e6 up.
fn format_g6(v: f64) -> String {
    if v == 0.0 {
        return if v.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    if !v.is_finite() {
        return String::new();
    }
    let sci = format!("{:.5e}", v);
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if !(-4..6).contains(&exp) {
        let mant = if mant.contains('.') {
            mant.trim_end_matches('0').trim_end_matches('.')
        } else {
            mant
        };
        let sign = if exp < 0 { '-' } else { '+' };
        return format!("{mant}e{sign}{:02}", exp.abs());
    }
    let decimals = (5 - exp).max(0) as usize;
    let fixed = format!("{v:.decimals$}");
    if fixed.contains('.') {
        fixed
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    } else {
        fixed
    }
}

/// JavaScript's `Number(x.toFixed(2))`: the decimal expansion of the double is
/// rounded to two places and an exact tie goes to the larger magnitude, where
/// Rust's formatting rounds a tie to even. Only multiples of 1/8 can tie.
fn to_fixed2(x: f64) -> f64 {
    let ax = x.abs();
    let mut s = format!("{ax:.2}");
    let e = ax * 8.0;
    if e == e.floor() && e % 2.0 == 1.0 {
        let n = (ax * 100.0 + 0.5) as i64;
        s = format!("{}.{:02}", n / 100, n % 100);
    }
    let v: f64 = s.parse().unwrap_or(0.0);
    v.copysign(x)
}

fn solve(value: f64, min: f64, max: f64, rounding: bool) -> f64 {
    let result = value * (max - min) / 255.0 + min;
    if rounding {
        result.floor()
    } else {
        round2(result)
    }
}

/// The reference's `Math.round(v*100)/100`. JavaScript rounds a tie toward
/// +Infinity, `f64::round` away from zero: they differ for negative ties.
fn round2(v: f64) -> f64 {
    js_round(v * 100.0) / 100.0
}

fn is_odd(n: usize) -> f64 {
    if !n.is_multiple_of(2) { -1.0 } else { 0.0 }
}

fn js_round(num: f64) -> f64 {
    let x = num.floor();
    let x = if num - x >= 0.5 { num.ceil() } else { x };
    x.copysign(num)
}

/// Hex expansion of a non-negative double, as the reference prints it: the
/// integer part in hex, then ".", then fraction digits until the fraction is
/// exactly zero. Multiplying a double by 16 is exact, so the loop ends after at
/// most ~270 steps; stopping earlier truncates the expansion and corrupts the key.
fn float_to_hex(x: f64) -> String {
    if !x.is_finite() || x < 0.0 {
        return String::new();
    }
    let quotient = x as u64;
    let mut fraction = x - quotient as f64;
    if quotient == 0 && fraction == 0.0 {
        return "0".to_string();
    }
    let mut result = String::new();
    if quotient > 0 {
        result.push_str(&format!("{quotient:x}"));
    }
    if fraction > 0.0 {
        result.push('.');
        while fraction > 0.0 {
            fraction *= 16.0;
            let digit = fraction as u32;
            fraction -= digit as f64;
            result.push(char::from_digit(digit, 16).unwrap_or('0'));
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float_to_hex_zero() {
        assert_eq!(float_to_hex(0.0), "0");
    }

    #[test]
    fn test_float_to_hex_integer() {
        assert_eq!(float_to_hex(1.0), "1");
        assert_eq!(float_to_hex(255.0), "ff");
        assert_eq!(float_to_hex(16.0), "10");
    }

    #[test]
    fn test_float_to_hex_fraction() {
        // 0.5 * 16 = 8 → ".8"
        assert_eq!(float_to_hex(0.5), ".8");
        // 0.25 * 16 = 4 → ".4"
        assert_eq!(float_to_hex(0.25), ".4");
    }

    #[test]
    fn test_float_to_hex_mixed() {
        // 1.5 → "1.8"
        assert_eq!(float_to_hex(1.5), "1.8");
    }

    #[test]
    fn test_solve_no_rounding() {
        // value=127.5, min=0, max=255 → 127.5 * 255/255 + 0 = 127.5 → round to 127.5
        let r = solve(127.5, 0.0, 255.0, false);
        assert!((r - 127.5).abs() < 1e-9);
    }

    #[test]
    fn test_solve_rounding() {
        // value=255, min=60, max=360 → 255*300/255 + 60 = 360 → floor = 360
        let r = solve(255.0, 60.0, 360.0, true);
        assert_eq!(r, 360.0);
    }

    #[test]
    fn test_js_round() {
        assert_eq!(js_round(0.5), 1.0);
        assert_eq!(js_round(1.4), 1.0);
        assert_eq!(js_round(1.5), 2.0);
        // -0.5: floor=-1, ceil(-0.5)=0, copysign(0, -0.5) = -0.0 (matches Go)
        assert_eq!(js_round(-0.5).abs(), 0.0);
        // -1.5: floor=-2, ceil(-1.5)=-1, copysign(-1, -1.5) = -1.0 (Go behavior)
        assert_eq!(js_round(-1.5), -1.0);
    }

    #[test]
    fn test_float_to_hex_keeps_the_whole_expansion() {
        // 0.07 needs 14 hex digits; the expansion ends only at an exactly zero fraction.
        assert_eq!(float_to_hex(0.07), ".11eb851eb851ec");
        assert_eq!(float_to_hex(7.09), "7.170a3d70a3d7");
    }

    #[test]
    fn test_matrix_numbers_read_the_exponent_as_a_number() {
        assert_eq!(matrix_numbers(0.719009), vec![0.719009]);
        assert_eq!(matrix_numbers(5.68575e-5), vec![5.68575, -5.0]);
        assert_eq!(matrix_numbers(-0.5), vec![-0.5]);
        assert_eq!(matrix_numbers(1.0), vec![1.0]);
        assert_eq!(matrix_numbers(0.0001), vec![0.0001]);
    }

    #[test]
    fn test_to_fixed2_rounds_like_javascript() {
        // 0.695 is stored as 0.69499999...: toFixed(2) gives 0.69, Math.round(v*100)/100 gives 0.7.
        assert_eq!(to_fixed2(0.695), 0.69);
        // exact ties go to the larger magnitude, not to even
        assert_eq!(to_fixed2(0.125), 0.13);
        assert_eq!(to_fixed2(-0.125), -0.13);
        assert_eq!(to_fixed2(0.375), 0.38);
    }

    fn frames_with_row(row: Vec<i32>) -> Vec<Vec<Vec<i32>>> {
        vec![vec![row; 16]; 4]
    }

    #[test]
    fn test_build_animation_key_refuses_what_it_cannot_build() {
        let key: Vec<u8> = (0..48).collect();
        let good = frames_with_row(vec![10, 20, 30, 40, 50, 60, 100, 5, 100, 200, 250]);
        assert!(ClientTransaction::build_animation_key(&key, 3, &[7, 9], &good).is_ok());
        // row index outside the key
        let e = ClientTransaction::build_animation_key(&key, 48, &[7], &good).unwrap_err();
        assert!(e.contains("row index"), "{e}");
        // key byte index outside the key
        let e = ClientTransaction::build_animation_key(&key, 3, &[7, 48], &good).unwrap_err();
        assert!(e.contains("key byte index"), "{e}");
        // a row too short to animate
        let short = frames_with_row(vec![1, 2, 3]);
        assert!(ClientTransaction::build_animation_key(&key, 3, &[7], &short).is_err());
    }

    #[test]
    fn test_generate_id_valid_base64() {
        // Build a minimal ClientTransaction manually
        let ct = ClientTransaction {
            key_bytes: vec![1, 2, 3, 4],
            animation_key: "testkey".to_string(),
            row_index: 0,
            key_bytes_indices: vec![1, 2],
        };
        let id = ct.generate_id("GET", "/2/timeline/home.json?count=20");
        // Must be non-empty and no trailing '='
        assert!(!id.is_empty());
        assert!(!id.ends_with('='));
        // Restore padding: base64 length must be multiple of 4
        let pad = (4 - id.len() % 4) % 4;
        let padded = format!("{}{}", id, "=".repeat(pad));
        let decoded = STANDARD.decode(&padded);
        assert!(decoded.is_ok(), "base64 decode failed: {:?}", decoded);
    }
}
