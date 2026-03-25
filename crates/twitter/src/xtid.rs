/// ClientTransaction — ported from go-twitter transaction.go + utils.go.
/// Fixes: correct keyword, float_to_hex rewrite, color clamping.
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::xtid_cubic::{interpolate, rotation_to_matrix, Cubic};
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

        Ok(Self { key_bytes, animation_key, row_index, key_bytes_indices })
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
        for i in 0..4 {
            time_bytes[i] = ((time_now >> (i * 8)) & 0xFF) as u8;
        }

        let hash_input =
            format!("{method}!{path}!{time_now}{KEYWORD}{}", self.animation_key);
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

        // Step 2: Select which row within that frame
        let row_idx = if row_index < key_bytes.len() {
            (key_bytes[row_index] as usize) % 16
        } else {
            0
        };

        // Step 3: Compute frameTime from key indices
        let mut frame_time = 1.0_f64;
        for &idx in key_indices {
            if idx < key_bytes.len() {
                frame_time *= (key_bytes[idx] as usize % 16) as f64;
            }
        }
        frame_time = js_round(frame_time / 10.0) * 10.0;

        if row_idx >= frame_2d.len() {
            return Err("row index out of bounds in SVG frame".to_string());
        }

        let row = &frame_2d[row_idx];
        let target_time = frame_time / TOTAL_TIME;
        Ok(Self::animate(row, target_time))
    }

    fn animate(row: &[i32], target_time: f64) -> String {
        // Single row must have at least 11 values: [r,g,b, r,g,b, rot, c0,c1,c2,c3]
        if row.len() < 11 {
            return String::new();
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
            let rounded = (v * 100.0).round() / 100.0;
            let abs_val = rounded.abs();
            let hex = float_to_hex(abs_val);
            if hex.starts_with('.') {
                parts.push(format!("0{}", hex.to_lowercase()));
            } else if hex.is_empty() {
                parts.push("0".to_string());
            } else {
                parts.push(hex.to_lowercase());
            }
        }

        parts.push("0".to_string());
        parts.push("0".to_string());

        let result = parts.join("");
        result.replace(['.', '-'], "")
    }
}

fn solve(value: f64, min: f64, max: f64, rounding: bool) -> f64 {
    let result = value * (max - min) / 255.0 + min;
    if rounding {
        result.floor()
    } else {
        (result * 100.0).round() / 100.0
    }
}

fn is_odd(n: usize) -> f64 {
    if n % 2 != 0 { -1.0 } else { 0.0 }
}

fn js_round(num: f64) -> f64 {
    let x = num.floor();
    let x = if num - x >= 0.5 { num.ceil() } else { x };
    x.copysign(num)
}

fn float_to_hex(x: f64) -> String {
    let mut result = String::new();
    let quotient = x as u64;
    let mut fraction = x - quotient as f64;

    if quotient == 0 && fraction == 0.0 {
        return "0".to_string();
    }

    if quotient > 0 {
        result.push_str(&format!("{quotient:x}"));
    }

    if fraction > 0.0 {
        result.push('.');
        for _ in 0..6 {
            fraction *= 16.0;
            let digit = fraction as u8;
            fraction -= digit as f64;
            result.push(char::from_digit(digit as u32, 16).unwrap_or('0'));
            if fraction.abs() < 1e-10 {
                break;
            }
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
