//! Twitter ui_metrics challenge solver — pure Rust, no JS engine.
//!
//! Fetches `GET twitter.com/i/js_inst?c_name=ui_metrics`, parses the
//! obfuscated JS, evaluates 3 patterns (prototype XOR, DOM tree, date XOR)
//! plus simple bitwise ops, returns JSON `{rf: {...}, s: "..."}`.
//!
//! Ported from glizzykingdreko/x-twitter-ui-metrics.

use std::collections::HashMap;

use chrono::{Datelike, TimeZone, Utc};
use regex::Regex;

/// Solve the ui_metrics JS challenge, returning the JSON string to send.
pub(super) fn solve(code: &str) -> Result<String, String> {
    let core = find_core_function(code)?;
    let (mut vars, order) = parse_initial_values(&core)?;
    let s_string = parse_s_string(code)?;
    process_operations(&core, &mut vars)?;

    // Build ordered rf object
    let rf: serde_json::Map<String, serde_json::Value> = order
        .iter()
        .map(|k| (k.clone(), serde_json::json!(vars[k])))
        .collect();
    let result = serde_json::json!({"rf": rf, "s": s_string});
    Ok(result.to_string())
}

fn find_core_function(code: &str) -> Result<String, String> {
    let re = Regex::new(r"var\s+([a-f0-9]{64})\s*=").unwrap();
    let m = re.find(code).ok_or("no 64-hex var found")?;
    let start = m.start();
    let ret_offset = code[start..]
        .find("return {")
        .ok_or("no return { found")?;
    let ret_pos = start + ret_offset;

    let mut depth = 0i32;
    let mut end = ret_pos;
    for (i, ch) in code[ret_pos..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = ret_pos + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    Ok(code[start..end].to_string())
}

fn parse_initial_values(
    code: &str,
) -> Result<(HashMap<String, i32>, Vec<String>), String> {
    let re = Regex::new(r"var\s+([a-f0-9]{64})\s*=\s*(\d+)\s*;").unwrap();
    let mut vars = HashMap::new();
    let mut order = Vec::new();
    for cap in re.captures_iter(code) {
        let name = cap[1].to_string();
        let val: i32 = cap[2].parse().map_err(|e| format!("parse int: {e}"))?;
        vars.insert(name.clone(), val);
        order.push(name);
    }
    if order.is_empty() {
        return Err("no initial variables found".into());
    }
    Ok((vars, order))
}

fn parse_s_string(code: &str) -> Result<String, String> {
    let re = Regex::new(r"'s'\s*:\s*'([^']+)'").unwrap();
    re.captures(code)
        .map(|c| c[1].to_string())
        .ok_or_else(|| "no 's' string found".into())
}

fn process_operations(
    body: &str,
    vars: &mut HashMap<String, i32>,
) -> Result<(), String> {
    let iife_re = Regex::new(r"^([a-f0-9]{64})\s*=\s*function\s*\(").unwrap();
    let date_re =
        Regex::new(r"^([a-f0-9]{64})\s*=\s*([a-f0-9]{64})\s*\^\s*new\s+Date")
            .unwrap();
    let args_re = Regex::new(r"\}\s*\(([^)]+)\)\s*;?\s*$").unwrap();

    let lines: Vec<&str> = body.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.is_empty()
            || line.starts_with("var ")
            || line.starts_with("return")
        {
            i += 1;
            continue;
        }

        // IIFE pattern (prototype XOR or DOM tree)
        if let Some(cap) = iife_re.captures(line) {
            let target = cap[1].to_string();
            let (func_text, next_i) = collect_iife(&lines, i);
            if let Some(acap) = args_re.captures(&func_text) {
                let args: Vec<i32> = acap[1]
                    .split(',')
                    .map(|a| get_value(vars, a.trim()))
                    .collect();
                if args.len() >= 3 {
                    let result = if func_text.contains("createElement") {
                        dom_tree_calc(args[0], args[1], args[2])
                    } else {
                        prototype_xor(args[0], args[1], args[2])
                    };
                    vars.insert(target, result);
                }
            }
            i = next_i;
            continue;
        }

        // Date XOR pattern
        if let Some(cap) = date_re.captures(line) {
            let target = cap[1].to_string();
            let source = &cap[2];
            if let Some(&v) = vars.get(source) {
                vars.insert(target, date_xor(v));
            }
            i += 1;
            continue;
        }

        // Simple bitwise operation
        process_simple_op(vars, line);
        i += 1;
    }
    Ok(())
}

fn collect_iife(lines: &[&str], start: usize) -> (String, usize) {
    let mut text = lines[start].to_string();
    let mut depth = lines[start].matches('{').count() as i32
        - lines[start].matches('}').count() as i32;
    let mut j = start + 1;
    while j < lines.len() && depth > 0 {
        text.push('\n');
        text.push_str(lines[j]);
        depth += lines[j].matches('{').count() as i32
            - lines[j].matches('}').count() as i32;
        j += 1;
    }
    (text, j)
}

fn get_value(vars: &HashMap<String, i32>, expr: &str) -> i32 {
    if let Some(&v) = vars.get(expr) {
        return v;
    }
    expr.trim().parse().unwrap_or(0)
}

fn process_simple_op(vars: &mut HashMap<String, i32>, line: &str) {
    let hex = r"[a-f0-9]{64}";
    let assign_re =
        Regex::new(&format!(r"^({hex})\s*=\s*(.+?)\s*;?\s*$")).unwrap();

    let Some(cap) = assign_re.captures(line) else {
        return;
    };
    let target = cap[1].to_string();
    let expr = &cap[2];
    let result = eval_expr(vars, expr);
    vars.insert(target, result);
}

fn eval_expr(vars: &HashMap<String, i32>, expr: &str) -> i32 {
    let expr = expr.trim();

    // ~(A & B) — NAND
    let nand_re = Regex::new(r"^~\((.+?)\s*&\s*(.+?)\)$").unwrap();
    if let Some(cap) = nand_re.captures(expr) {
        let a = resolve(vars, &cap[1]);
        let b = resolve(vars, &cap[2]);
        return !(a & b);
    }
    // ~A — NOT
    if let Some(inner) = expr.strip_prefix('~') {
        return !resolve(vars, inner);
    }
    // A op B
    for (op_str, op_fn) in [
        (" ^ ", (|a: i32, b: i32| a ^ b) as fn(i32, i32) -> i32),
        (" | ", |a, b| a | b),
        (" & ", |a, b| a & b),
        (" >> ", |a, b| a.wrapping_shr(b as u32)),
        (" << ", |a, b| a.wrapping_shl(b as u32)),
    ] {
        if let Some(pos) = expr.find(op_str) {
            let a = resolve(vars, &expr[..pos]);
            let b = resolve(vars, &expr[pos + op_str.len()..]);
            return op_fn(a, b);
        }
    }
    resolve(vars, expr)
}

fn resolve(vars: &HashMap<String, i32>, s: &str) -> i32 {
    let s = s.trim();
    if let Some(&v) = vars.get(s) {
        return v;
    }
    s.parse().unwrap_or(0)
}

// === Three core computation patterns ===

fn prototype_xor(arg1: i32, arg2: i32, arg3: i32) -> i32 {
    (arg2 ^ arg1) | (arg3 ^ arg2)
}

fn date_xor(value: i32) -> i32 {
    let ts_ms = value as i64 * 10_000_000_000i64;
    let day = Utc
        .timestamp_millis_opt(ts_ms)
        .single()
        .map(|d| d.day() as i32)
        .unwrap_or(1);
    value ^ day
}

fn dom_tree_calc(val1: i32, val2: i32, val3: i32) -> i32 {
    struct Node {
        text: i32,
        parent: i32,
    }
    let mut nodes = vec![Node { text: 0, parent: -1 }];

    let mut build = |par: usize, mut v: i32| -> usize {
        let mut cur = par;
        for _ in 0..8 {
            let idx = nodes.len();
            nodes.push(Node {
                text: v,
                parent: cur as i32,
            });
            if (v & 1) == 0 {
                cur = idx;
            }
            v >>= 1;
        }
        cur
    };

    let d1 = build(0, val1);
    let d2 = build(d1, val2);
    let d3 = build(d2, val3);

    let mut idx = d3 as i32;
    let mut sum: i32 = 0;
    while idx > 0 {
        sum = sum.wrapping_add(nodes[idx as usize].text);
        idx = nodes[idx as usize].parent;
    }
    sum % 256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prototype_xor_basic() {
        assert_eq!(prototype_xor(10, 20, 30), (20 ^ 10) | (30 ^ 20));
    }

    #[test]
    fn dom_tree_deterministic() {
        let r1 = dom_tree_calc(161, 195, 75);
        let r2 = dom_tree_calc(161, 195, 75);
        assert_eq!(r1, r2);
        assert!(r1 >= 0 && r1 < 256);
    }

    #[test]
    fn date_xor_known_value() {
        // value=100 → ts=10^12 ms → 2001-09-09 → day=9
        assert_eq!(date_xor(100), 100 ^ 9);
    }

    #[test]
    fn eval_expr_nand() {
        let mut vars = HashMap::new();
        vars.insert("a".repeat(64), 0xFF);
        vars.insert("b".repeat(64), 0x0F);
        let expr = format!("~({} & {})", "a".repeat(64), "b".repeat(64));
        assert_eq!(eval_expr(&vars, &expr), !(0xFF & 0x0F));
    }

    #[test]
    fn parse_s_string_extracts() {
        let code = r#"return {'rf': {}, 's': 'abc123_def'}"#;
        assert_eq!(parse_s_string(code).unwrap(), "abc123_def");
    }
}
