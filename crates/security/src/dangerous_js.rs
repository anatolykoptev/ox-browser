//! Detect dangerous JavaScript patterns via AST analysis using `oxc_parser`.

use std::sync::LazyLock;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, AssignmentTarget, Expression};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use crate::types::Severity;

#[derive(Debug, Clone, Serialize)]
pub struct DangerousJsReport {
    pub findings: Vec<DangerousJsFinding>,
    pub score_modifier: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DangerousJsFinding {
    pub pattern: String,
    pub detail: String,
    pub severity: Severity,
}

static INLINE_SCRIPT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<script(?:\s[^>]*)?>(?P<body>[\s\S]*?)</script>").unwrap());

static HAS_SRC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bsrc\s*=\s*["']"#).unwrap());

/// Analyze inline `<script>` blocks for dangerous JavaScript patterns.
pub fn analyze_dangerous_js(html: &str) -> DangerousJsReport {
    let mut findings = Vec::new();

    for cap in INLINE_SCRIPT_RE.captures_iter(html) {
        let tag_full = cap.get(0).unwrap().as_str();
        let body = &cap["body"];
        if HAS_SRC_RE.is_match(tag_full) || body.trim().is_empty() {
            continue;
        }
        analyze_script(body, &mut findings);
    }

    let score_modifier = findings
        .iter()
        .map(|f| match f.severity {
            Severity::High => -10,
            Severity::Medium => -5,
            _ => 0,
        })
        .sum::<i32>()
        .max(-25);

    DangerousJsReport {
        findings,
        score_modifier,
    }
}

fn analyze_script(source: &str, findings: &mut Vec<DangerousJsFinding>) {
    let allocator = Allocator::default();
    let source_type = SourceType::mjs();
    let ret = Parser::new(&allocator, source, source_type).parse();
    if ret.panicked || !ret.errors.is_empty() {
        return; // skip unparseable scripts
    }
    for stmt in &ret.program.body {
        walk_statement(stmt, findings);
    }
}

fn walk_statement(stmt: &oxc_ast::ast::Statement, findings: &mut Vec<DangerousJsFinding>) {
    match stmt {
        oxc_ast::ast::Statement::ExpressionStatement(es) => {
            walk_expr(&es.expression, findings);
        }
        oxc_ast::ast::Statement::VariableDeclaration(vd) => {
            for decl in &vd.declarations {
                if let Some(init) = &decl.init {
                    walk_expr(init, findings);
                }
            }
        }
        oxc_ast::ast::Statement::BlockStatement(bs) => {
            for s in &bs.body {
                walk_statement(s, findings);
            }
        }
        oxc_ast::ast::Statement::IfStatement(is) => {
            walk_expr(&is.test, findings);
            walk_statement(&is.consequent, findings);
            if let Some(alt) = &is.alternate {
                walk_statement(alt, findings);
            }
        }
        _ => {}
    }
}

fn walk_expr(expr: &Expression, findings: &mut Vec<DangerousJsFinding>) {
    match expr {
        Expression::CallExpression(call) => {
            check_call(call, findings);
            for arg in &call.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expr(inner, findings);
                }
            }
        }
        Expression::AssignmentExpression(assign) => {
            check_assignment(assign, findings);
            walk_expr(&assign.right, findings);
        }
        Expression::NewExpression(ne) => {
            check_new_expr(ne, findings);
        }
        Expression::SequenceExpression(seq) => {
            for e in &seq.expressions {
                walk_expr(e, findings);
            }
        }
        _ => {}
    }
}

fn check_call(call: &oxc_ast::ast::CallExpression, findings: &mut Vec<DangerousJsFinding>) {
    // eval(...) or window.eval(...) or window["eval"](...)
    if is_callee_named(&call.callee, "eval") {
        findings.push(DangerousJsFinding {
            pattern: "eval".into(),
            detail: "eval() executes arbitrary code".into(),
            severity: Severity::High,
        });
        return;
    }
    // Function("...") without new
    if is_callee_named(&call.callee, "Function") {
        findings.push(DangerousJsFinding {
            pattern: "Function".into(),
            detail: "Function() constructor executes arbitrary code".into(),
            severity: Severity::High,
        });
        return;
    }
    // document.write / document.writeln
    if is_member_call(&call.callee, "document", "write")
        || is_member_call(&call.callee, "document", "writeln")
    {
        let name = member_prop_name(&call.callee).unwrap_or("write");
        findings.push(DangerousJsFinding {
            pattern: "document.write".into(),
            detail: format!("document.{name}() can inject arbitrary HTML"),
            severity: Severity::Medium,
        });
        return;
    }
    // setTimeout/setInterval with string first arg
    if is_callee_named(&call.callee, "setTimeout") || is_callee_named(&call.callee, "setInterval") {
        if let Some(first) = call.arguments.first() {
            if matches!(first, Argument::StringLiteral(_)) {
                let fn_name = callee_name(&call.callee).unwrap_or("setTimeout");
                findings.push(DangerousJsFinding {
                    pattern: "setTimeout-string".into(),
                    detail: format!("{fn_name}() with string argument acts as eval"),
                    severity: Severity::Medium,
                });
            }
        }
    }
}

fn check_assignment(
    assign: &oxc_ast::ast::AssignmentExpression,
    findings: &mut Vec<DangerousJsFinding>,
) {
    let prop = match &assign.left {
        AssignmentTarget::StaticMemberExpression(mem) => Some(mem.property.name.to_string()),
        AssignmentTarget::ComputedMemberExpression(mem) => {
            string_literal_value(&mem.expression).map(String::from)
        }
        _ => None,
    };
    if let Some(ref name) = prop {
        if name == "innerHTML" || name == "outerHTML" {
            findings.push(DangerousJsFinding {
                pattern: name.clone(),
                detail: format!("{name} assignment can inject arbitrary HTML"),
                severity: Severity::Medium,
            });
        }
    }
}

fn check_new_expr(ne: &oxc_ast::ast::NewExpression, findings: &mut Vec<DangerousJsFinding>) {
    if is_callee_named(&ne.callee, "Function") {
        findings.push(DangerousJsFinding {
            pattern: "Function".into(),
            detail: "new Function() constructor executes arbitrary code".into(),
            severity: Severity::High,
        });
    }
}

// --- helpers ---

fn is_callee_named(expr: &Expression, name: &str) -> bool {
    match expr {
        Expression::Identifier(id) => id.name == name,
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == name && is_window(&mem.object)
        }
        Expression::ComputedMemberExpression(mem) => {
            string_literal_value(&mem.expression) == Some(name) && is_window(&mem.object)
        }
        _ => false,
    }
}

fn is_window(expr: &Expression) -> bool {
    matches!(expr, Expression::Identifier(id) if id.name == "window")
}

fn is_member_call(expr: &Expression, obj_name: &str, prop: &str) -> bool {
    match expr {
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == prop
                && matches!(&mem.object, Expression::Identifier(id) if id.name == obj_name)
        }
        Expression::ComputedMemberExpression(mem) => {
            string_literal_value(&mem.expression) == Some(prop)
                && matches!(&mem.object, Expression::Identifier(id) if id.name == obj_name)
        }
        _ => false,
    }
}

fn member_prop_name<'a>(expr: &'a Expression) -> Option<&'a str> {
    match expr {
        Expression::StaticMemberExpression(mem) => Some(&mem.property.name),
        _ => None,
    }
}

fn callee_name<'a>(expr: &'a Expression) -> Option<&'a str> {
    match expr {
        Expression::Identifier(id) => Some(&id.name),
        _ => None,
    }
}

fn string_literal_value<'a>(expr: &'a Expression) -> Option<&'a str> {
    match expr {
        Expression::StringLiteral(s) => Some(&s.value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(js: &str) -> String {
        format!("<script>{js}</script>")
    }

    #[test]
    fn test_eval_call() {
        let r = analyze_dangerous_js(&wrap("eval('alert(1)')"));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].pattern, "eval");
        assert_eq!(r.findings[0].severity, Severity::High);
    }

    #[test]
    fn test_window_eval() {
        let r = analyze_dangerous_js(&wrap(r#"window.eval("code")"#));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].pattern, "eval");

        let r2 = analyze_dangerous_js(&wrap(r#"window["eval"]("code")"#));
        assert_eq!(r2.findings.len(), 1);
        assert_eq!(r2.findings[0].pattern, "eval");
    }

    #[test]
    fn test_function_constructor() {
        // Using new + Function constructor
        let r = analyze_dangerous_js(&wrap("new Function('return 1')"));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].pattern, "Function");
        assert_eq!(r.findings[0].severity, Severity::High);

        // Without new keyword
        let r2 = analyze_dangerous_js(&wrap("Function('return 1')"));
        assert_eq!(r2.findings.len(), 1);
    }

    #[test]
    fn test_innerhtml_assignment() {
        let r = analyze_dangerous_js(&wrap("element.innerHTML = userInput"));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].pattern, "innerHTML");
        assert_eq!(r.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_document_write() {
        let r = analyze_dangerous_js(&wrap("document.write('<h1>hi</h1>')"));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].pattern, "document.write");

        let r2 = analyze_dangerous_js(&wrap("document.writeln('text')"));
        assert_eq!(r2.findings.len(), 1);
    }

    #[test]
    fn test_settimeout_string() {
        let r = analyze_dangerous_js(&wrap("setTimeout('alert(1)', 1000)"));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].pattern, "setTimeout-string");
        assert_eq!(r.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_safe_script() {
        let r = analyze_dangerous_js(&wrap(
            "const x = document.getElementById('foo'); console.log(x);",
        ));
        assert!(r.findings.is_empty());
        assert_eq!(r.score_modifier, 0);
    }

    #[test]
    fn test_script_with_src_ignored() {
        let html = r#"<script src="https://example.com/app.js">eval("bad")</script>"#;
        let r = analyze_dangerous_js(html);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_score_modifier_capped() {
        // 4 high findings = 4*(-10) = -40, capped at -25
        let js = "eval('a'); eval('b'); eval('c'); eval('d')";
        let r = analyze_dangerous_js(&wrap(js));
        assert_eq!(r.findings.len(), 4);
        assert_eq!(r.score_modifier, -25);
    }
}
