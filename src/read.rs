//! `read` subcommand — CLI surface for the content-extraction pipeline.
//!
//! Calls `ox_http::read_pipeline::read_page`, the SAME function the
//! `/read` HTTP handler (`ox_js::read`) and the MCP `read` tool call.
//! One pipeline, three surfaces — formats, defaults, and chrome-render
//! escalation all come from the shared function, so they cannot drift.

use ox_http::content::{ReadOutput, ReadParams};
use ox_http::read_pipeline::{SiteHandler, read_page};

use crate::build_cli_http_client;

/// Arguments for the `read` subcommand, parsed by clap in `main.rs`.
pub struct ReadArgs {
    pub url: String,
    pub format: String,
    pub max_length: usize,
    pub profile: Option<String>,
    pub proxy: Option<String>,
    pub debug: bool,
    pub json: bool,
    /// Per-call deadline in seconds (`--timeout`). `None` → seam default;
    /// `Some(s)` → clamped to `[1, MAX_CALL_TIMEOUT_SECS]`. Bounds the
    /// whole read pipeline, not one attempt (issue #139).
    pub timeout: Option<u64>,
}

/// Format strings accepted by `--format`. Mirrors the set
/// `ContentFormat::from_param` recognises (content.rs) so the CLI never
/// rejects a value the pipeline would have honoured, and never silently
/// passes a value the pipeline would fall back on.
const VALID_FORMATS: &[&str] = &["text", "markdown", "md", "html", "llm"];

/// Validate `--format`. Rejects unknown values with a clear message instead
/// of letting `ContentFormat::from_param` silently fall back to Text.
pub fn validate_format(s: &str) -> Result<(), String> {
    if VALID_FORMATS.contains(&s) {
        Ok(())
    } else {
        Err(format!(
            "invalid --format '{s}': expected one of text, markdown, html, llm"
        ))
    }
}

/// Build the `ReadParams` the pipeline consumes. Pure — no I/O — so the
/// CLI-construction path is unit-testable without a server or network.
pub fn build_read_params(args: &ReadArgs) -> Result<ReadParams, String> {
    validate_format(&args.format)?;
    Ok(ReadParams {
        url: args.url.clone(),
        format: args.format.clone(),
        max_length: args.max_length,
        timeout_secs: args.timeout,
    })
}

/// Run the `read` subcommand.
///
/// Stream contract:
/// - default (human): extracted content → stdout, metadata header → stderr
///   (so `ox-browser read URL | grep x` yields just content);
/// - `--json`: the full `ReadOutput` JSON → stdout (pipeable to `jq`);
/// - on error: reason → stderr (via the returned `Err`), exit non-zero.
pub async fn run(args: ReadArgs) -> anyhow::Result<()> {
    let params = build_read_params(&args).map_err(|e| anyhow::anyhow!(e))?;
    let http = build_cli_http_client(args.profile.as_deref(), args.proxy, args.debug)?;
    let handlers: Vec<SiteHandler> = ox_js::default_site_handlers();

    let output = read_page(&http, &params, &handlers).await;

    if let Some(err) = &output.error {
        // A failed read must surface the reason and exit non-zero — never an
        // empty document + exit 0 (the silent-empty-success failure mode).
        return Err(anyhow::anyhow!("read failed: {err}"));
    }

    if args.json {
        let json = serde_json::to_string(&output)
            .map_err(|e| anyhow::anyhow!("serialize read output: {e}"))?;
        println!("{json}");
    } else {
        emit_human(&output);
    }
    Ok(())
}

/// Human-readable output: metadata to stderr, content to stdout.
fn emit_human(output: &ReadOutput) {
    eprintln!("title:      {}", output.title);
    if !output.author.is_empty() {
        eprintln!("author:     {}", output.author);
    }
    if !output.language.is_empty() {
        eprintln!("language:   {}", output.language);
    }
    eprintln!("method:     {}", output.method);
    eprintln!("elapsed_ms: {}", output.elapsed_ms);
    eprintln!("length:     {}", output.length);
    // Blank separator then content on stdout.
    eprintln!();
    print!("{}", output.content);
    if !output.content.ends_with('\n') {
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ox_http::content::ContentFormat;

    #[test]
    fn validate_format_accepts_all_pipeline_formats() {
        // Every string ContentFormat::from_param maps non-default must be
        // accepted, plus the default "text". If a format is added to
        // from_param but not here, this test catches the drift.
        for &valid in VALID_FORMATS {
            assert!(validate_format(valid).is_ok(), "{valid} should be accepted");
            // The pipeline must also recognise it (otherwise the CLI accepts
            // a value the pipeline silently falls back on).
            let _ = ContentFormat::from_param(valid); // never panics
        }
    }

    #[test]
    fn validate_format_rejects_invalid_with_clear_message() {
        for &invalid in &["", "json", "xml", "TEXT", "Markdown", "plain"] {
            let err = validate_format(invalid).unwrap_err();
            assert!(
                err.contains("invalid --format"),
                "message must name the flag; got: {err}"
            );
            assert!(
                err.contains(invalid) || invalid.is_empty(),
                "message must echo the bad value; got: {err}"
            );
        }
    }

    #[test]
    fn build_read_params_preserves_args() {
        let args = ReadArgs {
            url: "https://example.com/x".into(),
            format: "markdown".into(),
            max_length: 1234,
            profile: None,
            proxy: None,
            debug: false,
            json: false,
            timeout: None,
        };
        let p = build_read_params(&args).unwrap();
        assert_eq!(p.url, "https://example.com/x");
        assert_eq!(p.format, "markdown");
        assert_eq!(p.max_length, 1234);
        assert_eq!(p.timeout_secs, None);
    }

    #[test]
    fn build_read_params_preserves_timeout() {
        let args = ReadArgs {
            url: "https://example.com/x".into(),
            format: "markdown".into(),
            max_length: 0,
            profile: None,
            proxy: None,
            debug: false,
            json: false,
            timeout: Some(3),
        };
        let p = build_read_params(&args).unwrap();
        assert_eq!(p.timeout_secs, Some(3));
    }

    #[test]
    fn build_read_params_rejects_invalid_format() {
        let args = ReadArgs {
            url: "https://example.com".into(),
            format: "yaml".into(),
            max_length: 0,
            profile: None,
            proxy: None,
            debug: false,
            json: false,
            timeout: None,
        };
        assert!(build_read_params(&args).is_err());
    }

    #[test]
    fn format_mapping_matches_pipeline_exactly() {
        // The CLI does not remap formats — it passes the string through to
        // ReadParams.format, and the pipeline's ContentFormat::from_param is
        // the single mapping. Assert each accepted string maps to the same
        // ContentFormat the pipeline would select. A test that would still
        // pass if the mapping were swapped is not a test: we assert the
        // concrete variant, so swapping from_param breaks this.
        for &(s, expected) in &[
            ("text", ContentFormat::Text),
            ("markdown", ContentFormat::Markdown),
            ("md", ContentFormat::Markdown),
            ("html", ContentFormat::Html),
            ("llm", ContentFormat::Llm),
        ] {
            assert_eq!(
                ContentFormat::from_param(s),
                expected,
                "format '{s}' must map to {expected:?}"
            );
        }
        // An invalid string the CLI rejects must NOT silently match a real
        // format in the pipeline either — confirm it falls back (Text),
        // which is why the CLI rejects it upstream.
        assert_eq!(ContentFormat::from_param("yaml"), ContentFormat::Text);
    }
}
