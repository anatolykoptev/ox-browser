//! Text-level CSS class detection — identifies visible content that looks
//! like CSS utility class names (Tailwind, Bootstrap, etc.).
//!
//! This is the text-level subset of webclaw's `noise.rs`, adapted to work
//! without `scraper::ElementRef` — the DOM-level noise filtering lives in
//! issue #59. Here we only need `is_css_class_text` and `is_css_class_word`
//! for the LLM cleanup pipeline's `strip_css_class_lines` step.

/// CSS utility prefixes that indicate a word is a class name, not prose.
const CSS_CLASS_PREFIXES: &[&str] = &[
    "text-",
    "bg-",
    "px-",
    "py-",
    "pt-",
    "pb-",
    "pl-",
    "pr-",
    "p-",
    "mx-",
    "my-",
    "mt-",
    "mb-",
    "ml-",
    "mr-",
    "m-",
    "w-",
    "h-",
    "min-",
    "max-",
    "flex-",
    "grid-",
    "col-",
    "row-",
    "gap-",
    "space-",
    "rounded-",
    "shadow-",
    "border-",
    "ring-",
    "outline-",
    "font-",
    "tracking-",
    "leading-",
    "decoration-",
    "opacity-",
    "transition-",
    "duration-",
    "delay-",
    "ease-",
    "translate-",
    "scale-",
    "rotate-",
    "origin-",
    "overflow-",
    "inset-",
    "divide-",
    "z-",
    "top-",
    "left-",
    "right-",
    "bottom-",
    "sr-",
    "not-",
    "group-",
    "peer-",
    "placeholder-",
    "focus-",
    "hover-",
    "active-",
    "disabled-",
    "dark-",
    "sm-",
    "md-",
    "lg-",
    "xl-",
    "2xl-",
];

/// Exact single-word CSS utility class names (no prefix needed).
const CSS_CLASS_EXACT: &[&str] = &[
    "flex",
    "grid",
    "block",
    "inline",
    "hidden",
    "static",
    "fixed",
    "absolute",
    "relative",
    "sticky",
    "isolate",
    "container",
    "prose",
    "antialiased",
    "truncate",
    "uppercase",
    "lowercase",
    "capitalize",
    "italic",
    "underline",
    "overline",
    "invisible",
    "visible",
    "sr-only",
    "not-sr-only",
];

/// Strip Tailwind responsive/state prefixes (e.g., "sm:text-lg" → "text-lg",
/// "dark:sm:text-lg" → "text-lg").
fn strip_tw_variant_prefix(word: &str) -> &str {
    word.rsplit_once(':').map_or(word, |(_, core)| core)
}

/// Check if a single whitespace-delimited word looks like a CSS utility class.
fn is_css_class_word(word: &str) -> bool {
    let core = strip_tw_variant_prefix(word);
    let lower = core.to_lowercase();

    // Arbitrary value syntax: "[--foo:bar]", "w-[200px]"
    if lower.contains('[') && lower.contains(']') {
        return true;
    }

    // Exact matches
    if CSS_CLASS_EXACT.iter().any(|&e| lower == e) {
        return true;
    }

    // Prefix matches
    if CSS_CLASS_PREFIXES.iter().any(|pfx| lower.starts_with(pfx)) {
        return true;
    }

    // Negative utilities: "-mt-4", "-translate-x-1/2"
    if lower.starts_with('-') && lower.len() > 1 {
        let rest = &lower[1..];
        if CSS_CLASS_PREFIXES.iter().any(|pfx| rest.starts_with(pfx)) {
            return true;
        }
    }

    false
}

/// Public wrapper for single-word CSS class detection.
pub(crate) fn is_css_class_word_pub(word: &str) -> bool {
    is_css_class_word(word)
}

/// Check if a text block is predominantly CSS class names.
///
/// Returns true if >50% of the whitespace-delimited words look like CSS
/// utility classes. Requires at least 3 words to avoid false positives.
pub(crate) fn is_css_class_text(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < 3 {
        return false;
    }

    let css_count = words.iter().filter(|w| is_css_class_word(w)).count();
    // >50% of words are CSS classes
    css_count * 2 > words.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn css_class_text_detected() {
        assert!(is_css_class_text(
            "text-4xl font-bold tracking-tight text-gray-900"
        ));
        assert!(is_css_class_text(
            "text-4xl text-5xl text-6xl text-8xl text-gray-950 text-white tracking-tighter text-balance"
        ));
        assert!(is_css_class_text(
            "flex grid rounded-lg shadow-md bg-white px-4 py-2"
        ));
        assert!(is_css_class_text(
            "sm:text-lg dark:bg-gray-800 hover:bg-blue-500"
        ));
        assert!(is_css_class_text("-mt-4 -translate-x-1/2 flex"));
    }

    #[test]
    fn css_class_text_normal_prose_kept() {
        assert!(!is_css_class_text(
            "the text-based approach works well for this use case"
        ));
        assert!(!is_css_class_text(
            "Build beautiful websites with modern tools"
        ));
        assert!(!is_css_class_text(
            "Tailwind CSS is a utility-first CSS framework"
        ));
        assert!(!is_css_class_text("flex grid"));
        assert!(!is_css_class_text("text-lg"));
    }

    #[test]
    fn css_class_text_mixed_content() {
        assert!(is_css_class_text(
            "text-4xl font-bold tracking-tight text-gray-900 hero"
        ));
        assert!(!is_css_class_text(
            "The quick brown fox jumps over the lazy text-lg dog"
        ));
    }
}
