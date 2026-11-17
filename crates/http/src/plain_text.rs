//! Block-aware HTML → plain-text rendering.
//!
//! `dom_query`'s `text()` concatenates every text node with no regard for the
//! element boundaries between them, so `<div>Hello</div><div>World</div>`
//! (the shape page builders such as Elementor emit, with no whitespace between
//! nested blocks) came out as `HelloWorld`. This walker emits a line break at
//! every block boundary and keeps normal single-space collapsing inside inline
//! content.

use dom_query::{Document, NodeRef};

/// How much separation is owed before the next piece of text. Ordered: a
/// stronger separator absorbs a weaker one, so adjacent block boundaries never
/// stack up beyond one blank line.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Sep {
    None,
    Space,
    Newline,
    Blank,
}

/// Tags that start and end a block: a newline is owed on both sides.
const BLOCK_TAGS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "body",
    "caption",
    "details",
    "dd",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hgroup",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "summary",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "ul",
];

/// Block tags that read as a paragraph: a blank line is owed on both sides.
const PARAGRAPH_TAGS: &[&str] = &[
    "blockquote",
    "dl",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ol",
    "p",
    "pre",
    "table",
    "ul",
];

/// Separator owed before the next text, plus whether the pending newline came
/// from an explicit `<br>` (so two breaks in a row read as a blank line, while
/// a block boundary next to a `<br>` does not count as one of the two).
struct Pending {
    sep: Sep,
    from_br: bool,
}

impl Pending {
    fn raise(&mut self, sep: Sep) {
        if sep >= Sep::Newline {
            self.from_br = false;
        }
        self.sep = self.sep.max(sep);
    }

    fn line_break(&mut self) {
        match self.sep {
            Sep::Newline if self.from_br => self.sep = Sep::Blank,
            Sep::None | Sep::Space => {
                self.sep = Sep::Newline;
                self.from_br = true;
            }
            Sep::Newline => self.from_br = true,
            Sep::Blank => {}
        }
    }
}

enum Op<'a> {
    Enter(NodeRef<'a>),
    Leave(Sep),
}

/// Render the `<body>` of `doc` as plain text; a document without a body
/// (frameset) renders as empty, as the old `body.text()` path did. Script/style
/// removal is the caller's job.
pub(crate) fn render(doc: &Document) -> String {
    let body = doc.select("body");
    let Some(root) = body.nodes().first().cloned() else {
        return String::new();
    };

    let mut out = String::new();
    let mut pending = Pending {
        sep: Sep::None,
        from_br: false,
    };
    let mut stack = vec![Op::Enter(root)];

    while let Some(op) = stack.pop() {
        match op {
            Op::Leave(sep) => pending.raise(sep),
            Op::Enter(node) => {
                if node.is_text() {
                    push_text(&mut out, &mut pending, &node.text());
                } else if node.is_element() {
                    enter_element(&node, &mut out, &mut pending, &mut stack);
                } else {
                    push_children(&mut stack, &node);
                }
            }
        }
    }
    // The pending separator is never flushed at the ends, so any newline here
    // is literal <pre> text and stays.
    out
}

fn enter_element<'a>(
    node: &NodeRef<'a>,
    out: &mut String,
    pending: &mut Pending,
    stack: &mut Vec<Op<'a>>,
) {
    let tag = node.node_name().map(|n| n.to_ascii_lowercase());
    let tag = tag.as_deref().unwrap_or("");

    if tag == "br" {
        pending.line_break();
        return;
    }
    if !BLOCK_TAGS.contains(&tag) {
        push_children(stack, node);
        return;
    }
    let sep = if PARAGRAPH_TAGS.contains(&tag) {
        Sep::Blank
    } else {
        Sep::Newline
    };
    pending.raise(sep);
    if tag == "pre" {
        // Whitespace is significant inside <pre>: keep it verbatim, `<br>` as
        // a newline. A whitespace-only <pre> renders nothing.
        let text = pre_text(node);
        if !text.trim().is_empty() {
            flush(out, pending);
            out.push_str(&text);
        }
        pending.raise(sep);
        return;
    }
    stack.push(Op::Leave(sep));
    push_children(stack, node);
}

/// Descendant text of a `<pre>` with `<br>` as a newline.
fn pre_text(node: &NodeRef<'_>) -> String {
    let mut text = String::new();
    let mut stack: Vec<NodeRef<'_>> = node.children_it(true).collect();
    while let Some(n) = stack.pop() {
        if n.is_text() {
            text.push_str(&n.text());
        } else if n.is_element() {
            if n.node_name().is_some_and(|t| t.eq_ignore_ascii_case("br")) {
                text.push('\n');
            } else {
                stack.extend(n.children_it(true));
            }
        }
    }
    text
}

/// Push children so the first child is popped first.
fn push_children<'a>(stack: &mut Vec<Op<'a>>, node: &NodeRef<'a>) {
    for child in node.children_it(true) {
        stack.push(Op::Enter(child));
    }
}

fn flush(out: &mut String, pending: &mut Pending) {
    if !out.is_empty() {
        out.push_str(match pending.sep {
            Sep::None => "",
            Sep::Space => " ",
            Sep::Newline => "\n",
            Sep::Blank => "\n\n",
        });
    }
    pending.sep = Sep::None;
    pending.from_br = false;
}

/// Append a text node, collapsing whitespace runs to one space. Leading and
/// trailing whitespace only raise the pending separator, so it is dropped at a
/// block edge and kept (as one space) between inline neighbours.
fn push_text(out: &mut String, pending: &mut Pending, text: &str) {
    let mut words = text.split_whitespace();
    let Some(first) = words.next() else {
        if !text.is_empty() {
            pending.raise(Sep::Space);
        }
        return;
    };
    if text.starts_with(char::is_whitespace) {
        pending.raise(Sep::Space);
    }
    flush(out, pending);
    out.push_str(first);
    for w in words {
        out.push(' ');
        out.push_str(w);
    }
    if text.ends_with(char::is_whitespace) {
        pending.raise(Sep::Space);
    }
}
