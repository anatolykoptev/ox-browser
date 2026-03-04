use crate::Form;
use dom_query::Document;

pub struct Page {
    pub url: String,
    pub status: u16,
    doc: Document,
}

impl Page {
    pub fn new(url: String, status: u16, html: &str) -> Self {
        Self {
            url,
            status,
            doc: Document::from(html),
        }
    }

    pub fn select(&self, css: &str) -> dom_query::Selection<'_> {
        self.doc.select(css)
    }

    pub fn select_single(&self, css: &str) -> Option<dom_query::Selection<'_>> {
        let sel = self.doc.select(css);
        if sel.is_empty() {
            None
        } else {
            Some(sel)
        }
    }

    pub fn title(&self) -> String {
        self.doc.select("title").text().to_string()
    }

    pub fn text(&self) -> String {
        self.doc.select("body").text().to_string()
    }

    pub fn html(&self) -> String {
        self.doc.html().to_string()
    }

    pub fn forms(&self) -> Vec<Form> {
        self.doc
            .select("form")
            .iter()
            .map(|sel| Form::from_selection(&sel))
            .collect()
    }

    pub fn form_by_id(&self, id: &str) -> Option<Form> {
        let sel = self.doc.select(&format!("form#{}", id));
        if sel.is_empty() {
            return None;
        }
        Some(Form::from_selection(&sel))
    }

    pub fn links(&self) -> Vec<Link> {
        self.doc
            .select("a[href]")
            .iter()
            .filter_map(|sel| {
                let href = sel.attr("href")?.to_string();
                let text = sel.text().to_string();
                Some(Link { href, text })
            })
            .collect()
    }

    pub fn meta_tags(&self) -> Vec<MetaTag> {
        self.doc
            .select("meta")
            .iter()
            .map(|sel| MetaTag {
                name: sel
                    .attr("name")
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                property: sel
                    .attr("property")
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                content: sel
                    .attr("content")
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
            })
            .collect()
    }

    pub fn document(&self) -> &Document {
        &self.doc
    }
}

#[derive(Debug, Clone)]
pub struct Link {
    pub href: String,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct MetaTag {
    pub name: String,
    pub property: String,
    pub content: String,
}
