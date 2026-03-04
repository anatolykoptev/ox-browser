use dom_query::Selection;

#[derive(Debug)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
}

#[derive(Debug, Clone)]
pub struct FormField {
    pub name: String,
    pub value: String,
    pub field_type: String,
    pub disabled: bool,
}

impl Form {
    pub fn from_selection(sel: &Selection<'_>) -> Self {
        let action = sel
            .attr("action")
            .map(|s| s.to_string())
            .unwrap_or_default();

        let raw_method = sel
            .attr("method")
            .map(|s| s.to_string())
            .unwrap_or_default()
            .to_uppercase();

        let method = if raw_method.is_empty() {
            "GET".to_string()
        } else {
            raw_method
        };

        let fields = extract_fields_from_selection(sel);

        Self {
            action,
            method,
            fields,
        }
    }

    pub fn set_field(&mut self, name: &str, value: &str) {
        if let Some(field) = self.fields.iter_mut().find(|f| f.name == name) {
            field.value = value.to_string();
        }
    }

    pub fn serialize(&self) -> String {
        self.fields
            .iter()
            .filter(|f| !f.disabled && !f.name.is_empty())
            .map(|f| {
                format!("{}={}", url_encode(&f.name), url_encode(&f.value))
            })
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// Extract form fields directly from a Selection using sub-selection,
/// avoiding re-parsing of inner HTML.
fn extract_fields_from_selection(
    form: &Selection<'_>,
) -> Vec<FormField> {
    let mut fields = Vec::new();

    // Input fields
    for input in form.select("input").iter() {
        let name = input
            .attr("name")
            .map(|s| s.to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let value = input
            .attr("value")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let field_type = input
            .attr("type")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let disabled = input.has_attr("disabled");

        fields.push(FormField {
            name,
            value,
            field_type,
            disabled,
        });
    }

    // Select fields
    for sel in form.select("select").iter() {
        let name = sel
            .attr("name")
            .map(|s| s.to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let disabled = sel.has_attr("disabled");
        let value = sel
            .select("option[selected]")
            .attr("value")
            .map(|s| s.to_string())
            .unwrap_or_default();

        fields.push(FormField {
            name,
            value,
            field_type: "select".to_string(),
            disabled,
        });
    }

    // Textarea fields
    for ta in form.select("textarea").iter() {
        let name = ta
            .attr("name")
            .map(|s| s.to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let value = ta.text().to_string();
        let disabled = ta.has_attr("disabled");

        fields.push(FormField {
            name,
            value,
            field_type: "textarea".to_string(),
            disabled,
        });
    }

    fields
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
