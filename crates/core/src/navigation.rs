use url::Url;

pub fn resolve_url(base: &str, relative: &str) -> Option<String> {
    let base_url = Url::parse(base).ok()?;
    let resolved = base_url.join(relative).ok()?;
    Some(resolved.to_string())
}

pub fn is_same_origin(url1: &str, url2: &str) -> bool {
    let u1 = Url::parse(url1).ok();
    let u2 = Url::parse(url2).ok();
    match (u1, u2) {
        (Some(a), Some(b)) => a.origin() == b.origin(),
        _ => false,
    }
}
