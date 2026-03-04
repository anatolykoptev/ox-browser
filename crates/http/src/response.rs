use reqwest::header::HeaderMap;

pub struct HttpResponse {
    pub status: u16,
    pub url: String,
    pub headers: HeaderMap,
    pub body: String,
}
