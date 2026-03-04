use crate::{HttpConfig, HttpError, HttpResponse, Result};
use reqwest::Client;

pub struct HttpClient {
    inner: Client,
    #[allow(dead_code)]
    config: HttpConfig,
}

impl HttpClient {
    pub fn new(config: HttpConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
            .cookie_store(true);

        if let Some(ref proxy_url) = config.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| HttpError::InvalidUrl(e.to_string()))?;
            builder = builder.proxy(proxy);
        }

        Ok(Self {
            inner: builder.build()?,
            config,
        })
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        let resp = self.inner.get(url).send().await?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let headers = resp.headers().clone();
        let body = resp.text().await?;

        Ok(HttpResponse {
            status,
            url: final_url,
            headers,
            body,
        })
    }

    pub async fn post(
        &self,
        url: &str,
        body: &str,
        content_type: &str,
    ) -> Result<HttpResponse> {
        let resp = self
            .inner
            .post(url)
            .header("Content-Type", content_type)
            .body(body.to_string())
            .send()
            .await?;

        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let headers = resp.headers().clone();
        let body = resp.text().await?;

        Ok(HttpResponse {
            status,
            url: final_url,
            headers,
            body,
        })
    }
}
