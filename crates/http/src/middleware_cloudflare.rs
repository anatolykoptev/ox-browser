//! Cloudflare detection middleware.
//!
//! Port of go-stealth's `CloudflareDetectMiddleware`. Inspects responses
//! for Cloudflare challenge markers and converts them to errors.

use std::sync::Arc;

use async_trait::async_trait;

use crate::cloudflare::detect_cloudflare;
use crate::error::HttpError;
use crate::middleware::{Handler, MiddlewareFn, Request};
use crate::{HttpResponse, Result};

/// Returns a middleware that detects Cloudflare challenges in responses.
///
/// When a challenge is detected, the response is converted to
/// [`HttpError::Cloudflare`]. This integrates with retry middleware:
/// place cloudflare detection *inside* retry so retries happen
/// automatically with a different proxy.
///
/// Chain order: `retry -> cloudflare_detect -> client_hints -> reqwest`
pub fn cloudflare_detect_middleware() -> MiddlewareFn {
    Arc::new(|next: Arc<dyn Handler>| -> Arc<dyn Handler> {
        Arc::new(CloudflareDetectHandler { next })
    })
}

struct CloudflareDetectHandler {
    next: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for CloudflareDetectHandler {
    async fn handle(&self, req: Request) -> Result<HttpResponse> {
        let resp = self.next.handle(req).await?;
        if let Some(cf) = detect_cloudflare(&resp) {
            return Err(HttpError::Cloudflare(
                cf.challenge_type,
                cf.status,
                cf.ray_id,
            ));
        }
        Ok(resp)
    }
}
