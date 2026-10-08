//! MCP tool: media_download

use rmcp::ErrorData as McpError;
use rmcp::model::*;
use serde::Deserialize;

use rmcp::schemars;
use schemars::JsonSchema;

use ox_js::inbound_auth::InboundAuth;

use super::OxMcpServer;

/// Input parameters for the `media_download` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MediaDownloadInput {
    /// URL of page containing video or images.
    pub url: String,
    /// Type of media to extract: "auto", "video", or "image". Default: auto.
    pub media_type: Option<String>,
    /// Maximum video height in pixels (default: 1080).
    pub max_height: Option<u32>,
    /// Maximum file size in MB (default: 50).
    pub max_size_mb: Option<f64>,
    /// Maximum number of files to return (default: 1).
    pub max_results: Option<usize>,
    /// Minimum image width filter in pixels.
    pub min_width: Option<u32>,
}

impl OxMcpServer {
    pub(crate) async fn do_media_download(
        &self,
        input: MediaDownloadInput,
        auth: InboundAuth,
    ) -> Result<CallToolResult, McpError> {
        let media_type = match input.media_type.as_deref() {
            Some("video") => ox_media::MediaType::Video,
            Some("image") => ox_media::MediaType::Image,
            _ => ox_media::MediaType::Auto,
        };

        let req = ox_media::MediaRequest {
            url: input.url,
            media_type,
            max_height: input.max_height,
            max_size_mb: input.max_size_mb,
            max_results: input.max_results,
            proxy: None,
            min_width: input.min_width,
        };

        // ox-browser#177 / SEC-CR-018: `client_for` stamps the gate's
        // `ok_secret` decision — see do_fetch.
        let http = self.client_for(auth);
        let result = ox_media::download(&http, &req, &self.media_config)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let json =
            serde_json::to_string(&result).unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
