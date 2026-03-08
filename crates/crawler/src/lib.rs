mod budget;
mod config;
mod crawler;
mod dedup;
mod frontier;
mod markdown;
mod result;
mod robots;
mod scope;

pub use budget::Budget;
pub use config::{CrawlConfig, CrawlerSection};
pub use crawler::Crawler;
pub use dedup::{is_cycle, normalize_url, ContentDedup, UrlDedup};
pub use frontier::{Frontier, FrontierEntry};
pub use markdown::{html_to_fit_markdown, html_to_markdown};
pub use result::{CrawlResult, CrawlStats};
pub use robots::RobotsCache;
pub use scope::CrawlScope;
