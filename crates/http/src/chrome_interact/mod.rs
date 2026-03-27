//! Headless Chrome page interaction engine.
//!
//! Launches headless Chrome, navigates to a URL, executes sequential
//! actions (click, type, wait, screenshot, evaluate, press, sleep),
//! and returns structured results.

pub mod types;
pub mod logs;
pub mod humanize;
mod actions;
mod execute;
mod navigation;
mod snapshot;

// Re-export public API
pub use actions::execute_action;
pub use execute::execute;
pub use logs::{ConsoleEntry, NetworkEntry, SessionLogs};
pub use types::{
    ActionAccumulator, ActionOutput, ChromeAction, CookieEntry, CookieInput,
    EvalResult, InteractRequest, InteractResponse, InteractStatus,
    ScreenshotResult, SnapshotResult,
};
