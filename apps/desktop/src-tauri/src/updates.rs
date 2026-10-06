//! Discreet update notice. Checks the public feed of Keyless releases on
//! GitHub and tells the UI when a newer version exists. Nothing is downloaded
//! or installed: the user opens the release page and updates as usual.

use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

const RELEASES_FEED: &str = "https://github.com/DiegoCastroAlves/Keyless/releases.atom";
const RELEASE_PAGE: &str = "https://github.com/DiegoCastroAlves/Keyless/releases/tag/v";
const FIRST_CHECK: Duration = Duration::from_secs(20);
const CHECK_EVERY: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_FEED_BYTES: usize = 1024 * 1024;
pub const EVENT_UPDATE: &str = "keyless://update-available";

type Version = (u64, u64, u64);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    pub url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub current: String,
    pub update: Option<UpdateInfo>,
}

pub fn version_info(state: &AppState) -> VersionInfo {
    let update = if state.settings().check_updates { state.update.lock().unwrap_or_else(|e| e.into_inner()).clone() } else { None };
    VersionInfo { current: env!("CARGO_PKG_VERSION").to_string(), update }
}

/// Checks in the background shortly after start, then twice a day.
pub fn start(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            if app.state::<AppState>().settings().check_updates
                && let Err(err) = check_now(&app).await
            {
                log::info!("update check failed: {err}");
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Checks right away and tells the UI when a newer version appears.
pub async fn check_now(app: &AppHandle) -> AppResult<VersionInfo> {
    let latest = fetch_latest().await?;
    let state = app.state::<AppState>();
    let update = latest
        .filter(|latest| parse_version(env!("CARGO_PKG_VERSION")).is_some_and(|current| *latest > current))
        .map(|(major, minor, patch)| {
            let version = format!("{major}.{minor}.{patch}");
            UpdateInfo { url: format!("{RELEASE_PAGE}{version}"), version }
        });
    let is_new = {
        let mut slot = state.update.lock().unwrap_or_else(|e| e.into_inner());
        let is_new = update.as_ref().map(|u| &u.version) != slot.as_ref().map(|u| &u.version);
        *slot = update.clone();
        is_new
    };
    if is_new && let Some(info) = &update {
        let _ = app.emit(EVENT_UPDATE, info.clone());
    }
    Ok(VersionInfo { current: env!("CARGO_PKG_VERSION").to_string(), update })
}

/// The release page of the available update (a URL this module built).
pub fn update_url(state: &AppState) -> Option<String> {
    state.update.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|u| u.url.clone())
}

async fn fetch_latest() -> AppResult<Option<Version>> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("Keyless/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Server(e.to_string()))?;
    let mut resp = client.get(RELEASES_FEED).send().await?;
    if !resp.status().is_success() {
        return Err(AppError::Server(format!("HTTP {}", resp.status())));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_FEED_BYTES {
            return Err(AppError::Server("release feed too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(newest_in_feed(&String::from_utf8_lossy(&body)))
}

/// "v1.2.3" or "1.2.3"; anything else (pre-release tags included) is ignored.
fn parse_version(text: &str) -> Option<Version> {
    let text = text.trim();
    let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
    let version = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
    parts.next().is_none().then_some(version)
}

/// Newest release tag linked from the GitHub releases feed.
fn newest_in_feed(feed: &str) -> Option<Version> {
    feed.split("/releases/tag/")
        .skip(1)
        .filter_map(|rest| parse_version(rest.split(['"', '<', '&', '?', '#']).next()?))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("v0.1.1"), Some((0, 1, 1)));
        assert_eq!(parse_version("10.20.3"), Some((10, 20, 3)));
        assert_eq!(parse_version("v1.2"), None);
        assert_eq!(parse_version("v1.2.3-beta.1"), None);
        assert_eq!(parse_version("v1.2.3.4"), None);
        assert!(parse_version("v0.10.0") > parse_version("v0.9.9"));
    }

    #[test]
    fn finds_the_newest_release_in_the_feed() {
        let feed = r#"<feed>
          <entry><link rel="alternate" type="text/html" href="https://github.com/DiegoCastroAlves/Keyless/releases/tag/v0.1.1"/></entry>
          <entry><link rel="alternate" type="text/html" href="https://github.com/DiegoCastroAlves/Keyless/releases/tag/v0.10.0"/></entry>
          <entry><link rel="alternate" type="text/html" href="https://github.com/DiegoCastroAlves/Keyless/releases/tag/v0.9.4"/></entry>
          <entry><link rel="alternate" type="text/html" href="https://github.com/DiegoCastroAlves/Keyless/releases/tag/v2.0.0-rc.1"/></entry>
        </feed>"#;
        assert_eq!(newest_in_feed(feed), Some((0, 10, 0)));
        assert_eq!(newest_in_feed("<feed></feed>"), None);
    }
}
