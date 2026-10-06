//! Discreet update notice. Checks the public list of Keyless releases on
//! GitHub and tells the UI when a newer version exists. Nothing is downloaded
//! or installed: the user opens the release page and updates as usual.

use std::time::Duration;

use serde::{Deserialize, Serialize, de::IgnoredAny};
use tauri::{AppHandle, Emitter, Manager};

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

/// Published releases only (the release feed would also list bare tags,
/// before their files exist).
const RELEASES_API: &str = "https://api.github.com/repos/DiegoCastroAlves/Keyless/releases?per_page=20";
const RELEASE_PAGE: &str = "https://github.com/DiegoCastroAlves/Keyless/releases/tag/v";
const FIRST_CHECK: Duration = Duration::from_secs(20);
const CHECK_EVERY: Duration = Duration::from_secs(12 * 60 * 60);
/// After a failure (offline, GitHub rate limit), try again sooner.
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const EVENT_UPDATE: &str = "keyless://update-available";

type Version = (u64, u64, u64);

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<IgnoredAny>,
}

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
            let mut wait = CHECK_EVERY;
            if app.state::<AppState>().settings().check_updates
                && let Err(err) = check_now(&app).await
            {
                log::info!("update check failed: {err}");
                wait = RETRY_AFTER;
            }
            tokio::time::sleep(wait).await;
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
    let mut resp = client
        .get(RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(AppError::Server(format!("HTTP {}", resp.status())));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(AppError::Server("release list too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    let releases: Vec<Release> = serde_json::from_slice(&body)?;
    Ok(newest_release(&releases))
}

/// "v1.2.3" or "1.2.3"; anything else (pre-release tags included) is ignored.
fn parse_version(text: &str) -> Option<Version> {
    let text = text.trim();
    let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
    let version = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
    parts.next().is_none().then_some(version)
}

/// Newest published release that has its files attached.
fn newest_release(releases: &[Release]) -> Option<Version> {
    releases
        .iter()
        .filter(|r| !r.draft && !r.assets.is_empty())
        .filter_map(|r| parse_version(&r.tag_name))
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
    fn picks_the_newest_published_release_with_files() {
        let json = r#"[
          {"tag_name": "v0.3.0", "draft": true, "prerelease": true, "assets": [{"name": "a"}]},
          {"tag_name": "v0.2.0", "draft": false, "prerelease": true, "assets": []},
          {"tag_name": "v2.0.0-rc.1", "draft": false, "prerelease": true, "assets": [{"name": "a"}]},
          {"tag_name": "v0.10.0", "draft": false, "prerelease": true, "assets": [{"name": "a"}, {"name": "b"}]},
          {"tag_name": "v0.9.4", "draft": false, "prerelease": false, "assets": [{"name": "a"}]}
        ]"#;
        let releases: Vec<Release> = serde_json::from_str(json).unwrap();
        assert_eq!(newest_release(&releases), Some((0, 10, 0)));
        assert_eq!(newest_release(&[]), None);
    }
}
