//! Updates. Checks the public list of Keyless releases on GitHub, tells the
//! UI when a newer version exists and installs it when the user asks.
//!
//! The release workflow signs every installer (minisign; the public key is in
//! tauri.conf.json, plugins > updater > pubkey) and binds each signature to
//! its version. Nothing is installed unless both check out, so neither GitHub
//! nor the network can push a modified build or an older one.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};

use crate::{
    error::{AppError, AppResult, Msg},
    state::AppState,
};

/// Published releases only (the release feed would also list bare tags,
/// before their files exist).
const RELEASES_API: &str = "https://api.github.com/repos/DiegoCastroAlves/Keyless/releases?per_page=20";
const RELEASE_PAGE: &str = "https://github.com/DiegoCastroAlves/Keyless/releases/tag/v";
const DOWNLOAD_BASE: &str = "https://github.com/DiegoCastroAlves/Keyless/releases/download/v";
const FIRST_CHECK: Duration = Duration::from_secs(20);
const CHECK_EVERY: Duration = Duration::from_secs(12 * 60 * 60);
/// After a failure (offline, GitHub rate limit), try again sooner.
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PACKAGE_BYTES: usize = 300 * 1024 * 1024;
/// Entry of the Arch Linux package in latest.json.
const PACMAN_TARGET: &str = "linux-x86_64-pacman";
pub const EVENT_UPDATE: &str = "keyless://update-available";
pub const EVENT_PROGRESS: &str = "keyless://update-progress";

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

/// How this copy of Keyless was installed, which decides how it updates.
#[derive(Clone, Copy, PartialEq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    /// Windows installer, AppImage, .deb or .rpm, updated by tauri-plugin-updater.
    Bundle,
    /// The Arch Linux package (packaging/arch), updated with pacman.
    Pacman,
    /// Development build or unknown installation: the release page is opened.
    Manual,
}

pub fn install_kind() -> InstallKind {
    use tauri::utils::{config::BundleType, platform::bundle_type};
    match bundle_type() {
        Some(BundleType::Nsis | BundleType::Msi | BundleType::AppImage | BundleType::Deb | BundleType::Rpm) => {
            InstallKind::Bundle
        }
        _ if cfg!(target_os = "linux") && option_env!("KEYLESS_PACKAGE") == Some("pacman") => InstallKind::Pacman,
        _ => InstallKind::Manual,
    }
}

/// System packages ask for the administrator password to install.
fn needs_password() -> bool {
    use tauri::utils::{config::BundleType, platform::bundle_type};
    install_kind() == InstallKind::Pacman || matches!(bundle_type(), Some(BundleType::Deb | BundleType::Rpm))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub current: String,
    pub update: Option<UpdateInfo>,
    pub install: InstallKind,
    pub needs_password: bool,
}

fn info(update: Option<UpdateInfo>) -> VersionInfo {
    VersionInfo { current: env!("CARGO_PKG_VERSION").to_string(), update, install: install_kind(), needs_password: needs_password() }
}

pub fn version_info(state: &AppState) -> VersionInfo {
    let update = if state.settings().check_updates { state.update.lock().unwrap_or_else(|e| e.into_inner()).clone() } else { None };
    info(update)
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
    Ok(info(update))
}

/// The release page of the available update (a URL this module built).
pub fn update_url(state: &AppState) -> Option<String> {
    state.update.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|u| u.url.clone())
}

// ----- installing ----------------------------------------------------------

#[derive(Clone, Serialize)]
struct Progress {
    downloaded: u64,
    total: Option<u64>,
}

struct Busy<'a>(&'a AtomicBool);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Downloads, verifies and installs the available update, then restarts.
/// On Windows the installer takes over and closes the app.
pub async fn install(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let version = state
        .update
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|u| u.version.clone())
        .ok_or(AppError::NotFound)?;
    if state.update_busy.swap(true, Ordering::SeqCst) {
        return Err(AppError::Invalid(Msg::new("busy")));
    }
    let _busy = Busy(&state.update_busy);

    let manifest = format!("{DOWNLOAD_BASE}{version}/latest.json");
    match install_kind() {
        InstallKind::Bundle => install_bundle(app, &manifest).await?,
        InstallKind::Pacman => install_pacman(app, &manifest, &version).await?,
        InstallKind::Manual => return Err(AppError::Invalid(Msg::new("update_manual"))),
    }
    app.restart()
}

fn update_failed(err: impl std::fmt::Display) -> AppError {
    AppError::Invalid(Msg::new("update_failed").with("detail", err))
}

async fn install_bundle(app: &AppHandle, manifest: &str) -> AppResult<()> {
    use tauri_plugin_updater::UpdaterExt;
    let endpoint = url::Url::parse(manifest).map_err(update_failed)?;
    let updater = app.updater_builder().endpoints(vec![endpoint]).map_err(update_failed)?.build().map_err(update_failed)?;
    let update = updater.check().await.map_err(update_failed)?.ok_or_else(|| AppError::Invalid(Msg::new("update_not_found")))?;
    let progress = app.clone();
    let mut downloaded = 0u64;
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ = progress.emit(EVENT_PROGRESS, Progress { downloaded, total });
            },
            || {},
        )
        .await
        .map_err(update_failed)
}

#[derive(Deserialize)]
struct Manifest {
    version: String,
    platforms: HashMap<String, ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    signature: String,
    url: String,
}

fn http_client(timeout: Duration) -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .timeout(timeout)
        .user_agent(concat!("Keyless/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Server(e.to_string()))
}

/// GET with a size limit, reporting progress when `app` is given.
async fn download(client: &reqwest::Client, url: &str, limit: usize, app: Option<&AppHandle>) -> AppResult<Vec<u8>> {
    let mut resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(update_failed(format!("HTTP {}", resp.status())));
    }
    let total = resp.content_length();
    if total.is_some_and(|t| t > limit as u64) {
        return Err(update_failed("download too large"));
    }
    let mut body = Vec::with_capacity(total.unwrap_or(0).min(limit as u64) as usize);
    let mut reported = 0;
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > limit {
            return Err(update_failed("download too large"));
        }
        body.extend_from_slice(&chunk);
        if let Some(app) = app
            && body.len() - reported >= 256 * 1024
        {
            reported = body.len();
            let _ = app.emit(EVENT_PROGRESS, Progress { downloaded: reported as u64, total });
        }
    }
    Ok(body)
}

fn public_key(app: &AppHandle) -> AppResult<String> {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("pubkey"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| update_failed("no update key"))
}

/// Checks the minisign signature of `data` and that it was made for
/// `version` (the version is in the signed trusted comment).
fn verify(data: &[u8], signature: &str, public_key: &str, version: &str) -> AppResult<()> {
    let invalid = || AppError::Invalid(Msg::new("update_invalid"));
    let decode = |text: &str| -> AppResult<String> {
        String::from_utf8(STANDARD.decode(text.trim()).map_err(|_| invalid())?).map_err(|_| invalid())
    };
    let public_key = minisign_verify::PublicKey::decode(&decode(public_key)?).map_err(|_| invalid())?;
    let signature = minisign_verify::Signature::decode(&decode(signature)?).map_err(|_| invalid())?;
    public_key.verify(data, &signature, false).map_err(|_| invalid())?;
    // Only trusted once the signature, which covers it, has been verified.
    let signed = signature.trusted_comment().split('\t').find_map(|field| field.strip_prefix("version:"));
    match (signed.and_then(parse_version), parse_version(version)) {
        (Some(signed), Some(announced)) if signed == announced => Ok(()),
        _ => Err(invalid()),
    }
}

async fn install_pacman(app: &AppHandle, manifest_url: &str, version: &str) -> AppResult<()> {
    let client = http_client(Duration::from_secs(600))?;
    let manifest: Manifest = serde_json::from_slice(&download(&client, manifest_url, MAX_RESPONSE_BYTES, None).await?)?;
    if parse_version(&manifest.version).is_none() || parse_version(&manifest.version) != parse_version(version) {
        return Err(AppError::Invalid(Msg::new("update_invalid")));
    }
    let entry = manifest.platforms.get(PACMAN_TARGET).ok_or_else(|| AppError::Invalid(Msg::new("update_not_found")))?;
    if !entry.url.starts_with(DOWNLOAD_BASE) {
        return Err(AppError::Invalid(Msg::new("update_invalid")));
    }
    let package = download(&client, &entry.url, MAX_PACKAGE_BYTES, Some(app)).await?;
    verify(&package, &entry.signature, &public_key(app)?, &manifest.version)?;
    // A zstd-compressed pacman package.
    if !package.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Err(AppError::Invalid(Msg::new("update_invalid")));
    }

    let dir = private_temp_dir()?;
    let path = dir.join(format!("keyless-{}-x86_64.pkg.tar.zst", manifest.version));
    std::fs::write(&path, &package).map_err(|e| AppError::Store(e.to_string()))?;
    let result = run_pacman(path).await;
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn private_temp_dir() -> AppResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!("keyless-update-{}", uuid::Uuid::new_v4()));
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    builder.create(&dir).map_err(|e| AppError::Store(e.to_string()))?;
    Ok(dir)
}

/// Installs with pacman through polkit, which asks for the password.
async fn run_pacman(path: PathBuf) -> AppResult<()> {
    let status = tauri::async_runtime::spawn_blocking(move || {
        std::process::Command::new("pkexec").arg("pacman").arg("-U").arg("--noconfirm").arg(Path::new(&path)).status()
    })
    .await
    .map_err(update_failed)?
    .map_err(update_failed)?;
    match status.code() {
        Some(0) => Ok(()),
        // Authentication dismissed or refused.
        Some(126 | 127) => Err(AppError::Cancelled),
        _ => Err(update_failed(format!("pacman exited with {status}"))),
    }
}

// ----- release list ----------------------------------------------------------

async fn fetch_latest() -> AppResult<Option<Version>> {
    let client = http_client(Duration::from_secs(20))?;
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

    // Throwaway key pair made with `tauri signer generate`; the payload was
    // signed with `tauri signer sign --app-version 1.2.3`.
    const TEST_PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDNGNDk5REMxMjE3OUNEOUIKUldTYnpYa2h3WjFKUDdjbmRRZ0JaYlRVNWFrY0NsekFVK0R5VnNrTHZYTzRWSEd6eW52WTdZVmYK";
    const TEST_SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVTYnpYa2h3WjFKUDRUMHg5Y2NxTlp0Y08rbFMybFRXYWtVZU02bHVvdGFRaXNNbkh4ZHNLQ2IwcHZtdFZTNVhsM2tEQ2lmeWFiOW5wKzZJcnpHU1J3dnozeG5xbHhaMHdRPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkxMzExNDY5CWZpbGU6cGF5bG9hZC5wa2cJdmVyc2lvbjoxLjIuMwpzNHRhc3RGSE9CKzJIMTBVM0oya212N3RIMWdvN2FHRUE2UW9VVzdkV25BdWFkV2VtbUpDOEg1VEdWNzQ1V3padGNFUTVWT3ZraVU1NjlUSlM5YVFEdz09Cg==";
    const TEST_PAYLOAD: &[u8] = b"keyless pacman update test\n";

    #[test]
    fn verifies_signature_and_signed_version() {
        assert!(verify(TEST_PAYLOAD, TEST_SIGNATURE, TEST_PUBLIC_KEY, "1.2.3").is_ok());
        assert!(verify(TEST_PAYLOAD, TEST_SIGNATURE, TEST_PUBLIC_KEY, "v1.2.3").is_ok());
        // A genuine signature cannot be reused for another version (downgrade).
        assert!(verify(TEST_PAYLOAD, TEST_SIGNATURE, TEST_PUBLIC_KEY, "1.2.4").is_err());
        // Tampered data.
        assert!(verify(b"keyless pacman update test!\n", TEST_SIGNATURE, TEST_PUBLIC_KEY, "1.2.3").is_err());
        // Another key.
        let other_key = include_str!("../tauri.conf.json")
            .split("\"pubkey\": \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap();
        assert!(verify(TEST_PAYLOAD, TEST_SIGNATURE, other_key, "1.2.3").is_err());
        assert!(verify(TEST_PAYLOAD, "not base64", TEST_PUBLIC_KEY, "1.2.3").is_err());
    }

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
