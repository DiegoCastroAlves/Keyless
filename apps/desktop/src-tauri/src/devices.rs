//! The account's devices (see the devices migration): this one registers
//! itself after signing in and says now and then that it is still in use,
//! the user sees every device where the account is open and can sign one
//! out from here. A device signed out from another one notices the next time
//! it cannot reach the server, and removes the account's data it keeps.
//!
//! The device's name, system and app version are encrypted with the user
//! key; the server only sees where its requests come from.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keyless_core::crypto::{context, random_array};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Manager};

use crate::{
    error::{AppError, AppResult},
    state::AppState,
    sync,
};

/// The device was signed out from another one, and its data removed.
pub const EVENT_DEVICE_REVOKED: &str = "keyless://device-revoked";
const SETTING: &str = "device";
/// How often a signed-in device tells the server it is in use.
const SEEN_EVERY: Duration = Duration::from_secs(5 * 60);
/// How often, at most, a device whose session stopped working asks whether
/// it was signed out.
const STATUS_EVERY: Duration = Duration::from_secs(5 * 60);

/// Runtime state.
#[derive(Default)]
pub struct DeviceState {
    seen_at: Mutex<Option<Instant>>,
    status_checked_at: Mutex<Option<Instant>>,
    /// The server does not have the devices functions yet (the migration is
    /// not applied): stop asking until the app restarts.
    unsupported: AtomicBool,
}

impl DeviceState {
    pub fn supported(&self) -> bool {
        !self.unsupported.load(Ordering::Relaxed)
    }

    /// Notes that the server lacks a function, from the error of a call to it.
    pub fn note_error(&self, err: &AppError) {
        if is_missing_function(err) {
            self.unsupported.store(true, Ordering::Relaxed);
        }
    }
}

/// The server lacks a function or table (its migration is not applied).
pub fn is_missing_function(err: &AppError) -> bool {
    matches!(err, AppError::Server(message) if message.contains("PGRST202") || message.contains("PGRST205"))
}

/// This device's identity for the signed-in account: kept in the local
/// database and dropped when signing out.
#[derive(Clone, Serialize, Deserialize)]
struct Identity {
    user_id: String,
    id: String,
    /// Proves to the server that a status question comes from this device.
    secret: String,
}

fn identity(state: &AppState, user_id: &str) -> AppResult<Identity> {
    let store = state.store();
    if let Some(identity) = store.setting::<Identity>(SETTING)?
        && identity.user_id == user_id
    {
        return Ok(identity);
    }
    let identity = Identity {
        user_id: user_id.to_string(),
        id: uuid::Uuid::new_v4().to_string(),
        secret: URL_SAFE_NO_PAD.encode(random_array::<32>()?.as_ref()),
    };
    store.set_setting(SETTING, &identity)?;
    Ok(identity)
}

/// What the other devices show about this one (encrypted).
#[derive(Clone, Default, Serialize, Deserialize)]
struct DeviceInfo {
    name: String,
    /// "linux", "windows", "macos", "android", "ios" or "web".
    platform: String,
    os: String,
    app_version: String,
}

fn info_context(user_id: &str, device_id: &str) -> Vec<u8> {
    context("device-info", &[user_id, device_id])
}

pub fn platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn host_name() -> String {
    #[cfg(windows)]
    let name = std::env::var("COMPUTERNAME").unwrap_or_default();
    #[cfg(not(windows))]
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .unwrap_or_default();
    name.trim().chars().take(64).collect()
}

fn os_name() -> String {
    #[cfg(target_os = "linux")]
    {
        let release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        let pretty = release
            .lines()
            .find_map(|line| line.strip_prefix("PRETTY_NAME="))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default();
        if !pretty.is_empty() {
            return pretty.chars().take(64).collect();
        }
        "Linux".into()
    }
    #[cfg(windows)]
    {
        "Windows".into()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        std::env::consts::OS.into()
    }
}

fn this_device() -> DeviceInfo {
    DeviceInfo { name: host_name(), platform: platform().into(), os: os_name(), app_version: env!("CARGO_PKG_VERSION").into() }
}

/// Registers this device for the signed-in account (after a sign-in, or
/// when the server does not know it).
pub async fn register(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    if !state.devices.supported() {
        return Ok(());
    }
    let (user_id, token) = sync::ensure_token(&state).await?;
    let identity = identity(&state, &user_id)?;
    let enc_info = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        let json = serde_json::to_vec(&this_device())?;
        session.account.user_key().seal(&json, &info_context(&user_id, &identity.id))?
    };
    let result: AppResult<serde_json::Value> = state
        .api
        .rpc(Some(&token), "register_device", json!({ "p_id": identity.id, "p_secret": identity.secret, "p_enc_info": enc_info }))
        .await;
    if let Err(err) = &result {
        state.devices.note_error(err);
    }
    *state.devices.seen_at.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    result.map(|_| ())
}

/// Registers this device in the background (after a sign-in).
pub fn spawn_register(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(err) = register(&app).await {
            log::info!("device registration: {err}");
        }
    });
}

/// Called after each successful sync: every few minutes, tells the server
/// the device is in use (and registers it when it is not known).
pub async fn seen(app: &AppHandle) {
    let state = app.state::<AppState>();
    {
        let mut seen_at = state.devices.seen_at.lock().unwrap_or_else(|e| e.into_inner());
        if seen_at.is_some_and(|at| at.elapsed() < SEEN_EVERY) {
            return;
        }
        *seen_at = Some(Instant::now());
    }
    // An email change confirmed meanwhile (here or on another device).
    if let Err(err) = crate::auth::sync_email(app).await {
        log::info!("email check: {err}");
    }
    if !state.devices.supported() {
        return;
    }
    let result = async {
        let (user_id, token) = sync::ensure_token(&state).await?;
        let identity = identity(&state, &user_id)?;
        let status: String = state.api.rpc(Some(&token), "device_seen", json!({ "p_id": identity.id })).await?;
        if status != "active" {
            register(app).await?;
        }
        Ok::<(), AppError>(())
    }
    .await;
    if let Err(err) = result {
        state.devices.note_error(&err);
        log::info!("device check: {err}");
    }
}

/// After the server refused this device's session: when the device was
/// signed out from another one, signs out here too (removing the account's
/// data) and tells the window.
pub async fn check_revoked(app: &AppHandle) {
    let state = app.state::<AppState>();
    if !state.devices.supported() {
        return;
    }
    {
        let mut checked = state.devices.status_checked_at.lock().unwrap_or_else(|e| e.into_inner());
        if checked.is_some_and(|at| at.elapsed() < STATUS_EVERY) {
            return;
        }
        *checked = Some(Instant::now());
    }
    let identity = state.store().setting::<Identity>(SETTING);
    let Ok(Some(identity)) = identity else { return };
    let status: AppResult<String> = state
        .api
        .rpc(None, "device_status", json!({ "p_id": identity.id, "p_secret": identity.secret }))
        .await;
    match status {
        Ok(status) if status == "revoked" => {
            log::warn!("this device was signed out from another device");
            if let Err(err) = crate::auth::sign_out(app).await {
                log::warn!("could not remove the account from this device: {err}");
            }
            crate::main_window::deliver(app, EVENT_DEVICE_REVOKED, serde_json::Value::Null);
        }
        Ok(_) => {}
        Err(err) => state.devices.note_error(&err),
    }
}

/// Signing out: this device leaves the account's list (while its session
/// still works) and forgets its identity.
pub async fn forget(state: &AppState, access_token: Option<&str>) {
    let identity = state.store().setting::<Identity>(SETTING).ok().flatten();
    if let (Some(token), Some(identity)) = (access_token, identity)
        && state.devices.supported()
    {
        let result: AppResult<serde_json::Value> = state.api.rpc(Some(token), "remove_device", json!({ "p_id": identity.id })).await;
        if let Err(err) = result {
            log::info!("could not remove this device from the account: {err}");
        }
    }
    let _ = state.store().delete_setting(SETTING);
    *state.devices.seen_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub os: String,
    pub app_version: String,
    pub ip: Option<String>,
    /// ISO 3166 code, when the server knew it.
    pub country: Option<String>,
    pub created_at: String,
    pub last_seen_at: String,
    /// This device.
    pub current: bool,
}

/// The account's signed-in devices, this one first.
pub async fn list(app: &AppHandle) -> AppResult<Vec<DeviceView>> {
    let state = app.state::<AppState>();
    let (user_id, token) = sync::ensure_token(&state).await?;
    let current = identity(&state, &user_id)?.id;
    let mut rows = state.api.devices(&token).await.map_err(|err| {
        state.devices.note_error(&err);
        if is_missing_function(&err) { AppError::Invalid(crate::error::Msg::new("devices_unavailable")) } else { err }
    })?;
    if !rows.iter().any(|row| row.id == current) {
        // Not registered yet (or registered before this account's data was
        // reset): register and read again.
        register(app).await?;
        rows = state.api.devices(&token).await?;
    }
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let mut devices: Vec<DeviceView> = rows
        .into_iter()
        .map(|row| {
            let info = session
                .account
                .user_key()
                .open(&row.enc_info, &info_context(&user_id, &row.id))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<DeviceInfo>(&bytes).ok())
                .unwrap_or_default();
            DeviceView {
                current: row.id == current,
                id: row.id,
                name: info.name,
                platform: info.platform,
                os: info.os,
                app_version: info.app_version,
                ip: row.ip,
                country: row.country,
                created_at: row.created_at,
                last_seen_at: row.last_seen_at,
            }
        })
        .collect();
    devices.sort_by_key(|d| !d.current);
    Ok(devices)
}

/// Signs another device out: its session ends at once, and it removes the
/// account's data the next time it runs.
pub async fn revoke(app: &AppHandle, id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    let _: serde_json::Value = state.api.rpc(Some(&token), "revoke_device", json!({ "p_id": id })).await?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyView {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// The account's passkeys for signing in (added in the web vault, see
/// `keyless_core::passkey_login`), their names decrypted.
pub async fn passkeys(app: &AppHandle) -> AppResult<Vec<PasskeyView>> {
    let state = app.state::<AppState>();
    let (user_id, token) = sync::ensure_token(&state).await?;
    let rows = state.api.passkeys(&token).await.map_err(|err| {
        if is_missing_function(&err) { AppError::Invalid(crate::error::Msg::new("passkeys_unavailable")) } else { err }
    })?;
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let name = session
                .account
                .user_key()
                .open(&row.enc_name, &context("passkey-name", &[&user_id, &row.credential_id]))
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            PasskeyView { id: row.id, name, created_at: row.created_at, last_used_at: row.last_used_at }
        })
        .collect())
}

pub async fn remove_passkey(app: &AppHandle, id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    let _: serde_json::Value = state.api.rpc(Some(&token), "remove_passkey", json!({ "p_id": id })).await?;
    Ok(())
}

/// Ends every other session of the account (devices of older versions
/// included); they need the master password to sign in again.
pub async fn sign_out_others(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.sign_out_others(&token).await
}
