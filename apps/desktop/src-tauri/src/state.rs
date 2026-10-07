//! Application state shared by every command.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

use keyless_core::{
    account::UnlockedAccount,
    crypto::context,
    import::ImportResult,
    item::ItemOverview,
    vault::{VaultKey, VaultMeta},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    api::{Api, AuthSession},
    clipboard::ClipboardGuard,
    error::{AppError, AppResult},
    secrets::SecretStore,
    store::Store,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Lock after this many minutes without activity.
    pub auto_lock_minutes: u32,
    /// Clear copied secrets from the clipboard after this many seconds.
    pub clipboard_clear_seconds: u32,
    /// Lock when the computer sleeps or the screen locks.
    pub lock_on_sleep: bool,
    /// "system", "light" or "dark".
    pub theme: String,
    /// "system", "en" or "es".
    pub language: String,
    /// Register the native messaging host so the browser extension works.
    pub browser_integration: bool,
    /// Look for new Keyless versions (see `updates`).
    pub check_updates: bool,
    /// Unlock with the computer's password after the master password was
    /// entered (see `system_unlock`). Only changed through
    /// `set_system_unlock`, which asks for the master password.
    pub system_unlock: bool,
    /// Item list order: "title", "created", "modified", "frequent" or "recent".
    pub list_sort: String,
    /// Newest (or most used, or Z to A) first.
    pub list_sort_desc: bool,
    /// Closing the window hides Keyless in the tray instead of quitting.
    pub close_to_tray: bool,
    /// Start Keyless when the user logs in.
    pub start_at_login: bool,
    /// When started at login, stay in the tray instead of opening the window.
    pub start_minimized: bool,
    /// Quick Access shortcut registered by the app (Windows; Linux desktops
    /// own their shortcuts). Empty turns it off.
    pub quick_access_shortcut: String,
    /// Show website icons, downloaded from each site (see `site_icons`).
    pub site_icons: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_lock_minutes: 10, clipboard_clear_seconds: 90, lock_on_sleep: true, theme: "system".into(), language: "system".into(), browser_integration: true, check_updates: true, system_unlock: false, list_sort: "title".into(), list_sort_desc: false, close_to_tray: true, start_at_login: false, start_minimized: true, quick_access_shortcut: "Ctrl+Shift+Space".into(), site_icons: true }
    }
}

impl Settings {
    pub fn sanitized(mut self) -> Self {
        self.auto_lock_minutes = self.auto_lock_minutes.clamp(1, 480);
        self.clipboard_clear_seconds = self.clipboard_clear_seconds.clamp(10, 600);
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            self.theme = "system".into();
        }
        if !matches!(self.language.as_str(), "system" | "en" | "es") {
            self.language = "system".into();
        }
        if !matches!(self.list_sort.as_str(), "title" | "created" | "modified" | "frequent" | "recent") {
            self.list_sort = "title".into();
        }
        self
    }
}

pub struct Tokens {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub expires_at: i64,
}

impl From<AuthSession> for Tokens {
    fn from(s: AuthSession) -> Self {
        Self { access: s.access_token, refresh: s.refresh_token, expires_at: s.expires_at }
    }
}

pub struct OpenVault {
    pub key: VaultKey,
    pub meta: VaultMeta,
    pub role: String,
}

impl OpenVault {
    pub fn can_write(&self) -> bool {
        matches!(self.role.as_str(), "owner" | "editor")
    }
}

pub struct CachedItem {
    pub vault_id: String,
    pub overview: ItemOverview,
}

/// Everything that exists only while Keyless is unlocked. Dropping it wipes
/// the keys from memory.
pub struct Session {
    pub user_id: String,
    pub email: String,
    pub account: UnlockedAccount,
    pub vaults: HashMap<String, OpenVault>,
    pub items: HashMap<String, CachedItem>,
    pub tokens: Option<Tokens>,
    /// Items that could not be decrypted (corrupted or tampered with).
    pub unreadable_items: usize,
}

impl Session {
    pub fn vault(&self, id: &str) -> AppResult<&OpenVault> {
        self.vaults.get(id).ok_or(AppError::NotFound)
    }

    pub fn session_context(&self) -> Vec<u8> {
        context("local-session", &[&self.user_id])
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SyncStatus {
    /// "idle", "syncing", "offline", "error" or "signed_out".
    pub state: String,
    pub last_synced_at: Option<i64>,
    pub message: Option<String>,
}

/// Failed unlock attempts. Persisted, so restarting the app does not reset
/// the back-off.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UnlockThrottle {
    pub failures: u32,
    /// Unix seconds.
    pub blocked_until: i64,
}

impl UnlockThrottle {
    pub fn check(&self) -> AppResult<()> {
        let now = crate::api::now_secs();
        if self.blocked_until > now {
            return Err(AppError::RateLimited((self.blocked_until - now).max(1) as u64));
        }
        Ok(())
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        if self.failures >= 5 {
            // 5 failures: 30 s, then doubling up to 15 minutes.
            let exp = (self.failures - 5).min(5);
            let secs = (30i64 << exp).min(900);
            self.blocked_until = crate::api::now_secs() + secs;
        }
    }
}

/// Held while an unlock/sign-in is running; concurrent attempts are refused
/// so they cannot slip past the throttle.
pub struct UnlockGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for UnlockGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct AppState {
    pub store: Mutex<Store>,
    pub secrets: SecretStore,
    pub api: Api,
    pub session: tokio::sync::Mutex<Option<Session>>,
    /// Monotonic and wall-clock time of the last user activity. The wall
    /// clock catches time spent suspended, which the monotonic clock may skip.
    pub last_activity: Mutex<(Instant, SystemTime)>,
    pub settings: Mutex<Settings>,
    pub clipboard: ClipboardGuard,
    pub sync_gate: tokio::sync::Mutex<()>,
    pub sync_status: Mutex<SyncStatus>,
    pub unlock_throttle: Mutex<UnlockThrottle>,
    pub unlock_busy: std::sync::atomic::AtomicBool,
    pub bridge: crate::bridge::Bridge,
    pub pending_import: Mutex<Option<ImportResult>>,
    /// Cancels the running "Continue with Google" browser step.
    pub google_cancel: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Google session waiting for the new account's master password.
    pub pending_google: tokio::sync::Mutex<Option<crate::oauth::PendingGoogle>>,
    /// Newer Keyless version found by the update check.
    pub update: Mutex<Option<crate::updates::UpdateInfo>>,
    /// An update is being downloaded or installed.
    pub update_busy: std::sync::atomic::AtomicBool,
    /// Account keys kept in memory while locked, for system unlock.
    pub kept_keys: Mutex<Option<crate::system_unlock::KeptKeys>>,
    /// When the master password was last entered in this run.
    pub password_at: Mutex<Option<SystemTime>>,
    /// When Quick Access was last shown.
    pub quick_access_shown: Mutex<Option<Instant>>,
    /// The Quick Access page has loaded.
    pub quick_access_ready: std::sync::atomic::AtomicBool,
    /// Quick Access was asked for before its page loaded.
    pub quick_access_pending: std::sync::atomic::AtomicBool,
    /// Browser extension requests waiting for the unlock prompt to close
    /// (true when Keyless was unlocked).
    pub unlock_prompt: Mutex<Vec<tokio::sync::oneshot::Sender<bool>>>,
    /// Whether Keyless is locked, for the tray icon and the browser
    /// extension's icon.
    pub lock_state: tokio::sync::watch::Sender<bool>,
}

impl AppState {
    pub fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn settings(&self) -> Settings {
        self.settings.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn save_settings(&self, settings: &Settings) -> AppResult<()> {
        self.store().set_setting("settings", settings)?;
        *self.settings.lock().unwrap_or_else(|e| e.into_inner()) = settings.clone();
        Ok(())
    }

    pub fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|e| e.into_inner()) = (Instant::now(), SystemTime::now());
    }

    pub fn idle_for(&self) -> Duration {
        let (instant, wall) = *self.last_activity.lock().unwrap_or_else(|e| e.into_inner());
        let wall_elapsed = SystemTime::now().duration_since(wall).unwrap_or_default();
        instant.elapsed().max(wall_elapsed)
    }

    pub fn begin_unlock(&self) -> AppResult<UnlockGuard<'_>> {
        if self.unlock_busy.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(AppError::Invalid(crate::error::Msg::new("busy")));
        }
        let guard = UnlockGuard(&self.unlock_busy);
        self.unlock_throttle.lock().unwrap_or_else(|e| e.into_inner()).check()?;
        Ok(guard)
    }

    pub fn record_unlock_result(&self, success: bool) {
        let mut throttle = self.unlock_throttle.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            *throttle = UnlockThrottle::default();
        } else {
            throttle.record_failure();
        }
        let _ = self.store().set_setting("unlock_throttle", &*throttle);
    }

    pub fn set_sync_status(&self, status: SyncStatus) {
        *self.sync_status.lock().unwrap_or_else(|e| e.into_inner()) = status;
    }

    pub fn sync_status(&self) -> SyncStatus {
        self.sync_status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
