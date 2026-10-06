//! Keyless desktop app (Tauri).
//!
//! All cryptography and secret handling happens in Rust; the web UI only
//! renders what these commands return.

mod api;
mod auth;
mod bridge;
mod clipboard;
mod commands;
mod config;
mod error;
mod hardening;
mod health;
mod import;
mod items;
mod lock;
mod secrets;
mod state;
mod store;
mod sync;

use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

use tauri::{Manager, plugin::TauriPlugin};

use crate::{
    api::Api,
    clipboard::ClipboardGuard,
    secrets::SecretStore,
    state::{AppState, Settings, SyncStatus, UnlockThrottle},
    store::Store,
};

/// Only our own bundled pages may load in the app window. Links inside item
/// notes, for example, can never navigate the window away.
fn navigation_guard<R: tauri::Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("navigation-guard")
        .on_navigation(|_webview, url| {
            let allowed = matches!(url.scheme(), "tauri")
                || matches!(url.host_str(), Some("tauri.localhost"))
                || (cfg!(debug_assertions) && matches!(url.host_str(), Some("localhost")) && url.port() == Some(1420));
            if !allowed {
                log::warn!("blocked navigation to {}", url.scheme());
            }
            allowed
        })
        .build()
}

/// The app's X25519 key for the browser bridge, kept with the other
/// device secrets.
fn load_or_create_bridge_key(secrets: &SecretStore) -> Result<x25519_dalek::StaticSecret, Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if let Some(encoded) = secrets.get(secrets::BRIDGE_KEY)?
        && let Ok(bytes) = STANDARD.decode(encoded.as_bytes())
        && let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(x25519_dalek::StaticSecret::from(array));
    }
    let bytes = keyless_core::crypto::random_array::<32>()?;
    secrets.put(secrets::BRIDGE_KEY, &STANDARD.encode(bytes.as_ref()))?;
    Ok(x25519_dalek::StaticSecret::from(*bytes))
}

pub fn run() {
    // Started by a browser for the extension: relay messages, no window.
    let args: Vec<String> = std::env::args().collect();
    if bridge::host::is_host_invocation(&args) {
        bridge::host::run();
        return;
    }
    hardening::apply();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(navigation_guard())
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let store = Store::open(&data_dir.join("keyless.db"))?;
            let settings: Settings = store.setting::<Settings>("settings")?.unwrap_or_default().sanitized();
            let throttle: UnlockThrottle = store.setting("unlock_throttle")?.unwrap_or_default();
            let secrets = SecretStore::new(&data_dir);
            let bridge_secret = load_or_create_bridge_key(&secrets)?;
            let browser_integration = settings.browser_integration;

            app.manage(AppState {
                store: Mutex::new(store),
                secrets,
                api: Api::new()?,
                session: tokio::sync::Mutex::new(None),
                last_activity: Mutex::new((Instant::now(), SystemTime::now())),
                settings: Mutex::new(settings),
                clipboard: ClipboardGuard::default(),
                sync_gate: tokio::sync::Mutex::new(()),
                sync_status: Mutex::new(SyncStatus::default()),
                unlock_throttle: Mutex::new(throttle),
                unlock_busy: std::sync::atomic::AtomicBool::new(false),
                bridge: bridge::Bridge::new(bridge_secret),
                pending_import: Mutex::new(None),
            });

            lock::start(app.handle().clone());
            sync::start_background_sync(app.handle().clone());
            bridge::server::start(app.handle().clone());
            std::thread::spawn(move || bridge::install::sync_registration(browser_integration));

            // Daily cleanup of items deleted more than 30 days ago.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(6 * 3600));
                loop {
                    interval.tick().await;
                    let _ = items::purge_old_trash(&handle).await;
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                window.app_handle().state::<AppState>().clipboard.clear_now();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::create_account,
            commands::sign_in,
            commands::unlock,
            commands::reauthenticate,
            commands::lock,
            commands::sign_out,
            commands::resend_confirmation,
            commands::reveal_secret_key,
            commands::change_master_password,
            commands::delete_account,
            commands::password_strength,
            commands::heartbeat,
            commands::get_settings,
            commands::update_settings,
            commands::get_sync_status,
            commands::sync_now,
            commands::list_vaults,
            commands::create_vault,
            commands::update_vault,
            commands::delete_vault,
            commands::list_items,
            commands::get_item,
            commands::get_item_draft,
            commands::save_item,
            commands::reveal_field,
            commands::get_totp,
            commands::get_password_history,
            commands::copy_field,
            commands::copy_item_value,
            commands::copy_text,
            commands::open_item_url,
            commands::set_favorite,
            commands::set_archived,
            commands::trash_item,
            commands::restore_item,
            commands::delete_items_permanently,
            commands::generate_password,
            commands::password_health,
            commands::check_breaches,
            commands::import_pick,
            commands::import_commit,
            commands::import_cancel,
            commands::export_backup,
            commands::copy_secret_key,
            commands::account_info,
            commands::cancel_account_deletion,
            commands::bridge_pair_respond,
            commands::list_bridge_peers,
            commands::remove_bridge_peer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Keyless");
}
