//! Keyless desktop app (Tauri).
//!
//! All cryptography and secret handling happens in Rust; the web UI only
//! renders what these commands return.

mod api;
mod attachments;
mod auth;
mod autostart;
mod bridge;
mod clipboard;
mod commands;
mod config;
mod error;
mod generator_history;
mod hardening;
mod health;
mod import;
mod item_versions;
mod items;
mod lock;
mod oauth;
mod qr;
mod shares;
mod quick_access;
mod secrets;
mod site_icons;
mod ssh_agent;
mod ssh_keys;
mod state;
mod store;
mod sync;
mod system_unlock;
mod tray;
mod unlock_prompt;
mod updates;

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

/// WebKitGTK's DMA-BUF renderer crashes on some drivers, notably NVIDIA under
/// Wayland ("Error 71 (Protocol error) dispatching to Wayland display"). The
/// UI is simple enough not to need it. A value set by the user wins.
#[cfg(target_os = "linux")]
fn disable_webkit_dmabuf_renderer() {
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        // SAFETY: runs at startup, before any other thread is spawned.
        unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
    }
}

pub fn run() {
    // Started by a browser for the extension: relay messages, no window.
    let args: Vec<String> = std::env::args().collect();
    if bridge::host::is_host_invocation(&args) {
        bridge::host::run();
        return;
    }
    hardening::apply();
    #[cfg(target_os = "linux")]
    disable_webkit_dmabuf_renderer();

    let quick_access_requested = args.iter().any(|a| a == quick_access::ARG);
    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_global_shortcut::Builder::new().build());
    builder
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Launched again: a shortcut asking for Quick Access, or the app
            // opened from the menu.
            if args.iter().any(|a| a == quick_access::ARG) {
                if let Err(err) = quick_access::show(app) {
                    log::warn!("could not open Quick Access: {err}");
                }
            } else {
                tray::show_main(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(navigation_guard())
        .setup(move |app| {
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let store = Store::open(&data_dir.join("keyless.db"))?;
            let settings: Settings = store.setting::<Settings>("settings")?.unwrap_or_default().sanitized();
            let throttle: UnlockThrottle = store.setting("unlock_throttle")?.unwrap_or_default();
            let secrets = SecretStore::new(&data_dir);
            let bridge_secret = load_or_create_bridge_key(&secrets)?;
            let browser_integration = settings.browser_integration;
            let start_at_login = settings.start_at_login;
            let start_hidden = quick_access_requested
                || (settings.start_minimized && std::env::args().any(|a| a == autostart::AUTOSTART_ARG));
            #[cfg(windows)]
            let quick_access_shortcut = settings.quick_access_shortcut.clone();

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
                google_cancel: Mutex::new(None),
                pending_google: tokio::sync::Mutex::new(None),
                update: Mutex::new(None),
                update_busy: std::sync::atomic::AtomicBool::new(false),
                kept_keys: Mutex::new(None),
                password_at: Mutex::new(None),
                quick_access_shown: Mutex::new(None),
                quick_access_ready: std::sync::atomic::AtomicBool::new(false),
                quick_access_pending: std::sync::atomic::AtomicBool::new(false),
                unlock_prompt: Mutex::new(Vec::new()),
                lock_state: tokio::sync::watch::Sender::new(true),
                ssh: Default::default(),
                watchtower: Default::default(),
                unlock_reason: Default::default(),
            });

            lock::start(app.handle().clone());
            sync::start_background_sync(app.handle().clone());
            bridge::server::start(app.handle().clone());
            ssh_agent::init(app.handle());
            health::init(app.handle());
            updates::start(app.handle().clone());
            std::thread::spawn(move || bridge::install::sync_registration(browser_integration));
            if start_at_login {
                // Keeps the login entry pointing at this executable (e.g. a moved AppImage).
                std::thread::spawn(|| autostart::sync(true));
            }
            // The window is created hidden (tauri.conf.json): shown unless
            // Keyless was started at login to stay in the tray.
            if !start_hidden {
                tray::show_main(app.handle());
            }
            if quick_access_requested && let Err(err) = quick_access::show(app.handle()) {
                log::warn!("could not open Quick Access: {err}");
            }
            #[cfg(windows)]
            if let Err(err) = quick_access::register_shortcut(app.handle(), &quick_access_shortcut) {
                log::warn!("Quick Access shortcut: {err}");
            }

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
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::Focused(false) if window.label() == quick_access::LABEL => {
                quick_access::on_blur(window.app_handle());
            }
            tauri::WindowEvent::CloseRequested { api, .. } if window.label() == quick_access::LABEL => {
                api.prevent_close();
                quick_access::hide(window.app_handle());
            }
            tauri::WindowEvent::CloseRequested { api, .. } if window.label() == "main" => {
                let app = window.app_handle();
                if app.state::<AppState>().settings().close_to_tray && tray::available(app) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            tauri::WindowEvent::Destroyed if window.label() == ssh_agent::LABEL => {
                ssh_agent::closed(window.app_handle());
            }
            tauri::WindowEvent::Destroyed if window.label() == unlock_prompt::LABEL => {
                unlock_prompt::closed(window.app_handle());
            }
            tauri::WindowEvent::Destroyed if window.label() == "main" => {
                let app = window.app_handle();
                app.state::<AppState>().clipboard.clear_now();
                app.exit(0);
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::create_account,
            commands::sign_in_with_google,
            commands::cancel_google_sign_in,
            commands::create_account_with_google,
            commands::sign_in,
            commands::unlock,
            commands::unlock_with_system,
            commands::set_system_unlock,
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
            commands::item_versions,
            commands::reveal_version_field,
            commands::restore_item_version,
            commands::remember_generated,
            commands::generator_history,
            commands::delete_generated,
            commands::password_health,
            commands::check_breaches,
            commands::last_breaches,
            commands::import_pick,
            commands::import_commit,
            commands::import_cancel,
            commands::export_backup,
            commands::export_plain,
            commands::ssh_generate_key,
            commands::delete_passkey,
            commands::attachment_add,
            commands::attachment_save,
            commands::attachment_delete,
            commands::attachment_space,
            commands::share_create,
            commands::share_list,
            commands::share_revoke,
            commands::set_watchtower_ignored,
            commands::ssh_import_key,
            commands::ssh_request,
            commands::ssh_request_ready,
            commands::ssh_answer,
            commands::ssh_agent_info,
            commands::ssh_close,
            commands::unlock_prompt_reason,
            commands::copy_secret_key,
            commands::account_info,
            commands::cancel_account_deletion,
            commands::version_info,
            commands::configure_tray,
            commands::move_items,
            commands::move_vault_items,
            commands::show_quick_access,
            commands::hide_quick_access,
            commands::quick_access_ready,
            commands::site_icons,
            commands::scan_qr,
            commands::unlock_prompt_ready,
            commands::close_unlock_prompt,
            commands::show_item_in_app,
            commands::set_quick_access_shortcut,
            commands::check_for_updates,
            commands::open_update_page,
            commands::install_update,
            commands::bridge_pair_respond,
            commands::list_bridge_peers,
            commands::remove_bridge_peer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Keyless");
}
