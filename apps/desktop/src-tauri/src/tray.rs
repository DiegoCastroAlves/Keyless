//! Tray icon. With "keep running in the tray" on, closing the window hides it
//! and Keyless keeps running (auto-lock, browser extension, Quick Access).

use serde::Deserialize;
use tauri::{
    AppHandle, Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

use crate::{auth, state::AppState};

const TRAY_ID: &str = "keyless";

/// Menu texts, translated by the UI.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayLabels {
    pub open: String,
    pub lock: String,
    pub quit: String,
}

/// Whether the system can show a tray icon. On Linux the icon needs the
/// AppIndicator library, which tray-icon loads on first use and panics
/// without: check first.
fn supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        [
            c"libayatana-appindicator3.so.1",
            c"libappindicator3.so.1",
            c"libayatana-appindicator3.so",
            c"libappindicator3.so",
        ]
        .iter()
        .any(|name| {
            // SAFETY: dlopen/dlclose with a valid NUL-terminated name; the
            // handle is only closed.
            unsafe {
                let handle = libc::dlopen(name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
                if handle.is_null() {
                    false
                } else {
                    libc::dlclose(handle);
                    true
                }
            }
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Creates the tray icon, or updates its menu when the language changes.
pub fn configure(app: &AppHandle, labels: &TrayLabels) -> tauri::Result<()> {
    if !supported() {
        return Err(tauri::Error::AssetNotFound("tray icon library (AppIndicator)".into()));
    }
    let open = MenuItem::with_id(app, "open", &labels.open, true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", &labels.lock, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", &labels.quit, true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &lock, &separator, &quit])?;

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        return tray.set_menu(Some(menu));
    }
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Keyless")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "lock" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { auth::lock(&app).await });
            }
            "quit" => self::quit(app),
            _ => {}
        })
        // A left click opens the window where the platform reports it
        // (Windows); on Linux the menu opens instead.
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Whether the window can hide into the tray instead of closing.
pub fn available(app: &AppHandle) -> bool {
    app.tray_by_id(TRAY_ID).is_some()
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Quits for real (from the tray), clearing a copied secret first.
pub fn quit(app: &AppHandle) {
    app.state::<AppState>().clipboard.clear_now();
    app.exit(0);
}
