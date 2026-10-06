//! Quick Access: a small window to find an item and copy or open it from any
//! app. It opens with a global shortcut:
//! - KDE: the packages install a default (Ctrl+Shift+Space) through
//!   share/kglobalaccel, changeable in System Settings > Shortcuts;
//! - other Linux desktops: a custom shortcut running `keyless-desktop
//!   --quick-access` (Wayland does not let apps grab keys themselves);
//! - Windows: registered by the app (Settings > General).

use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::state::AppState;

pub const LABEL: &str = "quick-access";
pub const ARG: &str = "--quick-access";
pub const EVENT_OPENED: &str = "keyless://quick-access-opened";
pub const EVENT_SELECT_ITEM: &str = "keyless://select-item";
/// Some compositors report a focus loss while the window is being mapped.
const BLUR_GRACE: Duration = Duration::from_millis(400);

/// Shows Quick Access. The first time, the window is created hidden and only
/// shown once its page reports it is ready (`ready`), so it never flashes
/// blank; afterwards it stays loaded and opens instantly.
pub fn show(app: &AppHandle) -> tauri::Result<()> {
    let state = app.state::<AppState>();
    let window = match app.get_webview_window(LABEL) {
        Some(window) => window,
        None => WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
            .title("Keyless")
            .inner_size(640.0, 440.0)
            .resizable(false)
            .decorations(false)
            .always_on_top(true)
            .skip_taskbar(true)
            .disable_drag_drop_handler()
            .center()
            .visible(false)
            .build()?,
    };
    if !state.quick_access_ready.load(Ordering::SeqCst) {
        state.quick_access_pending.store(true, Ordering::SeqCst);
        return Ok(());
    }
    *state.quick_access_shown.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    let _ = window.center();
    window.show()?;
    // Centered again once mapped: the first time its size is only known now.
    let _ = window.center();
    window.set_focus()?;
    let _ = app.emit_to(LABEL, EVENT_OPENED, ());
    Ok(())
}

/// The page finished loading: show the window if it was asked for meanwhile.
pub fn ready(app: &AppHandle) -> tauri::Result<()> {
    let state = app.state::<AppState>();
    state.quick_access_ready.store(true, Ordering::SeqCst);
    if state.quick_access_pending.swap(false, Ordering::SeqCst) {
        show(app)?;
    }
    Ok(())
}

pub fn hide(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.hide();
    }
}

/// Closes when another window takes the focus, like a menu.
pub fn on_blur(app: &AppHandle) {
    let shown = *app.state::<AppState>().quick_access_shown.lock().unwrap_or_else(|e| e.into_inner());
    if shown.is_none_or(|at| at.elapsed() > BLUR_GRACE) {
        hide(app);
    }
}

/// Shows an item in the main window.
pub fn show_item(app: &AppHandle, item_id: &str) {
    hide(app);
    crate::tray::show_main(app);
    let _ = app.emit_to("main", EVENT_SELECT_ITEM, item_id);
}

/// The Windows shortcut, registered by the app itself.
#[cfg(windows)]
pub fn register_shortcut(app: &AppHandle, shortcut: &str) -> AppResult<()> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
    let manager = app.global_shortcut();
    let _ = manager.unregister_all();
    if shortcut.trim().is_empty() {
        return Ok(());
    }
    manager
        .on_shortcut(shortcut, |app, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                let _ = show(app);
            }
        })
        .map_err(|e| crate::error::AppError::Invalid(crate::error::Msg::new("shortcut_invalid").with("detail", e)))
}

#[cfg(windows)]
use crate::error::AppResult;
