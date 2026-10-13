//! Items opened in windows of their own, kept above the other windows (to
//! read a value while typing it elsewhere). They close when Keyless locks.

use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

/// Labels of item windows: this, then the item's id.
pub const PREFIX: &str = "item-";

/// Opens item `item_id` in its window, or brings that window forward.
pub async fn open(app: &AppHandle, item_id: &str) -> AppResult<()> {
    // Ids are UUIDs; a window label takes only some characters.
    if item_id.is_empty() || !item_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(AppError::NotFound);
    }
    let title = {
        let state = app.state::<AppState>();
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        session.items.get(item_id).map(|i| i.overview.title.clone()).ok_or(AppError::NotFound)?
    };
    let label = format!("{PREFIX}{item_id}");
    if let Some(window) = app.get_webview_window(&label) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return Ok(());
    }
    WebviewWindowBuilder::new(app, &label, WebviewUrl::App("index.html".into()))
        .title(if title.is_empty() { "Keyless".to_string() } else { format!("{title} – Keyless") })
        .inner_size(460.0, 640.0)
        .min_inner_size(380.0, 420.0)
        .always_on_top(true)
        .build()
        .map_err(|e| AppError::Store(e.to_string()))?;
    Ok(())
}

/// Closes every item window (when Keyless locks or signs out).
pub fn close_all(app: &AppHandle) {
    for (label, window) in app.webview_windows() {
        if label.starts_with(PREFIX) {
            let _ = window.destroy();
        }
    }
}
