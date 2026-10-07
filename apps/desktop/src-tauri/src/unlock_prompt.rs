//! Unlocking Keyless when the browser extension asks for it. The computer
//! password is used when it can be; otherwise (turned off, expired, or the
//! user cancelled the system prompt) a small Keyless window asks for the
//! master password. The master password is always typed in Keyless itself,
//! never in the browser, and the main window stays as it was.

use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::oneshot;

use crate::{
    auth,
    error::{AppError, AppResult},
    state::AppState,
    system_unlock,
};

pub const LABEL: &str = "unlock-prompt";

/// Returns once Keyless is unlocked, or `Cancelled` when the user closed the
/// prompt.
pub async fn request(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    if state.session.lock().await.is_some() {
        return Ok(());
    }
    if state.store().account()?.is_none() {
        return Err(AppError::NoAccount);
    }
    if app.get_webview_window(LABEL).is_none() && system_unlock::available(&state) {
        match auth::unlock_with_system(app).await {
            Ok(()) => return Ok(()),
            Err(AppError::Invalid(msg)) if msg.key == "busy" => return Err(AppError::Invalid(msg)),
            // Cancelled, failed or expired meanwhile: the master password is
            // still an option.
            Err(_) => {}
        }
    }
    let (tx, rx) = oneshot::channel();
    state.unlock_prompt.lock().unwrap_or_else(|e| e.into_inner()).push(tx);
    show(app).map_err(|e| AppError::Server(e.to_string()))?;
    match rx.await {
        Ok(true) => Ok(()),
        _ => Err(AppError::Cancelled),
    }
}

fn show(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(LABEL) {
        window.show()?;
        return window.set_focus();
    }
    // Shown by `ready` once its page has rendered, so it never flashes blank.
    WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
        .title("Keyless")
        .inner_size(400.0, 330.0)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .always_on_top(true)
        .disable_drag_drop_handler()
        .center()
        .visible(false)
        .build()?;
    Ok(())
}

/// The prompt's page has rendered.
pub fn ready(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(LABEL) {
        window.show()?;
        // Centered again once mapped, when its real size is known.
        let _ = window.center();
        window.set_focus()?;
    }
    Ok(())
}

pub fn close(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.close();
    }
}

/// The prompt window is gone: unlocked, cancelled or closed by the user.
/// The page is destroyed with it, along with anything typed there.
pub fn closed(app: &AppHandle) {
    let state = app.state::<AppState>();
    let waiters: Vec<_> = state.unlock_prompt.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let unlocked = app.state::<AppState>().session.lock().await.is_some();
        for waiter in waiters {
            let _ = waiter.send(unlocked);
        }
    });
}
