//! The main window. It is made when it is first shown (not at all while
//! Keyless only waits in the tray), and hidden in the tray after that.
//!
//! On Linux its page is ended there too: WebKitGTK keeps a web process of
//! some 75 MiB for it. Destroying the window would not free it (WebKitGTK
//! keeps the process, and a new one starts on every opening), so the window
//! stays, keeping its size and place, and only its process ends; the page
//! loads again, in a moment, when it opens (see `show`).
//!
//! Events that need the window (an item to show, a new item from the browser
//! extension, a browser asking to pair) open it, and wait in a queue until
//! its page has its listeners and says so (`ready`). What the page loads by
//! itself when it starts (the items, the status, an update) is not queued.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::state::AppState;

pub const LABEL: &str = "main";
/// Shown anyway when its page has not said it is ready by then.
const SHOW_ANYWAY: Duration = Duration::from_secs(4);

#[derive(Default)]
pub struct MainState {
    /// Its page has its listeners (see `ready`).
    ready: AtomicBool,
    /// Asked to show while its page was loading.
    show_when_ready: AtomicBool,
    /// Its page was ended in the tray (Linux): it loads again when shown.
    ended: AtomicBool,
    /// Events for it, until its page is ready.
    queue: Mutex<Vec<(String, Value)>>,
}

/// Shows the main window: made first when it is not there, its page loaded
/// again when it was ended in the tray.
pub fn show(app: &AppHandle) {
    let state = app.state::<AppState>();
    match app.get_webview_window(LABEL) {
        Some(window) if state.main.ready.load(Ordering::SeqCst) => present(&window),
        Some(window) => {
            state.main.show_when_ready.store(true, Ordering::SeqCst);
            if state.main.ended.swap(false, Ordering::SeqCst) {
                reload(&window);
                show_anyway_later(app);
            }
        }
        None => {
            state.main.show_when_ready.store(true, Ordering::SeqCst);
            if let Err(err) = build(app) {
                log::warn!("could not open the window: {err}");
            }
        }
    }
}

fn present(window: &WebviewWindow) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

/// Makes the window, hidden until its page is ready.
fn build(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let window = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
        .title("Keyless")
        .inner_size(1180.0, 760.0)
        .min_inner_size(880.0, 560.0)
        .center()
        .visible(false)
        .build()?;
    crate::apply_zoom(app, app.state::<AppState>().settings().zoom);
    show_anyway_later(app);
    Ok(window)
}

/// Shows the window after a while even when its page never says it is
/// ready (it failed to load: better a window than none).
fn show_anyway_later(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SHOW_ANYWAY).await;
        let state = app.state::<AppState>();
        if !state.main.ready.load(Ordering::SeqCst)
            && state.main.show_when_ready.swap(false, Ordering::SeqCst)
            && let Some(window) = app.get_webview_window(LABEL)
        {
            present(&window);
        }
    });
}

/// Sends `event` to the main window, opening it for it: at once when its
/// page is ready, otherwise once it is.
pub fn deliver(app: &AppHandle, event: &str, payload: Value) {
    let state = app.state::<AppState>();
    if state.main.ready.load(Ordering::SeqCst) && app.get_webview_window(LABEL).is_some() {
        let _ = app.emit_to(LABEL, event, payload);
    } else {
        state.main.queue.lock().unwrap_or_else(|e| e.into_inner()).push((event.to_string(), payload));
    }
    show(app);
}

/// Its page has its listeners (it says so once it starts): the events
/// waiting for it go to it, and it shows if it was asked to.
pub fn ready(app: &AppHandle) {
    let state = app.state::<AppState>();
    state.main.ready.store(true, Ordering::SeqCst);
    let waiting = std::mem::take(&mut *state.main.queue.lock().unwrap_or_else(|e| e.into_inner()));
    for (event, payload) in waiting {
        let _ = app.emit_to(LABEL, &event, payload);
    }
    if state.main.show_when_ready.swap(false, Ordering::SeqCst)
        && let Some(window) = app.get_webview_window(LABEL)
    {
        present(&window);
    }
}

/// To the tray: hidden, and on Linux its page ended (see the top).
pub fn close_to_tray(window: &WebviewWindow) {
    let _ = window.hide();
    #[cfg(target_os = "linux")]
    {
        let state = window.app_handle().state::<AppState>();
        state.main.ready.store(false, Ordering::SeqCst);
        state.main.ended.store(true, Ordering::SeqCst);
        end_page(window);
    }
}

/// Ends a hidden window's web process (Linux): its memory goes back to the
/// system; `reload` starts it again.
#[cfg(target_os = "linux")]
pub fn end_page(window: &WebviewWindow) {
    use webkit2gtk::WebViewExt;
    if let Err(err) = window.with_webview(|webview| webview.inner().terminate_web_process()) {
        log::warn!("could not end the window's page: {err}");
    }
}

/// Loads a window's page again, after `end_page`.
pub fn reload(window: &WebviewWindow) {
    #[cfg(target_os = "linux")]
    {
        use webkit2gtk::WebViewExt;
        if let Err(err) = window.with_webview(|webview| webview.inner().reload()) {
            log::warn!("could not load the window again: {err}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = window.eval("location.reload()");
}

/// Keyless keeps running with no window open: in the tray.
pub fn keeps_running(app: &AppHandle) -> bool {
    app.state::<AppState>().settings().close_to_tray && crate::tray::available(app)
}
