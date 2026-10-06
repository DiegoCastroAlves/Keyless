//! Clipboard with automatic clearing.
//!
//! Copied secrets are marked so clipboard managers skip them (KDE Klipper via
//! `x-kde-passwordManagerHint`, Windows clipboard history and cloud sync), and
//! are cleared after a timeout, but only if the clipboard still holds what
//! Keyless put there.

use std::{
    sync::Mutex,
    time::Duration,
};

use zeroize::Zeroizing;

use crate::error::{AppError, AppResult, Msg};

#[derive(Default)]
pub struct ClipboardGuard {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Kept alive: on X11 the clipboard owner must stay around to serve the
    /// contents.
    clipboard: Option<arboard::Clipboard>,
    /// What we last copied, to avoid clearing something the user copied
    /// afterwards.
    last: Option<Zeroizing<String>>,
    generation: u64,
}

impl ClipboardGuard {
    /// Copies `text` and returns a generation number for [`Self::clear_if`].
    pub fn copy(&self, text: Zeroizing<String>, sensitive: bool) -> AppResult<u64> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.clipboard.is_none() {
            inner.clipboard = Some(arboard::Clipboard::new().map_err(|e| AppError::Invalid(Msg::new("clipboard_unavailable").with("detail", e)))?);
        }
        let clipboard = inner.clipboard.as_mut().expect("initialized above");
        let set = clipboard.set();
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
        let set = if sensitive {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        } else {
            set
        };
        #[cfg(target_os = "windows")]
        let set = if sensitive {
            use arboard::SetExtWindows;
            set.exclude_from_history().exclude_from_cloud()
        } else {
            set
        };
        #[cfg(target_os = "macos")]
        let _ = sensitive;
        set.text(text.as_str())
            .map_err(|e| AppError::Invalid(Msg::new("clipboard_failed").with("detail", e)))?;
        inner.generation += 1;
        inner.last = Some(text);
        Ok(inner.generation)
    }

    /// Clears the clipboard if it still contains what copy `generation` put
    /// there.
    pub fn clear_if(&self, generation: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.generation != generation {
            return;
        }
        Self::clear_locked(&mut inner);
    }

    /// Clears the clipboard if it still contains anything Keyless copied.
    pub fn clear_now(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::clear_locked(&mut inner);
    }

    fn clear_locked(inner: &mut Inner) {
        let Some(last) = inner.last.take() else { return };
        let Some(clipboard) = inner.clipboard.as_mut() else { return };
        let current = clipboard.get_text().ok().map(Zeroizing::new);
        if current.as_deref().map(|c| c.as_str()) == Some(last.as_str()) {
            let _ = clipboard.clear();
        }
    }
}

pub fn schedule_clear(app: tauri::AppHandle, generation: u64, after: Duration) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(after).await;
        use tauri::Manager;
        if let Some(state) = app.try_state::<crate::state::AppState>() {
            state.clipboard.clear_if(generation);
        }
    });
}
