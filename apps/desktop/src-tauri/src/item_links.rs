//! Links to items, `keyless://item/<id>`: copied from an item, followed from
//! notes or the search box, and from anywhere else on the computer (Keyless
//! registers the scheme for the user as it starts). A link only shows the
//! item, once Keyless is unlocked; it can do nothing else.

use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

const PREFIX: &str = "keyless://item/";
/// Tells the main window an item was asked for (taken with [`take`]).
pub const EVENT_ITEM_REQUESTED: &str = "keyless://item-requested";

/// The item a link names, if it is a link to an item.
pub fn item_id(link: &str) -> Option<&str> {
    let head = link.get(..PREFIX.len())?;
    if !head.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let id = link[PREFIX.len()..].trim_end_matches('/');
    (!id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')).then_some(id)
}

/// Keyless was started, or started again, with `args`: when one is a link to
/// an item, the main window shows it. Returns whether there was one.
pub fn handle_args(app: &AppHandle, args: &[String]) -> bool {
    let Some(id) = args.iter().find_map(|a| item_id(a)) else { return false };
    *app.state::<AppState>().item_request.lock().unwrap_or_else(|e| e.into_inner()) = Some(id.to_string());
    crate::tray::show_main(app);
    let _ = app.emit(EVENT_ITEM_REQUESTED, ());
    true
}

/// The item last asked for by a link, once.
pub fn take(state: &AppState) -> Option<String> {
    state.item_request.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// Makes this Keyless the handler of `keyless://` links for the user.
pub fn register() {
    let Some(exe) = crate::bridge::install::host_executable() else { return };
    #[cfg(target_os = "linux")]
    linux::register(&exe);
    #[cfg(windows)]
    windows::register(&exe);
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = exe;
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{path::Path, process::Command};

    const FILE: &str = "keyless-url-handler.desktop";
    const MIME: &str = "x-scheme-handler/keyless";

    pub fn entry(exe: &Path) -> String {
        format!(
            "[Desktop Entry]\nType=Application\nName=Keyless\nExec={} %u\nIcon=keyless-desktop\nTerminal=false\nNoDisplay=true\nMimeType={MIME};\n",
            crate::autostart::linux::quote_exec(&exe.to_string_lossy())
        )
    }

    pub fn register(exe: &Path) {
        let Some(data) = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".local/share")))
        else {
            return;
        };
        let dir = data.join("applications");
        let path = dir.join(FILE);
        let entry = entry(exe);
        if std::fs::read_to_string(&path).is_ok_and(|current| current == entry) && is_default() {
            return;
        }
        if let Err(err) = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, entry)) {
            log::warn!("link handler entry at {}: {err}", path.display());
            return;
        }
        // Without xdg-utils, the desktop may still pick the entry up by its
        // MimeType.
        if let Err(err) = Command::new("xdg-mime").args(["default", FILE, MIME]).status() {
            log::info!("xdg-mime: {err}");
        }
    }

    fn is_default() -> bool {
        Command::new("xdg-mime")
            .args(["query", "default", MIME])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == FILE)
    }
}

#[cfg(windows)]
mod windows {
    use std::path::Path;

    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ, RegSetKeyValueW};

    const KEY: &str = r"Software\Classes\keyless";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set(key: &str, name: Option<&str>, value: &str) -> u32 {
        let key = wide(key);
        let name = name.map(wide);
        let value = wide(value);
        // SAFETY: valid NUL-terminated UTF-16 buffers that outlive the call.
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                REG_SZ,
                value.as_ptr() as *const _,
                (value.len() * 2) as u32,
            )
        }
    }

    pub fn register(exe: &Path) {
        let command = format!("\"{}\" \"%1\"", exe.display());
        for (key, name, value) in [
            (KEY.to_string(), None, "URL:Keyless"),
            (KEY.to_string(), Some("URL Protocol"), ""),
            (format!(r"{KEY}\shell\open\command"), None, command.as_str()),
        ] {
            let status = set(&key, name, value);
            if status != 0 {
                log::warn!("link handler registry value: error {status}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::item_id;

    #[test]
    fn item_links() {
        assert_eq!(item_id("keyless://item/0f8c2a1e-4b7d-4c3a-9e2f-1a2b3c4d5e6f"), Some("0f8c2a1e-4b7d-4c3a-9e2f-1a2b3c4d5e6f"));
        assert_eq!(item_id("KEYLESS://item/abc-123/"), Some("abc-123"));
        assert_eq!(item_id("keyless://item/"), None);
        assert_eq!(item_id("keyless://item/../etc"), None);
        assert_eq!(item_id("keyless://item/a?b=c"), None);
        assert_eq!(item_id("keyless://vault/abc"), None);
        assert_eq!(item_id("https://keyless.example/item/abc"), None);
        assert_eq!(item_id("--show"), None);
    }
}
