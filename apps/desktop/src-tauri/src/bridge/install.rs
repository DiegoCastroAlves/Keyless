//! Registers Keyless as a native messaging host with the installed browsers
//! (current user only), so the extension can reach the app.

use std::path::{Path, PathBuf};

use serde_json::json;

use super::{CHROME_EXTENSION_IDS, FIREFOX_EXTENSION_ID, HOST_NAME};

/// The executable browsers should start. For AppImage builds this is the
/// AppImage file itself, not the temporary mount.
pub fn host_executable() -> Option<PathBuf> {
    if let Some(appimage) = std::env::var_os("APPIMAGE") {
        return Some(PathBuf::from(appimage));
    }
    std::env::current_exe().ok()
}

fn chrome_manifest(exe: &Path) -> String {
    let origins: Vec<String> = CHROME_EXTENSION_IDS.iter().map(|id| format!("chrome-extension://{id}/")).collect();
    serde_json::to_string_pretty(&json!({
        "name": HOST_NAME,
        "description": "Keyless password manager",
        "path": exe,
        "type": "stdio",
        "allowed_origins": origins,
    }))
    .unwrap_or_default()
}

fn firefox_manifest(exe: &Path) -> String {
    serde_json::to_string_pretty(&json!({
        "name": HOST_NAME,
        "description": "Keyless password manager",
        "path": exe,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    }))
    .unwrap_or_default()
}

/// Adds or removes the registrations. Errors are logged, never fatal.
pub fn sync_registration(enabled: bool) {
    let Some(exe) = host_executable() else { return };
    #[cfg(target_os = "linux")]
    linux::apply(enabled, &exe);
    #[cfg(windows)]
    windows::apply(enabled, &exe);
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = (enabled, exe);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;

    use super::{HOST_NAME, chrome_manifest, firefox_manifest};

    /// Chromium-family profile roots, relative to $XDG_CONFIG_HOME (which is
    /// where these browsers look for user-level host manifests).
    const CHROMIUM: &[&str] = &[
        "google-chrome",
        "google-chrome-beta",
        "google-chrome-unstable",
        "chromium",
        "BraveSoftware/Brave-Browser",
        "microsoft-edge",
        "vivaldi",
        "opera",
    ];
    /// Firefox-family roots, relative to $HOME.
    const FIREFOX: &[&str] = &[".mozilla", ".librewolf", ".zen", ".waterfox"];

    pub fn apply(enabled: bool, exe: &Path) {
        let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else { return };
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        let targets = CHROMIUM
            .iter()
            .map(|root| (config.join(root), "NativeMessagingHosts", chrome_manifest(exe)))
            .chain(
                FIREFOX
                    .iter()
                    .map(|root| (home.join(root), "native-messaging-hosts", firefox_manifest(exe))),
            );
        for (root, folder, manifest) in targets {
            if !root.is_dir() {
                continue;
            }
            let path = root.join(folder).join(format!("{HOST_NAME}.json"));
            let result = if enabled {
                std::fs::create_dir_all(root.join(folder)).and_then(|_| std::fs::write(&path, &manifest))
            } else if path.exists() {
                std::fs::remove_file(&path)
            } else {
                Ok(())
            };
            if let Err(err) = result {
                log::warn!("browser registration at {}: {err}", path.display());
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::path::Path;

    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW,
        RegSetValueExW,
    };

    use super::{HOST_NAME, chrome_manifest, firefox_manifest};

    const CHROMIUM_KEYS: &[&str] = &[
        r"Software\Google\Chrome\NativeMessagingHosts",
        r"Software\Chromium\NativeMessagingHosts",
        r"Software\Microsoft\Edge\NativeMessagingHosts",
        r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
        r"Software\Vivaldi\NativeMessagingHosts",
    ];
    const FIREFOX_KEYS: &[&str] = &[r"Software\Mozilla\NativeMessagingHosts"];

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_default_value(subkey: &str, value: &str) -> bool {
        let subkey = wide(subkey);
        let data = wide(value);
        // SAFETY: valid NUL-terminated UTF-16 buffers; the key is closed.
        unsafe {
            let mut key: HKEY = std::ptr::null_mut();
            let status = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            );
            if status != 0 {
                return false;
            }
            let status = RegSetValueExW(key, std::ptr::null(), 0, REG_SZ, data.as_ptr() as *const u8, (data.len() * 2) as u32);
            RegCloseKey(key);
            status == 0
        }
    }

    fn delete_key(subkey: &str) {
        let subkey = wide(subkey);
        // SAFETY: valid NUL-terminated UTF-16 buffer.
        unsafe {
            RegDeleteKeyW(HKEY_CURRENT_USER, subkey.as_ptr());
        }
    }

    pub fn apply(enabled: bool, exe: &Path) {
        let Some(base) = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from) else { return };
        let dir = base.join("Keyless").join("native-messaging");
        let chrome_path = dir.join("chrome.json");
        let firefox_path = dir.join("firefox.json");
        if enabled {
            if std::fs::create_dir_all(&dir).is_err()
                || std::fs::write(&chrome_path, chrome_manifest(exe)).is_err()
                || std::fs::write(&firefox_path, firefox_manifest(exe)).is_err()
            {
                log::warn!("could not write native messaging manifests");
                return;
            }
            for key in CHROMIUM_KEYS {
                set_default_value(&format!(r"{key}\{HOST_NAME}"), &chrome_path.to_string_lossy());
            }
            for key in FIREFOX_KEYS {
                set_default_value(&format!(r"{key}\{HOST_NAME}"), &firefox_path.to_string_lossy());
            }
        } else {
            for key in CHROMIUM_KEYS.iter().chain(FIREFOX_KEYS) {
                delete_key(&format!(r"{key}\{HOST_NAME}"));
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
