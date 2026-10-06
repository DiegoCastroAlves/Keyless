//! Start Keyless when the user logs in (Settings > General): an XDG autostart
//! entry on Linux, the per-user Run key on Windows. Errors are logged, never
//! fatal.

use std::path::Path;

/// Passed by the login entry, so Keyless can start hidden in the tray.
pub const AUTOSTART_ARG: &str = "--autostart";

pub fn sync(enabled: bool) {
    let Some(exe) = crate::bridge::install::host_executable() else { return };
    #[cfg(target_os = "linux")]
    linux::apply(enabled, &exe);
    #[cfg(windows)]
    windows::apply(enabled, &exe);
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = (enabled, exe);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{AUTOSTART_ARG, Path};

    /// Quotes a path for the Exec key of a desktop entry.
    pub fn quote_exec(path: &str) -> String {
        let mut quoted = String::from('"');
        for c in path.chars() {
            if matches!(c, '"' | '`' | '$' | '\\') {
                quoted.push('\\');
            }
            quoted.push(c);
        }
        quoted.push('"');
        quoted
    }

    pub fn entry(exe: &Path) -> String {
        format!(
            "[Desktop Entry]\nType=Application\nName=Keyless\nExec={} {AUTOSTART_ARG}\nIcon=keyless-desktop\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",
            quote_exec(&exe.to_string_lossy())
        )
    }

    pub fn apply(enabled: bool, exe: &Path) {
        let Some(config) = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config")))
        else {
            return;
        };
        let path = config.join("autostart").join("keyless-desktop.desktop");
        let result = if enabled {
            std::fs::create_dir_all(config.join("autostart")).and_then(|_| std::fs::write(&path, entry(exe)))
        } else if path.exists() {
            std::fs::remove_file(&path)
        } else {
            Ok(())
        };
        if let Err(err) = result {
            log::warn!("autostart entry at {}: {err}", path.display());
        }
    }
}

#[cfg(windows)]
mod windows {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ, RegDeleteKeyValueW, RegSetKeyValueW};

    use super::{AUTOSTART_ARG, Path};

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE_NAME: &str = "Keyless";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn apply(enabled: bool, exe: &Path) {
        let key = wide(RUN_KEY);
        let name = wide(VALUE_NAME);
        // SAFETY: valid NUL-terminated UTF-16 buffers that outlive the calls.
        let status = unsafe {
            if enabled {
                let command = wide(&format!("\"{}\" {AUTOSTART_ARG}", exe.display()));
                RegSetKeyValueW(
                    HKEY_CURRENT_USER,
                    key.as_ptr(),
                    name.as_ptr(),
                    REG_SZ,
                    command.as_ptr() as *const _,
                    (command.len() * 2) as u32,
                )
            } else {
                RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr())
            }
        };
        // 2 = ERROR_FILE_NOT_FOUND: nothing to delete.
        if status != 0 && !(status == 2 && !enabled) {
            log::warn!("autostart registry value: error {status}");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux::{entry, quote_exec};

    #[test]
    fn quotes_the_executable_path() {
        assert_eq!(quote_exec("/usr/bin/keyless-desktop"), "\"/usr/bin/keyless-desktop\"");
        assert_eq!(quote_exec("/home/a b/Keyless$1.AppImage"), "\"/home/a b/Keyless\\$1.AppImage\"");
        let entry = entry(std::path::Path::new("/usr/bin/keyless-desktop"));
        assert!(entry.contains("Exec=\"/usr/bin/keyless-desktop\" --autostart\n"));
    }
}
