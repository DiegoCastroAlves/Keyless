//! Storage for the account Secret Key on this device.
//!
//! The Secret Key is kept in the operating system's credential store (Windows
//! Credential Manager, or the Secret Service on Linux — KWallet / GNOME
//! Keyring), which encrypts it with the user's login. If no credential store
//! is available, it falls back to a file readable only by the current user.
//!
//! Either way, the Secret Key alone cannot decrypt anything: the master
//! password is also required.

use std::path::{Path, PathBuf};

use keyless_core::keys::SecretKey;
use zeroize::Zeroizing;

use crate::{
    config::KEYRING_SERVICE,
    error::{AppError, AppResult},
};

pub struct SecretStore {
    fallback_dir: PathBuf,
}

fn entry_name(email: &str) -> String {
    format!("secret-key:{}", email.trim().to_lowercase())
}

impl SecretStore {
    pub fn new(fallback_dir: &Path) -> Self {
        Self { fallback_dir: fallback_dir.to_path_buf() }
    }

    /// Keyless keeps one account per device, so a single fallback file is
    /// enough.
    fn fallback_path(&self, _email: &str) -> PathBuf {
        self.fallback_dir.join("secret-key")
    }

    pub fn save(&self, email: &str, key: &SecretKey) -> AppResult<()> {
        let display = key.to_display();
        match keyring::Entry::new(KEYRING_SERVICE, &entry_name(email)).and_then(|e| e.set_password(&display)) {
            Ok(()) => {
                // Remove any older fallback copy now that the keyring works.
                let _ = std::fs::remove_file(self.fallback_path(email));
                Ok(())
            }
            Err(err) => {
                log::warn!("OS credential store unavailable ({err}); using a protected file instead");
                write_private_file(&self.fallback_path(email), display.as_bytes())
            }
        }
    }

    pub fn load(&self, email: &str) -> AppResult<Option<SecretKey>> {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &entry_name(email)) {
            match entry.get_password() {
                Ok(display) => {
                    let display = Zeroizing::new(display);
                    return Ok(Some(SecretKey::parse(&display)?));
                }
                Err(keyring::Error::NoEntry) => {}
                Err(err) => log::warn!("could not read from the OS credential store: {err}"),
            }
        }
        match std::fs::read_to_string(self.fallback_path(email)) {
            Ok(display) => {
                let display = Zeroizing::new(display);
                Ok(Some(SecretKey::parse(display.trim())?))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(AppError::Store(err.to_string())),
        }
    }

    pub fn delete(&self, email: &str) {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &entry_name(email)) {
            let _ = entry.delete_credential();
        }
        let path = self.fallback_path(email);
        if path.exists() {
            // Overwrite before unlinking; best effort on journaling filesystems.
            if let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) {
                let _ = std::fs::write(&path, vec![0u8; len as usize]);
            }
            let _ = std::fs::remove_file(path);
        }
    }
}

fn write_private_file(path: &Path, contents: &[u8]) -> AppResult<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| AppError::Store(e.to_string()))?;
    file.write_all(contents).map_err(|e| AppError::Store(e.to_string()))?;
    file.sync_all().map_err(|e| AppError::Store(e.to_string()))?;
    Ok(())
}
