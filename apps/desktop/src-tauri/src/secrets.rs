//! Device-local secrets: the account Secret Key and the browser bridge key.
//!
//! They are kept in the operating system's credential store (Windows
//! Credential Manager with local-only persistence, or the Secret Service on
//! Linux — KWallet / GNOME Keyring), which encrypts them with the user's
//! login. If no credential store is available, they fall back to files
//! readable only by the current user.
//!
//! The Secret Key alone cannot decrypt anything: the master password is also
//! required.

use std::path::{Path, PathBuf};

use keyless_core::keys::SecretKey;
use zeroize::Zeroizing;

use crate::{
    config::KEYRING_SERVICE,
    error::{AppError, AppResult},
};

const SECRET_KEY: &str = "secret-key";
pub const BRIDGE_KEY: &str = "bridge-key";

pub struct SecretStore {
    fallback_dir: PathBuf,
}

fn entry(name: &str) -> Option<keyring_core::Entry> {
    if keyring::Entry::store_status().is_err() {
        return None;
    }
    #[cfg(windows)]
    {
        // Enterprise persistence (the default) would roam the secret to other
        // machines on domain-joined computers.
        let modifiers = std::collections::HashMap::from([("persistence", "Local")]);
        keyring_core::Entry::new_with_modifiers(KEYRING_SERVICE, name, &modifiers).ok()
    }
    #[cfg(not(windows))]
    {
        keyring_core::Entry::new(KEYRING_SERVICE, name).ok()
    }
}

fn account_entry_name(email: &str) -> String {
    format!("{SECRET_KEY}:{}", email.trim().to_lowercase())
}

impl SecretStore {
    pub fn new(fallback_dir: &Path) -> Self {
        Self { fallback_dir: fallback_dir.to_path_buf() }
    }

    fn fallback_path(&self, name: &str) -> PathBuf {
        // Only one account per device, so the email is not part of the file
        // name.
        let file = if name.starts_with(SECRET_KEY) { SECRET_KEY } else { name };
        self.fallback_dir.join(file)
    }

    /// True when secrets are kept in plain files because no OS credential
    /// store is available.
    pub fn uses_fallback(&self) -> bool {
        self.fallback_path(SECRET_KEY).exists()
    }

    pub fn put(&self, name: &str, value: &str) -> AppResult<()> {
        match entry(name).map(|e| e.set_password(value)) {
            Some(Ok(())) => {
                remove_file_securely(&self.fallback_path(name));
                Ok(())
            }
            other => {
                if let Some(Err(err)) = other {
                    log::warn!("OS credential store unavailable ({err}); using a protected file instead");
                }
                write_private_file(&self.fallback_path(name), value.as_bytes())
            }
        }
    }

    pub fn get(&self, name: &str) -> AppResult<Option<Zeroizing<String>>> {
        if let Some(entry) = entry(name) {
            match entry.get_password() {
                Ok(value) => return Ok(Some(Zeroizing::new(value))),
                Err(keyring_core::Error::NoEntry) => {}
                Err(err) => log::warn!("could not read from the OS credential store: {err}"),
            }
        }
        match std::fs::read_to_string(self.fallback_path(name)) {
            Ok(value) => Ok(Some(Zeroizing::new(value.trim().to_string()))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(AppError::Store(err.to_string())),
        }
    }

    pub fn delete(&self, name: &str) {
        if let Some(entry) = entry(name) {
            let _ = entry.delete_credential();
        }
        remove_file_securely(&self.fallback_path(name));
    }

    pub fn save_secret_key(&self, email: &str, key: &SecretKey) -> AppResult<()> {
        self.put(&account_entry_name(email), &key.to_display())
    }

    pub fn load_secret_key(&self, email: &str) -> AppResult<Option<SecretKey>> {
        match self.get(&account_entry_name(email))? {
            Some(display) => Ok(Some(SecretKey::parse(&display)?)),
            None => Ok(None),
        }
    }

    pub fn delete_secret_key(&self, email: &str) {
        self.delete(&account_entry_name(email));
    }
}

fn remove_file_securely(path: &Path) {
    if path.exists() {
        // Overwrite before unlinking; best effort on journaling filesystems.
        if let Ok(len) = std::fs::metadata(path).map(|m| m.len()) {
            let _ = std::fs::write(path, vec![0u8; len as usize]);
        }
        let _ = std::fs::remove_file(path);
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
