//! Device-local secrets: the account Secret Key and the browser bridge key.
//!
//! They are kept in the operating system's credential store (Windows
//! Credential Manager with local-only persistence, or the Secret Service on
//! Linux — KWallet / GNOME Keyring), which encrypts them with the user's
//! login. If no credential store is available, or it refuses to save them,
//! they fall back to files readable only by the current user, and move into
//! the credential store as soon as it works again.
//!
//! A credential store that is there but fails (it is still starting at
//! login, for example) is asked again a few times, and never taken to mean
//! "no secret saved".
//!
//! The Secret Key alone cannot decrypt anything: the master password is also
//! required.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use keyless_core::keys::SecretKey;
use zeroize::Zeroizing;

use crate::{
    config::KEYRING_SERVICE,
    error::{AppError, AppResult},
};

const SECRET_KEY: &str = "secret-key";
pub const BRIDGE_KEY: &str = "bridge-key";
/// Waits between attempts when the credential store fails.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(250), Duration::from_millis(750)];
/// The credential store kept failing in this run: later calls try once.
static STORE_FAILING: AtomicBool = AtomicBool::new(false);

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

/// Runs a credential store call, again after a short wait while it fails
/// with a platform error (D-Bus or service trouble). Access denied or a
/// locked store is not retried: that would prompt the user again.
fn with_retries<T>(call: impl Fn() -> keyring_core::Result<T>) -> keyring_core::Result<T> {
    let mut result = call();
    if !STORE_FAILING.load(Ordering::Relaxed) {
        for delay in RETRY_DELAYS {
            if !matches!(result, Err(keyring_core::Error::PlatformFailure(_))) {
                break;
            }
            std::thread::sleep(delay);
            result = call();
        }
    }
    STORE_FAILING.store(matches!(result, Err(keyring_core::Error::PlatformFailure(_))), Ordering::Relaxed);
    result
}

fn unavailable(err: keyring_core::Error) -> AppError {
    AppError::Invalid(crate::error::Msg::new("keyring_unavailable").with("detail", err))
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
        match entry(name).map(|e| with_retries(|| e.set_password(value))) {
            Some(Ok(())) => {
                remove_file_securely(&self.fallback_path(name));
                Ok(())
            }
            other => {
                if let Some(Err(err)) = other {
                    log::warn!("OS credential store unavailable ({err}); using a protected file until it works again");
                }
                write_private_file(&self.fallback_path(name), value.as_bytes())
            }
        }
    }

    /// The saved value. An error (`keyring_unavailable`) when the credential
    /// store fails and there is no fallback file: the secret may well be in
    /// the store, so this must not be taken as "nothing saved".
    pub fn get(&self, name: &str) -> AppResult<Option<Zeroizing<String>>> {
        // A fallback file is always the newest value (`put` removes it once
        // the store took one), even when the store still has an older one.
        if let Some(value) = self.read_fallback(name)? {
            if let Some(entry) = entry(name) {
                self.move_into_store(&entry, name, &value);
            }
            return Ok(Some(value));
        }
        let Some(entry) = entry(name) else {
            return Ok(None);
        };
        match with_retries(|| entry.get_password()) {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => {
                log::warn!("could not read from the OS credential store: {err}");
                Err(unavailable(err))
            }
        }
    }

    fn read_fallback(&self, name: &str) -> AppResult<Option<Zeroizing<String>>> {
        match std::fs::read_to_string(self.fallback_path(name)) {
            Ok(value) => Ok(Some(Zeroizing::new(value.trim().to_string()))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(AppError::Store(err.to_string())),
        }
    }

    /// A secret that had to go to a file, now that the credential store
    /// answers: saved there (tried once per run, so a refusal is not asked
    /// again at every unlock), and the file removed once it reads back.
    fn move_into_store(&self, entry: &keyring_core::Entry, name: &str, value: &str) {
        static TRIED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        {
            let mut tried = TRIED.lock().unwrap_or_else(|e| e.into_inner());
            if tried.iter().any(|n| n == name) {
                return;
            }
            tried.push(name.to_string());
        }
        // The file goes only once the store gives the same value back.
        let stored = with_retries(|| entry.set_password(value)).and_then(|()| entry.get_password()).map(Zeroizing::new);
        match stored {
            Ok(read) if read.as_str() == value => remove_file_securely(&self.fallback_path(name)),
            Ok(_) => log::warn!("the OS credential store gave back a different secret; the file stays"),
            Err(err) => log::warn!("could not move a secret into the OS credential store: {err}"),
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
    #[cfg(windows)]
    crate::win_security::restrict_file(path);
    file.write_all(contents).map_err(|e| AppError::Store(e.to_string()))?;
    file.sync_all().map_err(|e| AppError::Store(e.to_string()))?;
    Ok(())
}
