//! Unlock with the computer's password ("system unlock").
//!
//! After the vault was unlocked with the master password, locking can keep
//! the account keys in this process's memory (never on disk; the process is
//! not dumpable and cannot be ptraced, see `hardening`) so the next unlock
//! only needs the operating system to confirm the user. On Linux that is a
//! polkit action with `auth_self`: the user's own password (or fingerprint,
//! when the system is set up for it), never cached, and only in the active
//! local session.
//!
//! The kept keys are dropped, so the master password is needed again:
//! - when Keyless quits or the computer restarts (they only live in memory);
//! - when the computer sleeps or hibernates;
//! - `MAX_AGE` after the master password was last entered;
//! - on sign out, or when the setting is turned off.
//!
//! Turning the setting on, showing the Secret Key, changing the master
//! password, exporting a backup and deleting the account always ask for the
//! master password.

use std::time::{Duration, SystemTime};

use keyless_core::account::UnlockedAccount;

use crate::{error::AppResult, state::AppState};

/// polkit action installed by the Linux packages (packaging/linux).
pub const POLKIT_ACTION: &str = "io.github.diegocastroalves.keyless.unlock";
/// The master password is asked again at least this often.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Account keys kept while locked.
pub struct KeptKeys {
    pub user_id: String,
    pub email: String,
    pub account: UnlockedAccount,
    /// When the master password was last entered.
    pub password_at: SystemTime,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LockReason {
    /// The lock button or shortcut.
    User,
    /// No activity for the configured time.
    Idle,
    /// The screen was locked.
    ScreenLock,
    /// The computer is going to sleep or hibernate.
    Sleep,
}

impl LockReason {
    /// Whether the keys may be kept for system unlock after this lock.
    pub fn keeps_keys(self) -> bool {
        !matches!(self, LockReason::Sleep)
    }
}

/// Whether the master password entered at `password_at` still allows system
/// unlock at `now`.
pub fn fresh(password_at: SystemTime, now: SystemTime) -> bool {
    now.duration_since(password_at).is_ok_and(|age| age < MAX_AGE)
}

/// Whether this installation can use system unlock.
pub fn supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        ["/usr/share/polkit-1/actions", "/etc/polkit-1/actions"]
            .iter()
            .any(|dir| std::path::Path::new(dir).join(format!("{POLKIT_ACTION}.policy")).is_file())
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Drops the kept keys (they are wiped from memory on drop).
pub fn forget(state: &AppState) {
    state.kept_keys.lock().unwrap_or_else(|e| e.into_inner()).take();
}

/// Whether the lock screen can offer system unlock right now.
pub fn available(state: &AppState) -> bool {
    let mut kept = state.kept_keys.lock().unwrap_or_else(|e| e.into_inner());
    if kept.as_ref().is_some_and(|k| !fresh(k.password_at, SystemTime::now())) {
        kept.take();
    }
    kept.is_some() && state.settings().system_unlock && supported()
}

/// Asks the operating system to confirm the user. `Ok(false)` when the user
/// cancelled or failed to authenticate.
pub async fn authenticate() -> AppResult<bool> {
    #[cfg(target_os = "linux")]
    {
        linux::authenticate().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(crate::error::AppError::Invalid(crate::error::Msg::new("system_unlock_unavailable")))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;

    use zbus::zvariant::Value;

    use super::POLKIT_ACTION;
    use crate::error::{AppError, AppResult, Msg};

    const ALLOW_USER_INTERACTION: u32 = 1;

    /// polkit CheckAuthorization for this process, identified by its own
    /// system bus connection (race-free, unlike a PID).
    pub async fn authenticate() -> AppResult<bool> {
        let unavailable = |err: zbus::Error| AppError::Invalid(Msg::new("system_unlock_failed").with("detail", err));
        let connection = zbus::Connection::system().await.map_err(unavailable)?;
        let name = connection
            .unique_name()
            .ok_or_else(|| AppError::Invalid(Msg::new("system_unlock_failed").with("detail", "no bus name")))?
            .to_string();
        let mut subject_details: HashMap<&str, Value> = HashMap::new();
        subject_details.insert("name", Value::from(name.as_str()));
        let subject = ("system-bus-name", subject_details);
        let details: HashMap<&str, &str> = HashMap::new();
        let reply = connection
            .call_method(
                Some("org.freedesktop.PolicyKit1"),
                "/org/freedesktop/PolicyKit1/Authority",
                Some("org.freedesktop.PolicyKit1.Authority"),
                "CheckAuthorization",
                &(subject, POLKIT_ACTION, details, ALLOW_USER_INTERACTION, ""),
            )
            .await
            .map_err(unavailable)?;
        let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) =
            reply.body().deserialize().map_err(unavailable)?;
        Ok(authorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Talks to the real polkit; run with `cargo test -- --ignored polkit`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore]
    async fn polkit_call_is_well_formed() {
        match authenticate().await {
            Ok(authorized) => println!("polkit answered: authorized = {authorized}"),
            Err(err) => println!("polkit answered with an error: {err:?}"),
        }
    }

    #[test]
    fn sleep_drops_the_keys() {
        assert!(LockReason::User.keeps_keys());
        assert!(LockReason::Idle.keeps_keys());
        assert!(LockReason::ScreenLock.keeps_keys());
        assert!(!LockReason::Sleep.keeps_keys());
    }

    #[test]
    fn master_password_is_needed_again_after_max_age() {
        let entered = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(fresh(entered, entered));
        assert!(fresh(entered, entered + MAX_AGE - Duration::from_secs(1)));
        assert!(!fresh(entered, entered + MAX_AGE));
        // A clock set backwards does not extend it.
        assert!(!fresh(entered, entered - Duration::from_secs(60)));
    }
}
