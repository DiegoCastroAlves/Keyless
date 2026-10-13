//! Unlock with the computer's password ("system unlock").
//!
//! After the vault was unlocked with the master password, locking can keep
//! the user key so the next unlock only needs the operating system to
//! confirm the user. It is kept sealed, with a key held outside this
//! process's ordinary memory (the kernel keyring on Linux, see
//! `guarded_key`): never on disk, and not in a memory dump or swap file
//! either. The rest of the account keys are opened again from the local
//! account with it. The process is also not dumpable and cannot be ptraced
//! (see `hardening`). On Linux that is a
//! polkit action with `auth_self`: the user's own password (or fingerprint,
//! when the system is set up for it), never cached, and only in the active
//! local session. On Windows it is Windows Hello (face, fingerprint or PIN),
//! through the system's user consent prompt.
//!
//! The kept keys are dropped, so the master password is needed again:
//! - when Keyless quits or the computer restarts (they only live in memory,
//!   and the kernel drops the keyring key with the process);
//! - when the computer sleeps or hibernates;
//! - some days after the master password was last entered (one by
//!   default; never, by choice, only for an account with a recovery key);
//! - on sign out, or when the setting is turned off.
//!
//! Turning the setting on, showing the Secret Key, changing the master
//! password, exporting a backup and deleting the account always ask for the
//! master password.

use std::time::{Duration, SystemTime};

use keyless_core::{
    account::{AccountBundle, UnlockedAccount, open_with_user_key},
    crypto::{SymmetricKey, context},
};

use tauri::AppHandle;

use crate::{error::AppResult, guarded_key::GuardedKey, state::AppState};

/// polkit policy file installed by the Linux packages (packaging/linux).
#[cfg(target_os = "linux")]
const POLKIT_POLICY_FILE: &str = "io.github.diegocastroalves.keyless.policy";
/// The action it defines.
#[cfg(target_os = "linux")]
pub const POLKIT_ACTION: &str = "io.github.diegocastroalves.keyless.unlock";
/// How long the master password lets system unlock work, from the setting
/// in days (0: until Keyless quits or the computer sleeps).
pub fn max_age(days: u32) -> Option<Duration> {
    (days != 0).then(|| Duration::from_secs(u64::from(days) * 24 * 60 * 60))
}

/// Account keys kept while locked.
pub struct KeptKeys {
    pub user_id: String,
    pub email: String,
    /// The user key, sealed with `guard`'s key.
    sealed_user_key: String,
    guard: GuardedKey,
    /// When the master password was last entered.
    pub password_at: SystemTime,
}

fn kept_key_context(user_id: &str) -> Vec<u8> {
    context("kept-user-key", &[user_id])
}

impl KeptKeys {
    /// Seals the account's user key for the rest of `max_age`. `None` when
    /// that time is over or no key can be guarded here.
    pub fn keep(user_id: String, email: String, account: &UnlockedAccount, password_at: SystemTime, max_age: Option<Duration>) -> Option<KeptKeys> {
        let age = SystemTime::now().duration_since(password_at).ok()?;
        let left = match max_age {
            Some(max_age) => max_age.checked_sub(age).filter(|left| !left.is_zero())?,
            None => Duration::from_secs(u64::from(u32::MAX)),
        };
        let (guard, key) = GuardedKey::create(left)?;
        let sealed_user_key = key.seal(account.user_key().as_bytes(), &kept_key_context(&user_id)).ok()?;
        Some(KeptKeys { user_id, email, sealed_user_key, guard, password_at })
    }

    /// The account keys again, from the local account's bundle. `None` when
    /// the guarded key expired or the bundle does not open with the kept key.
    pub fn open(&self, bundle: &AccountBundle) -> Option<UnlockedAccount> {
        let key = self.guard.key()?;
        let user_key = key.open(&self.sealed_user_key, &kept_key_context(&self.user_id)).ok()?;
        let user_key = SymmetricKey::from_slice(&user_key).ok()?;
        open_with_user_key(bundle, user_key, &self.user_id).ok()
    }
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
/// unlock at `now`, `max_age` (see [`max_age`]) after it.
pub fn fresh(password_at: SystemTime, now: SystemTime, max_age: Option<Duration>) -> bool {
    now.duration_since(password_at).is_ok_and(|age| max_age.is_none_or(|max_age| age < max_age))
}

/// Whether this installation can use system unlock.
pub fn supported() -> bool {
    crate::guarded_key::available() && os_supported()
}

fn os_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        ["/usr/share/polkit-1/actions", "/etc/polkit-1/actions"]
            .iter()
            .any(|dir| std::path::Path::new(dir).join(POLKIT_POLICY_FILE).is_file())
    }
    #[cfg(windows)]
    {
        hello::supported()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}

/// How the system confirms the user here, for the UI: "computer_password"
/// (polkit) or "windows_hello".
pub fn method() -> &'static str {
    if cfg!(windows) { "windows_hello" } else { "computer_password" }
}

/// Drops the kept keys (they are wiped from memory on drop).
pub fn forget(state: &AppState) {
    state.kept_keys.lock().unwrap_or_else(|e| e.into_inner()).take();
}

/// Whether the lock screen can offer system unlock right now.
pub fn available(state: &AppState) -> bool {
    let mut kept = state.kept_keys.lock().unwrap_or_else(|e| e.into_inner());
    let max_age = max_age(state.settings().master_password_days);
    if kept.as_ref().is_some_and(|k| !fresh(k.password_at, SystemTime::now(), max_age)) {
        kept.take();
    }
    kept.is_some() && state.settings().system_unlock && supported()
}

/// Asks the operating system to confirm the user. `Ok(false)` when the user
/// cancelled or failed to authenticate.
pub async fn authenticate(app: &AppHandle) -> AppResult<bool> {
    #[cfg(target_os = "linux")]
    {
        let _ = app;
        linux::authenticate().await
    }
    #[cfg(windows)]
    {
        hello::authenticate(app).await
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = app;
        Err(crate::error::AppError::Invalid(crate::error::Msg::new("system_unlock_unavailable")))
    }
}

#[cfg(windows)]
mod hello {
    use std::sync::OnceLock;

    use tauri::{AppHandle, Manager};
    use windows::{
        Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability},
        Win32::{Foundation::HWND, System::WinRT::IUserConsentVerifierInterop},
        core::{HSTRING, factory},
    };
    use windows_future::IAsyncOperation;

    use crate::error::{AppError, AppResult, Msg};

    /// Windows Hello is set up for this user (checked once: asking takes a
    /// moment).
    pub fn supported() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            UserConsentVerifier::CheckAvailabilityAsync()
                .and_then(|operation| operation.join())
                .is_ok_and(|availability| availability == UserConsentVerifierAvailability::Available)
        })
    }

    /// The Windows Hello prompt, in front of Keyless's window (the unlock
    /// prompt for the browser, or the main window).
    pub async fn authenticate(app: &AppHandle) -> AppResult<bool> {
        let window = [crate::unlock_prompt::LABEL, "main"]
            .iter()
            .filter_map(|label| app.get_webview_window(label))
            .find(|w| w.is_visible().unwrap_or(false))
            .and_then(|w| w.hwnd().ok())
            .map(|hwnd| hwnd.0 as isize);
        let failed = |e: windows::core::Error| AppError::Invalid(Msg::new("system_unlock_failed").with("detail", e.message()));
        let result = tokio::task::spawn_blocking(move || -> windows::core::Result<UserConsentVerificationResult> {
            let message = HSTRING::from("Keyless");
            let operation: IAsyncOperation<UserConsentVerificationResult> = match window {
                // SAFETY: a window handle of this process, alive while the
                // prompt is shown (the caller waits for it).
                Some(hwnd) => unsafe {
                    factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?.RequestVerificationForWindowAsync(HWND(hwnd as _), &message)?
                },
                None => UserConsentVerifier::RequestVerificationAsync(&message)?,
            };
            operation.join()
        })
        .await
        .map_err(|_| AppError::Invalid(Msg::new("system_unlock_failed")))?
        .map_err(failed)?;
        Ok(result == UserConsentVerificationResult::Verified)
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

    /// The kept user key opens the account again, and only that account's.
    #[cfg(target_os = "linux")]
    #[test]
    fn kept_keys_reopen_the_account() {
        use keyless_core::{account::create_account, keys::KdfParams};
        crate::guarded_key::init();
        if !crate::guarded_key::available() {
            eprintln!("no kernel keyring here; skipped");
            return;
        }
        let kek = SymmetricKey::generate().unwrap();
        let (bundle, account) = create_account(&kek, KdfParams::recommended(), "user-1").unwrap();
        let kept = KeptKeys::keep("user-1".into(), "a@b.c".into(), &account, SystemTime::now(), max_age(1)).unwrap();
        let reopened = kept.open(&bundle).unwrap();
        assert_eq!(reopened.user_key().as_bytes(), account.user_key().as_bytes());
        assert_eq!(reopened.public_key_encoded(), account.public_key_encoded());

        let (other, _) = create_account(&kek, KdfParams::recommended(), "user-2").unwrap();
        assert!(kept.open(&other).is_none());

        // The master password was entered too long ago: nothing is kept.
        let old = SystemTime::now() - Duration::from_secs(24 * 60 * 60 + 1);
        assert!(KeptKeys::keep("user-1".into(), "a@b.c".into(), &account, old, max_age(1)).is_none());
        // Unless it is never asked again.
        assert!(KeptKeys::keep("user-1".into(), "a@b.c".into(), &account, old, None).is_some());
    }

    /// Talks to the real polkit; run with `cargo test -- --ignored polkit`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore]
    async fn polkit_call_is_well_formed() {
        match linux::authenticate().await {
            Ok(authorized) => println!("polkit answered: authorized = {authorized}"),
            Err(err) => println!("polkit answered with an error: {err:?}"),
        }
    }

    /// The file the packages install is the one `supported` looks for, and it
    /// defines the action `authenticate` asks for.
    #[cfg(target_os = "linux")]
    #[test]
    fn checks_for_the_installed_policy() {
        let packaged = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packaging/linux").join(POLKIT_POLICY_FILE);
        let policy = std::fs::read_to_string(&packaged).expect("policy file in packaging/linux");
        assert!(policy.contains(&format!("<action id=\"{POLKIT_ACTION}\">")));
        let config = include_str!("../tauri.conf.json");
        assert!(config.contains(&format!("/usr/share/polkit-1/actions/{POLKIT_POLICY_FILE}")));
        let pkgbuild = include_str!("../../../../packaging/arch/PKGBUILD");
        assert!(pkgbuild.contains(&format!("/usr/share/polkit-1/actions/{POLKIT_POLICY_FILE}")));
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
        let day = max_age(1);
        assert_eq!(day, Some(Duration::from_secs(24 * 60 * 60)));
        assert!(fresh(entered, entered, day));
        assert!(fresh(entered, entered + Duration::from_secs(24 * 60 * 60 - 1), day));
        assert!(!fresh(entered, entered + Duration::from_secs(24 * 60 * 60), day));
        assert!(fresh(entered, entered + Duration::from_secs(29 * 24 * 60 * 60), max_age(30)));
        // Never: until Keyless quits or the computer sleeps.
        assert_eq!(max_age(0), None);
        assert!(fresh(entered, entered + Duration::from_secs(400 * 24 * 60 * 60), None));
        // A clock set backwards does not extend it.
        assert!(!fresh(entered, entered - Duration::from_secs(60), day));
        assert!(!fresh(entered, entered - Duration::from_secs(60), None));
    }
}
