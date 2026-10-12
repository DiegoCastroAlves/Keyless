//! A key held outside this process's ordinary memory, for the account keys
//! kept while locked (see `system_unlock`): they stay in memory only sealed
//! with this key.
//!
//! - Linux: a "user" key in the kernel keyring of this process. Only this
//!   process can read it (possessor-only permissions), it is not in our
//!   memory (so not in a swap file or a memory dump either), and the kernel
//!   deletes it when its time runs out or the process ends.
//! - Windows: encrypted in place with `CryptProtectMemory` (same process),
//!   whose key the system keeps.
//!
//! Elsewhere, or when the keyring cannot be used (some sandboxes block it),
//! there is no guarded key and nothing is kept: unlocking needs the master
//! password.

use std::time::Duration;

use keyless_core::crypto::{SymmetricKey, random_array};

pub struct GuardedKey {
    #[cfg(target_os = "linux")]
    serial: i32,
    #[cfg(windows)]
    protected: zeroize::Zeroizing<[u8; 32]>,
}

impl GuardedKey {
    /// A new random key, guarded for at most `lifetime`. Returns the guard
    /// and the key itself, to seal with right away.
    pub fn create(lifetime: Duration) -> Option<(GuardedKey, SymmetricKey)> {
        let bytes = random_array::<32>().ok()?;
        let key = SymmetricKey::from_slice(bytes.as_ref()).ok()?;
        let guard = platform::store(&bytes, lifetime)?;
        Some((guard, key))
    }

    /// The key, while it is still guarded (`None` once it expired).
    pub fn key(&self) -> Option<SymmetricKey> {
        let bytes = platform::load(self)?;
        SymmetricKey::from_slice(bytes.as_ref()).ok()
    }
}

impl Drop for GuardedKey {
    fn drop(&mut self) {
        platform::discard(self);
    }
}

/// Whether keys can be guarded here.
pub fn available() -> bool {
    platform::available()
}

/// Sets up what the guard needs. Call at startup, before any other thread is
/// spawned: on Linux the process keyring is attached to the threads that
/// exist when it is made and those created afterwards, so making it first
/// lets every thread reach the keys in it.
pub fn init() {
    platform::init();
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{ffi::CStr, sync::OnceLock, time::Duration};

    use zeroize::Zeroizing;

    use super::GuardedKey;

    // From <linux/keyctl.h>; not in the libc crate.
    const KEY_SPEC_PROCESS_KEYRING: libc::c_long = -2;
    const KEYCTL_GET_KEYRING_ID: libc::c_long = 0;
    const KEYCTL_SETPERM: libc::c_long = 5;
    const KEYCTL_READ: libc::c_long = 11;
    const KEYCTL_SET_TIMEOUT: libc::c_long = 15;
    const KEYCTL_INVALIDATE: libc::c_long = 21;
    /// View, read, write, search, link and set attributes, for the
    /// possessor (this process) only: nothing for the user, group or others.
    const POSSESSOR_ONLY: libc::c_long = 0x3f00_0000;
    const KEY_TYPE: &CStr = c"user";
    const DESCRIPTION: &CStr = c"keyless:kept-keys";

    static READY: OnceLock<bool> = OnceLock::new();

    fn keyctl(operation: libc::c_long, a: libc::c_long, b: libc::c_long, c: libc::c_long) -> libc::c_long {
        // SAFETY: keyctl with integer arguments, or (for KEYCTL_READ) a
        // pointer and length of a buffer the caller owns.
        unsafe { libc::syscall(libc::SYS_keyctl, operation, a, b, c, 0 as libc::c_long) }
    }

    pub fn init() {
        READY.get_or_init(|| {
            // Threads that already exist would not see the keyring (Bitwarden
            // hit this: clients#22449), so it must be made while this is the
            // only one. Tests run on the harness's threads and only use the
            // thread that made it.
            if !cfg!(test) && other_threads() {
                log::warn!("threads were started before the kernel keyring was set up; system unlock is off");
                return false;
            }
            keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 1, 0) >= 0
        });
    }

    fn other_threads() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| status.lines().find_map(|l| l.strip_prefix("Threads:").map(|n| n.trim().to_string())))
            .is_none_or(|n| n != "1")
    }

    pub fn available() -> bool {
        *READY.get_or_init(|| false)
    }

    pub fn store(bytes: &[u8; 32], lifetime: Duration) -> Option<GuardedKey> {
        if !available() {
            return None;
        }
        // SAFETY: valid NUL-terminated strings and a 32-byte buffer.
        let serial = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                KEY_TYPE.as_ptr(),
                DESCRIPTION.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                KEY_SPEC_PROCESS_KEYRING,
            )
        };
        if serial < 0 {
            log::warn!("could not add a key to the kernel keyring: {}", std::io::Error::last_os_error());
            return None;
        }
        let guard = GuardedKey { serial: serial as i32 };
        let seconds = lifetime.as_secs().clamp(1, u32::MAX as u64) as libc::c_long;
        if keyctl(KEYCTL_SET_TIMEOUT, serial, seconds, 0) < 0 || keyctl(KEYCTL_SETPERM, serial, POSSESSOR_ONLY, 0) < 0 {
            log::warn!("could not restrict the kernel keyring key: {}", std::io::Error::last_os_error());
            return None; // dropping the guard invalidates the key
        }
        Some(guard)
    }

    pub fn load(guard: &GuardedKey) -> Option<Zeroizing<[u8; 32]>> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        let read = keyctl(KEYCTL_READ, guard.serial as libc::c_long, bytes.as_mut_ptr() as libc::c_long, bytes.len() as libc::c_long);
        // Expired (EKEYEXPIRED), invalidated or not ours: nothing.
        (read == bytes.len() as libc::c_long).then_some(bytes)
    }

    pub fn discard(guard: &mut GuardedKey) {
        keyctl(KEYCTL_INVALIDATE, guard.serial as libc::c_long, 0, 0);
    }
}

#[cfg(windows)]
mod platform {
    use std::time::Duration;

    use windows_sys::Win32::Security::Cryptography::{
        CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory, CryptUnprotectMemory,
    };
    use zeroize::{Zeroize, Zeroizing};

    use super::GuardedKey;

    pub fn init() {}

    pub fn available() -> bool {
        true
    }

    /// The time limit is enforced by `system_unlock` (the kept keys carry
    /// when the master password was entered).
    pub fn store(bytes: &[u8; 32], _lifetime: Duration) -> Option<GuardedKey> {
        let mut protected = Zeroizing::new(*bytes);
        // SAFETY: a 32-byte buffer we own; the size is a multiple of
        // CRYPTPROTECTMEMORY_BLOCK_SIZE (16).
        let ok = unsafe { CryptProtectMemory(protected.as_mut_ptr().cast(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS) };
        if ok == 0 {
            log::warn!("CryptProtectMemory failed: {}", std::io::Error::last_os_error());
            return None;
        }
        Some(GuardedKey { protected })
    }

    pub fn load(guard: &GuardedKey) -> Option<Zeroizing<[u8; 32]>> {
        let mut bytes = Zeroizing::new(*guard.protected);
        // SAFETY: as above.
        let ok = unsafe { CryptUnprotectMemory(bytes.as_mut_ptr().cast(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS) };
        (ok != 0).then_some(bytes)
    }

    pub fn discard(guard: &mut GuardedKey) {
        guard.protected.zeroize();
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use std::time::Duration;

    use zeroize::Zeroizing;

    use super::GuardedKey;

    pub fn init() {}

    pub fn available() -> bool {
        false
    }

    pub fn store(_bytes: &[u8; 32], _lifetime: Duration) -> Option<GuardedKey> {
        None
    }

    pub fn load(_guard: &GuardedKey) -> Option<Zeroizing<[u8; 32]>> {
        None
    }

    pub fn discard(_guard: &mut GuardedKey) {}
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Talks to the real kernel keyring.
    #[test]
    fn keeps_the_key_until_dropped() {
        init();
        if !available() {
            eprintln!("no kernel keyring here; skipped");
            return;
        }
        let (guard, key) = GuardedKey::create(Duration::from_secs(60)).unwrap();
        let sealed = key.seal(b"user key", b"test").unwrap();
        // Read from another thread made afterwards, as the app's runtime does.
        let opened = std::thread::scope(|s| s.spawn(|| guard.key().unwrap().open(&sealed, b"test").unwrap()).join().unwrap());
        assert_eq!(opened.as_slice(), b"user key");

        let serial = guard.serial;
        drop(guard);
        let stale = GuardedKey { serial };
        assert!(stale.key().is_none());
        std::mem::forget(stale);
    }

    #[test]
    fn expires() {
        init();
        if !available() {
            return;
        }
        let (guard, _) = GuardedKey::create(Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_millis(2100));
        assert!(guard.key().is_none());
    }
}
