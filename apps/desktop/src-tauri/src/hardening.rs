//! Process hardening applied at startup (release builds only, so debuggers
//! keep working in development).

pub fn apply() {
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    linux();
}

/// - Not dumpable: no core dumps with decrypted data, and other processes of
///   the same user cannot attach with ptrace or read our memory through
///   /proc/<pid>/mem.
/// - Core file size limit 0 as a second line of defence.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn linux() {
    // SAFETY: plain syscalls with constant, valid arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            log::warn!("could not disable core dumps / ptrace");
        }
        let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}
