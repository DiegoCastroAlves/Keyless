//! Process hardening applied at startup (release builds only, so debuggers
//! keep working in development).

pub fn apply() {
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    linux();
    // Compiled in every build so it is always checked; applied in release.
    #[cfg(windows)]
    if !cfg!(debug_assertions) {
        windows();
    }
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

/// - No crash reports or dumps (Windows Error Reporting) that would hold
///   decrypted data, and no crash dialog.
/// - DLLs are not loaded from the current folder, from network shares or
///   from low-integrity (sandboxed, downloaded) files.
///
/// Memory reading by other programs of the same user is not blocked the way
/// PR_SET_DUMPABLE does on Linux: a stricter process ACL made Bitwarden
/// crash on Windows 11 24H2 (clients#20876), so it is not used here.
#[cfg(windows)]
fn windows() {
    use windows_sys::Win32::System::{
        Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode},
        ErrorReporting::WerAddExcludedApplication,
        LibraryLoader::SetDllDirectoryW,
        SystemServices::PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
        Threading::{ProcessImageLoadPolicy, SetProcessMitigationPolicy},
    };

    /// NoRemoteImages | NoLowMandatoryLabelImages.
    const IMAGE_LOAD_FLAGS: u32 = 0b11;

    let name: Option<Vec<u16>> = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.file_name().map(|n| n.to_string_lossy().encode_utf16().chain(Some(0)).collect()));
    let mut policy = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    policy.Anonymous.Flags = IMAGE_LOAD_FLAGS;
    let empty = [0u16];
    // SAFETY: plain calls with valid, NUL-terminated strings and a policy
    // structure of the size given.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        if let Some(name) = &name
            && WerAddExcludedApplication(name.as_ptr(), 0) < 0
        {
            log::warn!("could not exclude Keyless from Windows Error Reporting");
        }
        SetDllDirectoryW(empty.as_ptr());
        if SetProcessMitigationPolicy(ProcessImageLoadPolicy, (&policy as *const PROCESS_MITIGATION_IMAGE_LOAD_POLICY).cast(), size_of_val(&policy)) == 0 {
            log::warn!("could not restrict where DLLs are loaded from");
        }
    }
}
