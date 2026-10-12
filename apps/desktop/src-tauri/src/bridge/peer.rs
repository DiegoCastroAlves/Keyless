//! Who is on the other end of the bridge socket.
//!
//! The socket is reachable by every program of this user, and the pairing
//! key the extension holds is stored in the browser profile on disk. So
//! besides the end-to-end encryption, the app checks the connecting process,
//! as 1Password's browser helper does:
//!
//! - it must be Keyless itself, started in host mode (same executable, or the
//!   same file contents: AppImages run from a new mount each time);
//! - not being debugged, and (Linux) without libraries forced into it with
//!   `LD_PRELOAD` / `LD_AUDIT` from places the user can write to;
//! - started by a browser: a known browser executable, installed by the
//!   system (owned by root and not writable by others on Linux; signed, or in
//!   Program Files, on Windows). On Linux an administrator can allow more
//!   browsers in `/etc/keyless/allowed_browsers` (owned by root): one
//!   executable name, or full path, per line.
//!
//! This keeps a program that copied the pairing key from talking to the app
//! directly. It cannot stop malware that controls the browser itself.

/// Executable names of the browsers Keyless works with.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
const BROWSERS: &[&str] = &[
    "chrome",
    "chromium",
    "chromium-browser",
    "brave",
    "brave-browser",
    "msedge",
    "vivaldi-bin",
    "opera",
    "thorium",
    "firefox",
    "firefox-bin",
    "firefox-esr",
    "librewolf",
    "waterfox",
    "waterfox-bin",
    "zen",
    "zen-bin",
    "floorp",
];

/// Why a connection was refused. Sent to the extension, which explains it.
pub const NOT_KEYLESS: &str = "untrusted_host";
pub const UNTRUSTED_BROWSER: &str = "untrusted_browser";

#[cfg(target_os = "linux")]
pub use linux::check;

#[cfg(windows)]
pub use windows::check;

#[cfg(all(unix, not(target_os = "linux")))]
pub fn check(_pid: Option<i32>) -> Result<(), &'static str> {
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        sync::OnceLock,
    };

    use sha2::{Digest, Sha256};

    use super::{BROWSERS, NOT_KEYLESS, UNTRUSTED_BROWSER};

    const ALLOWED_BROWSERS_FILE: &str = "/etc/keyless/allowed_browsers";

    /// Checks the process that connected (`pid` from the socket's peer
    /// credentials).
    pub fn check(pid: Option<i32>) -> Result<(), &'static str> {
        let pid = pid.ok_or(NOT_KEYLESS)?;
        if !same_executable(pid) {
            return Err(NOT_KEYLESS);
        }
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|_| NOT_KEYLESS)?;
        if status_field(&status, "TracerPid") != Some(0) || !clean_environment(pid) {
            return Err(NOT_KEYLESS);
        }
        let parent = status_field(&status, "PPid").ok_or(UNTRUSTED_BROWSER)?;
        let browser = executable(parent as i32).ok_or(UNTRUSTED_BROWSER)?;
        if trusted_browser(&browser) { Ok(()) } else { Err(UNTRUSTED_BROWSER) }
    }

    fn status_field(status: &str, name: &str) -> Option<u32> {
        status.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix(':')?.trim().parse().ok())
    }

    /// The executable of a process. A file replaced since it started (an
    /// update) reads as "<path> (deleted)": the path is what counts.
    fn executable(pid: i32) -> Option<PathBuf> {
        let link = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let text = link.to_str()?;
        Some(PathBuf::from(text.strip_suffix(" (deleted)").unwrap_or(text)))
    }

    fn same_executable(pid: i32) -> bool {
        let (Some(ours), Some(theirs)) = (executable(std::process::id() as i32), executable(pid)) else {
            return false;
        };
        if ours == theirs {
            return true;
        }
        // An AppImage is mounted somewhere new on every start: compare the
        // files themselves (still open through /proc even if replaced).
        static OURS: OnceLock<Option<[u8; 32]>> = OnceLock::new();
        let ours = OURS.get_or_init(|| file_hash(Path::new("/proc/self/exe")));
        ours.is_some() && *ours == file_hash(Path::new(&format!("/proc/{pid}/exe")))
    }

    fn file_hash(path: &Path) -> Option<[u8; 32]> {
        use std::io::Read;
        let mut file = std::fs::File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1 << 16];
        loop {
            match file.read(&mut buffer).ok()? {
                0 => return Some(hasher.finalize().into()),
                n => hasher.update(&buffer[..n]),
            }
        }
    }

    /// No code forced into the process from a file the user (or malware
    /// running as the user) could have written.
    fn clean_environment(pid: i32) -> bool {
        let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
            return false;
        };
        environ.split(|&b| b == 0).all(|entry| {
            let Ok(entry) = std::str::from_utf8(entry) else { return true };
            let Some((name, value)) = entry.split_once('=') else { return true };
            if !matches!(name, "LD_PRELOAD" | "LD_AUDIT") {
                return true;
            }
            value
                .split([':', ' '])
                .filter(|lib| !lib.is_empty())
                .all(|lib| lib.starts_with('/') && system_file(Path::new(lib)))
        })
    }

    /// Owned by root and not writable by anyone else, nor is its folder.
    fn system_file(path: &Path) -> bool {
        let owned = |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0);
        owned(path) && path.parent().is_some_and(owned)
    }

    fn trusted_browser(path: &Path) -> bool {
        let extra = allowed_browsers();
        if extra.iter().any(|line| Path::new(line) == path) {
            return true;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        (BROWSERS.contains(&name) || extra.iter().any(|line| line == name)) && system_file(path)
    }

    /// The administrator's list, ignored unless only root can change it.
    fn allowed_browsers() -> Vec<String> {
        let path = Path::new(ALLOWED_BROWSERS_FILE);
        if !system_file(path) {
            return Vec::new();
        }
        std::fs::read_to_string(path)
            .map(|text| {
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn reads_status_fields() {
            let status = "Name:\tkeyless\nPPid:\t4242\nTracerPid:\t0\n";
            assert_eq!(status_field(status, "PPid"), Some(4242));
            assert_eq!(status_field(status, "TracerPid"), Some(0));
            assert_eq!(status_field(status, "Pid"), None);
        }

        #[test]
        fn this_test_binary_is_its_own_executable() {
            assert!(same_executable(std::process::id() as i32));
        }

        #[test]
        fn system_files_and_browsers() {
            assert!(system_file(Path::new("/usr/bin/env")));
            assert!(!system_file(Path::new("/tmp")));
            assert!(!trusted_browser(Path::new("/usr/bin/env")));
            // A browser name in a folder the user owns is not trusted.
            let home = std::env::temp_dir().join("chrome");
            assert!(!trusted_browser(&home));
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::{os::windows::io::AsRawHandle, path::PathBuf};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE},
        Security::WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
            WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
        },
        System::{
            Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS},
            Pipes::GetNamedPipeClientProcessId,
            Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
        },
    };

    use super::{BROWSERS, NOT_KEYLESS, UNTRUSTED_BROWSER};

    struct Process {
        handle: HANDLE,
    }

    impl Process {
        fn open(pid: u32) -> Option<Process> {
            // SAFETY: plain call; a null handle means failure.
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            (!handle.is_null()).then_some(Process { handle })
        }

        fn image(&self) -> Option<PathBuf> {
            let mut buffer = vec![0u16; 32_768];
            let mut len = buffer.len() as u32;
            // SAFETY: the buffer and its length match.
            let ok = unsafe { QueryFullProcessImageNameW(self.handle, 0, buffer.as_mut_ptr(), &mut len) };
            (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buffer[..len as usize])))
        }

        /// Creation time, in 100 ns units.
        fn created(&self) -> Option<u64> {
            let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
            // SAFETY: four FILETIMEs we own.
            let ok = unsafe { GetProcessTimes(self.handle, &mut created, &mut exited, &mut kernel, &mut user) };
            (ok != 0).then_some(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: a handle we opened.
            unsafe { CloseHandle(self.handle) };
        }
    }

    fn parent_pid(pid: u32) -> Option<u32> {
        // SAFETY: snapshot of all processes; closed below.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut found = None;
        // SAFETY: the entry's dwSize is set, as these functions require.
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            if entry.th32ProcessID == pid {
                found = Some(entry.th32ParentProcessID);
                break;
            }
            // SAFETY: as above.
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        // SAFETY: the snapshot handle from above.
        unsafe { CloseHandle(snapshot) };
        found
    }

    fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    }

    fn file_name(path: &std::path::Path) -> String {
        path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default()
    }

    /// The parent that started `child`, if it is still the same process (a
    /// parent id can be reused once the parent exits).
    fn parent_of(child_pid: u32, child: &Process) -> Option<(u32, Process)> {
        let pid = parent_pid(child_pid)?;
        let parent = Process::open(pid)?;
        (parent.created()? <= child.created()?).then_some((pid, parent))
    }

    /// Checks the process at the other end of the pipe.
    pub fn check(pipe: &tokio::net::windows::named_pipe::NamedPipeServer) -> Result<(), &'static str> {
        let mut pid = 0u32;
        // SAFETY: a connected pipe handle we own.
        if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
            return Err(NOT_KEYLESS);
        }
        let host = Process::open(pid).ok_or(NOT_KEYLESS)?;
        let ours = std::env::current_exe().map_err(|_| NOT_KEYLESS)?;
        if !host.image().is_some_and(|image| same_path(&image, &ours)) {
            return Err(NOT_KEYLESS);
        }

        // Chrome and Edge start hosts through cmd.exe: look one level up.
        let (parent_pid, parent) = parent_of(pid, &host).ok_or(UNTRUSTED_BROWSER)?;
        let mut image = parent.image().ok_or(UNTRUSTED_BROWSER)?;
        if file_name(&image) == "cmd.exe" && in_system32(&image) {
            let (_, browser) = parent_of(parent_pid, &parent).ok_or(UNTRUSTED_BROWSER)?;
            image = browser.image().ok_or(UNTRUSTED_BROWSER)?;
        }
        let name = file_name(&image);
        let known = BROWSERS.iter().any(|b| name == format!("{b}.exe"));
        if known && (in_program_files(&image) || signed(&image)) { Ok(()) } else { Err(UNTRUSTED_BROWSER) }
    }

    fn in_system32(path: &std::path::Path) -> bool {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        same_path(path.parent().unwrap_or(path), &PathBuf::from(root).join("System32"))
    }

    /// Installed for all users: only administrators can change it.
    fn in_program_files(path: &std::path::Path) -> bool {
        let lower = path.to_string_lossy().to_lowercase();
        ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
            .iter()
            .filter_map(|var| std::env::var(var).ok())
            .any(|dir| lower.starts_with(&format!("{}\\", dir.to_lowercase().trim_end_matches('\\'))))
    }

    /// A valid Authenticode signature (per-user installs of Chrome and
    /// Edge). No revocation check: that would go to the network.
    fn signed(path: &std::path::Path) -> bool {
        let wide: Vec<u16> = path.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        data.Anonymous.pFile = &mut file;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: the structures are set up as WinVerifyTrust documents, and
        // live until the closing call below.
        let status = unsafe { WinVerifyTrust(INVALID_HANDLE_VALUE, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: releases the state of the call above.
        unsafe { WinVerifyTrust(INVALID_HANDLE_VALUE, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
        status == 0
    }
}
