//! Who is on the other end of the bridge socket.
//!
//! The socket is reachable by every program of this user, and the pairing
//! key the extension holds is stored in the browser profile on disk. So
//! besides the end-to-end encryption, the app checks the connecting process,
//! as 1Password's browser helper does:
//!
//! - it must be Keyless itself, started in host mode (same executable, or the
//!   same file contents: AppImages run from a new mount each time);
//! - on Linux: not being debugged, and with no code from anywhere else: every
//!   executable mapping comes from a system file (owned by root, not writable
//!   by others) or, for a Keyless that is not installed system-wide, from its
//!   own folder, and there is no anonymous executable memory (where injected
//!   code would live); `LD_PRELOAD` / `LD_AUDIT` may only name system files;
//! - started by a browser: a known browser executable installed by the system
//!   (owned by root on Linux; in Program Files, or signed by the browser's
//!   publisher, on Windows). On Linux an administrator can allow more browsers
//!   in `/etc/keyless/allowed_browsers` (owned by root): one executable name,
//!   or full path, per line.
//! - or by another browser installed by the system (on Linux, a Chromium or
//!   Firefox build owned by root; on Windows, in Program Files) that the user
//!   allowed in the app: it asks the first time (`UNKNOWN_BROWSER`).
//!
//! This is checked once, when the host connects. It turns away programs that
//! copied the pairing key and talk to the socket themselves, but not malware
//! that runs a real browser and a real Keyless host under its control (see
//! SECURITY.md, "Accepted limitations").

/// Executable names of the browsers Keyless works with (Linux, and Windows
/// with ".exe").
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
const BROWSERS: &[&str] = &[
    "chrome",
    "chromium",
    "chromium-browser",
    "brave",
    "brave-browser",
    "msedge",
    "vivaldi",
    "vivaldi-bin",
    "opera",
    "thorium",
    "norte",
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
/// A browser installed by the system that Keyless does not know, and the
/// user has not allowed (yet): the app asks.
pub const UNKNOWN_BROWSER: &str = "unknown_browser";

/// Why a connection was refused.
#[derive(Debug)]
pub struct Refusal {
    pub code: &'static str,
    /// The browser to ask the user about (`UNKNOWN_BROWSER`).
    pub browser: Option<std::path::PathBuf>,
}

impl From<&'static str> for Refusal {
    fn from(code: &'static str) -> Self {
        Self { code, browser: None }
    }
}

#[cfg(target_os = "linux")]
pub use linux::check;

#[cfg(windows)]
pub use windows::{check, client_pid};

#[cfg(all(unix, not(target_os = "linux")))]
pub fn check(_pid: Option<i32>, _allowed: &[std::path::PathBuf]) -> Result<(), Refusal> {
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::HashSet,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };

    use sha2::{Digest, Sha256};

    use super::{BROWSERS, NOT_KEYLESS, Refusal, UNKNOWN_BROWSER, UNTRUSTED_BROWSER};

    const ALLOWED_BROWSERS_FILE: &str = "/etc/keyless/allowed_browsers";

    /// Checks the process that connected (`pid` from the socket's peer
    /// credentials). `allowed`: the browsers the user allowed in the app.
    pub fn check(pid: Option<i32>, allowed: &[PathBuf]) -> Result<(), Refusal> {
        let pid = pid.ok_or(NOT_KEYLESS)?;
        let exe = executable(pid).ok_or(NOT_KEYLESS)?;
        if !same_executable(pid, &exe) {
            return Err(NOT_KEYLESS.into());
        }
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|_| NOT_KEYLESS)?;
        if status_field(&status, "TracerPid") != Some(0) || !clean_environment(pid) || !clean_mappings(pid, &exe) {
            return Err(NOT_KEYLESS.into());
        }
        let parent = status_field(&status, "PPid").ok_or(UNTRUSTED_BROWSER)?;
        let browser = executable(parent as i32).ok_or(UNTRUSTED_BROWSER)?;
        if trusted_browser(&browser) {
            return Ok(());
        }
        // Another browser from the system: the user decides.
        if system_file(&browser) && looks_like_browser(&browser) {
            return if allowed.contains(&browser) { Ok(()) } else { Err(Refusal { code: UNKNOWN_BROWSER, browser: Some(browser) }) };
        }
        Err(UNTRUSTED_BROWSER.into())
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

    fn same_executable(pid: i32, theirs: &Path) -> bool {
        let Some(ours) = executable(std::process::id() as i32) else {
            return false;
        };
        if ours == theirs {
            return true;
        }
        // An AppImage is mounted somewhere new on every start: compare the
        // files themselves (still open through /proc even if replaced), the
        // size first, and the hash of a file once (by its identity).
        let (Ok(mine), Ok(other)) = (std::fs::metadata("/proc/self/exe"), std::fs::metadata(format!("/proc/{pid}/exe"))) else {
            return false;
        };
        if mine.len() != other.len() {
            return false;
        }
        /// A file's device, inode and modification time.
        type Identity = (u64, u64, i64);
        static OURS: OnceLock<Option<[u8; 32]>> = OnceLock::new();
        static LAST: Mutex<Option<(Identity, [u8; 32])>> = Mutex::new(None);
        let Some(ours) = OURS.get_or_init(|| file_hash(Path::new("/proc/self/exe"))) else {
            return false;
        };
        let identity = (other.dev(), other.ino(), other.mtime());
        if let Some((seen, hash)) = *LAST.lock().unwrap_or_else(|e| e.into_inner())
            && seen == identity
        {
            return hash == *ours;
        }
        let Some(hash) = file_hash(Path::new(&format!("/proc/{pid}/exe"))) else {
            return false;
        };
        *LAST.lock().unwrap_or_else(|e| e.into_inner()) = Some((identity, hash));
        hash == *ours
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
            let Some(eq) = entry.iter().position(|&b| b == b'=') else { return true };
            if !matches!(&entry[..eq], b"LD_PRELOAD" | b"LD_AUDIT") {
                return true;
            }
            // A value that is not text is refused, not skipped.
            let Ok(value) = std::str::from_utf8(&entry[eq + 1..]) else { return false };
            value
                .split([':', ' '])
                .filter(|lib| !lib.is_empty())
                .all(|lib| lib.starts_with('/') && system_file(Path::new(lib)))
        })
    }

    /// Where the code of a Keyless that is not installed system-wide may come
    /// from: its own folder (an AppImage's mount, or a development build's).
    /// `None` for a system install: then every library must be a system file.
    fn own_root(exe: &Path) -> Option<PathBuf> {
        if system_file(exe) {
            return None;
        }
        let dir = exe.parent()?;
        // <mount>/usr/bin/keyless-desktop in an AppImage.
        if dir.ends_with("usr/bin") {
            return dir.parent()?.parent().map(Path::to_path_buf);
        }
        Some(dir.to_path_buf())
    }

    /// The code the process runs, as the kernel maps it (it cannot be hidden
    /// by rewriting the environment, and it covers `LD_LIBRARY_PATH` too):
    /// files from the system or from Keyless's own folder, and no anonymous
    /// executable memory.
    fn clean_mappings(pid: i32, exe: &Path) -> bool {
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            return false;
        };
        let root = own_root(exe);
        let mut checked = HashSet::new();
        for line in maps.lines() {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            let Some(perms) = fields.get(1) else { return false };
            if !perms.contains('x') {
                continue;
            }
            let path = fields.get(5..).map(|rest| rest.join(" ")).unwrap_or_default();
            if path.is_empty() {
                return false;
            }
            if path.starts_with('[') {
                if matches!(path.as_str(), "[vdso]" | "[vsyscall]") {
                    continue;
                }
                return false;
            }
            let path = path.strip_suffix(" (deleted)").unwrap_or(&path).to_string();
            if !checked.insert(path.clone()) {
                continue;
            }
            let file = Path::new(&path);
            let allowed = system_file(file) || root.as_ref().is_some_and(|root| file.starts_with(root));
            if !allowed {
                return false;
            }
        }
        true
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

    /// A Chromium or Firefox build (or an app made with Chromium): files
    /// their folder always has. Other programs are not offered to the user.
    fn looks_like_browser(path: &Path) -> bool {
        let Some(dir) = path.parent() else { return false };
        ["icudtl.dat", "v8_context_snapshot.bin", "snapshot_blob.bin", "omni.ja", "application.ini"]
            .iter()
            .any(|name| dir.join(name).is_file())
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
            let pid = std::process::id() as i32;
            let exe = executable(pid).unwrap();
            assert!(same_executable(pid, &exe));
            // Built in the user's folder: its own folder is allowed, and the
            // test binary maps nothing else but system libraries.
            assert_eq!(own_root(&exe).as_deref(), exe.parent());
            assert!(clean_mappings(pid, &exe));
        }

        #[test]
        fn appimage_root_is_the_mount() {
            let exe = Path::new("/tmp/.mount_KeylesAbCdEf/usr/bin/keyless-desktop");
            assert_eq!(own_root(exe).as_deref(), Some(Path::new("/tmp/.mount_KeylesAbCdEf")));
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

        #[test]
        fn browsers_by_their_files() {
            assert!(!looks_like_browser(Path::new("/usr/bin/env")));
            let dir = std::env::temp_dir().join(format!("keyless-browser-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("icudtl.dat"), b"").unwrap();
            assert!(looks_like_browser(&dir.join("some-browser")));
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::{os::windows::io::AsRawHandle, path::PathBuf};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE},
        Security::{
            Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW},
            WinTrust::{
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
                WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
                WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
            },
        },
        System::{
            Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS},
            Pipes::GetNamedPipeClientProcessId,
            Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
        },
    };

    use super::{BROWSERS, NOT_KEYLESS, Refusal, UNKNOWN_BROWSER, UNTRUSTED_BROWSER};

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

    /// The process at the other end of the pipe.
    pub fn client_pid(pipe: &tokio::net::windows::named_pipe::NamedPipeServer) -> Option<u32> {
        let mut pid = 0u32;
        // SAFETY: a connected pipe handle we own.
        (unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } != 0).then_some(pid)
    }

    /// Checks the process at the other end of the pipe (`client_pid`).
    /// `allowed`: the browsers the user allowed in the app.
    pub fn check(pid: Option<u32>, allowed: &[PathBuf]) -> Result<(), Refusal> {
        let pid = pid.ok_or(NOT_KEYLESS)?;
        let host = Process::open(pid).ok_or(NOT_KEYLESS)?;
        let ours = std::env::current_exe().map_err(|_| NOT_KEYLESS)?;
        if !host.image().is_some_and(|image| same_path(&image, &ours)) {
            return Err(NOT_KEYLESS.into());
        }

        // Chrome and Edge start hosts through cmd.exe: look one level up.
        let (parent_pid, parent) = parent_of(pid, &host).ok_or(UNTRUSTED_BROWSER)?;
        let mut image = parent.image().ok_or(UNTRUSTED_BROWSER)?;
        if file_name(&image) == "cmd.exe" && in_windows_folder(&image) {
            let (_, browser) = parent_of(parent_pid, &parent).ok_or(UNTRUSTED_BROWSER)?;
            image = browser.image().ok_or(UNTRUSTED_BROWSER)?;
        }
        let name = file_name(&image);
        let known = BROWSERS.iter().any(|b| name == format!("{b}.exe"));
        let trusted = in_program_files(&image) || signer(&image).is_some_and(|signer| browser_publisher(&signer));
        if known && trusted {
            return Ok(());
        }
        // Another program installed for all users: the user decides.
        if in_program_files(&image) {
            return if allowed.iter().any(|path| same_path(path, &image)) {
                Ok(())
            } else {
                Err(Refusal { code: UNKNOWN_BROWSER, browser: Some(image) })
            };
        }
        Err(UNTRUSTED_BROWSER.into())
    }

    /// System32, or SysWOW64 (the cmd.exe 32-bit browsers start).
    fn in_windows_folder(path: &std::path::Path) -> bool {
        let root = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
        let dir = path.parent().unwrap_or(path);
        same_path(dir, &root.join("System32")) || same_path(dir, &root.join("SysWOW64"))
    }

    /// Publishers whose browsers may be installed per user (outside Program
    /// Files). Authenticode does not cover a file's name, so any signature
    /// would let a signed program renamed "chrome.exe" pass.
    fn browser_publisher(signer: &str) -> bool {
        const PUBLISHERS: &[&str] =
            &["Google LLC", "Microsoft Corporation", "Mozilla Corporation", "Brave Software, Inc.", "Opera Norway AS", "Vivaldi Technologies AS"];
        PUBLISHERS.iter().any(|p| signer.eq_ignore_ascii_case(p))
    }

    /// Installed for all users: only administrators can change it.
    fn in_program_files(path: &std::path::Path) -> bool {
        let lower = path.to_string_lossy().to_lowercase();
        ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
            .iter()
            .filter_map(|var| std::env::var(var).ok())
            .any(|dir| lower.starts_with(&format!("{}\\", dir.to_lowercase().trim_end_matches('\\'))))
    }

    /// Who signed the file (the leaf certificate's name), if it has a valid
    /// Authenticode signature. No revocation check: that would go to the
    /// network.
    fn signer(path: &std::path::Path) -> Option<String> {
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
        let name = if status == 0 {
            // SAFETY: the state from a successful verification, valid until
            // it is closed below; each pointer is checked before use.
            unsafe {
                let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
                let signer = if provider.is_null() { std::ptr::null_mut() } else { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
                if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
                    None
                } else {
                    let cert = (*(*signer).pasCertChain).pCert;
                    let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), std::ptr::null_mut(), 0);
                    if len <= 1 {
                        None
                    } else {
                        let mut buffer = vec![0u16; len as usize];
                        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), buffer.as_mut_ptr(), len);
                        Some(String::from_utf16_lossy(&buffer[..len as usize - 1]))
                    }
                }
            }
        } else {
            None
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: releases the state of the call above.
        unsafe { WinVerifyTrust(INVALID_HANDLE_VALUE, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
        name
    }
}
