//! Native messaging host mode.
//!
//! Browsers start the Keyless executable with the calling extension as an
//! argument and talk to it over stdin/stdout (32-bit length-prefixed JSON).
//! In that mode Keyless does not open a window: it relays each message to
//! the running app over the local socket and the answer back to the browser.
//! It never sees plaintext: requests and answers are encrypted end to end
//! between the extension and the app.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use super::{CHROME_EXTENSION_IDS, FIREFOX_EXTENSION_ID};

/// Browser → host messages are limited by Chrome to 4 GiB; we accept 1 MiB.
const MAX_MESSAGE: usize = 1024 * 1024;

/// True when the process was started by a browser for one of our
/// extensions.
pub fn is_host_invocation(args: &[String]) -> bool {
    args.iter().skip(1).any(|arg| {
        CHROME_EXTENSION_IDS
            .iter()
            .any(|id| arg.trim_end_matches('/') == format!("chrome-extension://{id}"))
            || arg == FIREFOX_EXTENSION_ID
    })
}

#[cfg(unix)]
type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Stream = std::fs::File;

fn connect() -> Option<Stream> {
    #[cfg(unix)]
    {
        if !super::server::socket_dirs_private() {
            return None;
        }
        Stream::connect(super::server::socket_path()).ok()
    }
    #[cfg(windows)]
    {
        let pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(super::server::pipe_name())
            .ok()?;
        server_is_ours(&pipe).then_some(pipe)
    }
}

/// The pipe was made by a process of this user (not another user who took
/// the name first).
#[cfg(windows)]
fn server_is_ours(pipe: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    let mut pid = 0u32;
    // SAFETY: an open pipe handle we own.
    let ok = unsafe { windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } != 0;
    ok && crate::win_security::current_user_sid().is_some_and(|me| crate::win_security::process_user_sid(pid).is_some_and(|owner| owner == me))
}

fn read_message(input: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len).ok()?;
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return None;
    }
    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn write_message(output: &mut impl Write, message: &[u8]) -> std::io::Result<()> {
    output.write_all(&(message.len() as u32).to_ne_bytes())?;
    output.write_all(message)?;
    output.flush()
}

/// This executable where it is installed. Linux names a file replaced
/// since the process started (an update) "<path> (deleted)".
fn own_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let text = exe.to_str()?;
    Some(PathBuf::from(text.strip_suffix(" (deleted)").unwrap_or(text)))
}

fn launch_app(path: &Path) {
    let mut command = std::process::Command::new(path);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let _ = command.spawn();
}

/// The installed file's device and inode.
#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Turns into the installed executable in place: same arguments, same pipes
/// to the browser, which keeps its connection. Only returns by exiting.
#[cfg(unix)]
fn become_installed(path: &Path) -> ! {
    use std::os::unix::process::CommandExt;
    let _ = std::process::Command::new(path).args(std::env::args_os().skip(1)).exec();
    // It failed: ending makes the browser start a new host next time.
    std::process::exit(0)
}

/// The browser's messages, read without reading ahead (Unix): a host that
/// turns into a newer one leaves the next messages in the pipe for it.
fn browser_input() -> Box<dyn Read> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        if let Ok(fd) = std::io::stdin().as_fd().try_clone_to_owned() {
            return Box::new(std::fs::File::from(fd));
        }
    }
    Box::new(std::io::stdin())
}

/// Runs the relay until the browser closes the pipe.
pub fn run() {
    let mut stdin = browser_input();
    let mut stdout = std::io::stdout().lock();
    let mut connection: Option<(Stream, BufReader<Stream>)> = None;
    let path = own_path();
    // An update may replace the installed file while the browser keeps this
    // host running: the app refuses a host older than itself, and this one
    // would start the old app. Once it notices, the host answers and turns
    // into the new one (the extension asks again when told the app is not
    // running). Windows does not let a running program be replaced.
    #[cfg(unix)]
    let started = path.as_deref().and_then(file_identity);

    while let Some(message) = read_message(&mut stdin) {
        #[cfg(unix)]
        let outdated = path.as_deref().is_some_and(|p| started.is_some() && file_identity(p).is_some_and(|now| Some(now) != started));
        // The only message handled here: start the app when it isn't running.
        if serde_json::from_slice::<serde_json::Value>(&message)
            .ok()
            .is_some_and(|m| m.get("type").and_then(|t| t.as_str()) == Some("launch"))
        {
            if let Some(path) = &path {
                launch_app(path);
            }
            let _ = write_message(&mut stdout, br#"{"type":"launch","ok":true}"#);
            #[cfg(unix)]
            if outdated && let Some(path) = &path {
                become_installed(path);
            }
            continue;
        }
        #[cfg(unix)]
        if outdated && let Some(path) = &path {
            let _ = write_message(&mut stdout, br#"{"type":"error","code":"app_not_running"}"#);
            become_installed(path);
        }

        if connection.is_none() {
            connection = connect().and_then(|stream| {
                let reader = stream.try_clone().ok()?;
                Some((stream, BufReader::new(reader)))
            });
        }
        let reply = connection.as_mut().and_then(|(stream, reader)| {
            stream.write_all(&message).ok()?;
            stream.write_all(b"\n").ok()?;
            stream.flush().ok()?;
            let mut line = Vec::new();
            let read = reader.by_ref().take(MAX_MESSAGE as u64).read_until(b'\n', &mut line).ok()?;
            (read > 0).then(|| {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                line
            })
        });
        match reply {
            Some(line) => {
                if write_message(&mut stdout, &line).is_err() {
                    return;
                }
            }
            None => {
                connection = None;
                if write_message(&mut stdout, br#"{"type":"error","code":"app_not_running"}"#).is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_browser_invocations() {
        let chrome = vec!["keyless".into(), "chrome-extension://mdafhkgmgciicpdegfgkblolngnhebca/".into()];
        assert!(is_host_invocation(&chrome));
        // The Chrome Web Store's build.
        let store = vec!["keyless".into(), "chrome-extension://hcmaplniiophbidhkclpbicbpleonhja/".into()];
        assert!(is_host_invocation(&store));
        let firefox = vec!["keyless".into(), "/path/manifest.json".into(), FIREFOX_EXTENSION_ID.into()];
        assert!(is_host_invocation(&firefox));
        let other = vec!["keyless".into(), "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".into()];
        assert!(!is_host_invocation(&other));
        assert!(!is_host_invocation(&["keyless".into()]));
    }

    #[test]
    fn message_framing() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"{\"a\":1}").unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_message(&mut cursor).unwrap(), b"{\"a\":1}");
        let mut huge = std::io::Cursor::new((u32::MAX).to_ne_bytes().to_vec());
        assert!(read_message(&mut huge).is_none());
    }
}
