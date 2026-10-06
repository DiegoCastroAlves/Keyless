//! Native messaging host mode.
//!
//! Browsers start the Keyless executable with the calling extension as an
//! argument and talk to it over stdin/stdout (32-bit length-prefixed JSON).
//! In that mode Keyless does not open a window: it relays each message to
//! the running app over the local socket and the answer back to the browser.
//! It never sees plaintext: requests and answers are encrypted end to end
//! between the extension and the app.

use std::io::{BufRead, BufReader, Read, Write};

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
        Stream::connect(super::server::socket_path()).ok()
    }
    #[cfg(windows)]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(super::server::pipe_name())
            .ok()
    }
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

fn launch_app() {
    if let Ok(exe) = std::env::current_exe() {
        let mut command = std::process::Command::new(exe);
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let _ = command.spawn();
    }
}

/// Runs the relay until the browser closes the pipe.
pub fn run() {
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut connection: Option<(Stream, BufReader<Stream>)> = None;

    while let Some(message) = read_message(&mut stdin) {
        // The only message handled here: start the app when it isn't running.
        if serde_json::from_slice::<serde_json::Value>(&message)
            .ok()
            .is_some_and(|m| m.get("type").and_then(|t| t.as_str()) == Some("launch"))
        {
            launch_app();
            let _ = write_message(&mut stdout, br#"{"type":"launch","ok":true}"#);
            continue;
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
