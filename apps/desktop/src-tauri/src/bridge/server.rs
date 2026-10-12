//! Local socket server the native messaging host connects to.

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use super::{
    crypto::{Channel, decode_public_key, encode_public_key, pairing_code},
    handlers,
};
use crate::state::AppState;

/// Upper bound for one request line (protects against memory exhaustion).
const MAX_LINE: usize = 1024 * 1024;
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CLOCK_SKEW_MS: i64 = 120_000;

pub const EVENT_PAIR_REQUEST: &str = "keyless://pair-request";

#[cfg(unix)]
pub fn socket_path() -> std::path::PathBuf {
    socket_dirs().pop().expect("at least one directory").join("bridge.sock")
}

/// The directories Keyless makes for the socket, outermost first: its own
/// folder in the per-user runtime directory, or, without one, a folder of
/// its own in the shared temporary directory as well.
#[cfg(unix)]
fn socket_dirs() -> Vec<std::path::PathBuf> {
    match std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).filter(|p| p.is_dir()) {
        Some(runtime) => vec![runtime.join("keyless")],
        None => {
            // SAFETY: getuid has no preconditions.
            let base = std::env::temp_dir().join(format!("keyless-{}", unsafe { libc::getuid() }));
            vec![base.clone(), base.join("keyless")]
        }
    }
}

/// Checks that `dir` is a real directory of this user that nobody else can
/// write to, creating it (0700) first when `create` is set. In a shared
/// /tmp, another user could otherwise make the folder first and put their
/// own socket in it.
#[cfg(unix)]
pub fn private_dir(dir: &std::path::Path, create: bool) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if create {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Err(err) if err.kind() != std::io::ErrorKind::AlreadyExists => return Err(err),
            _ => {}
        }
    }
    let meta = std::fs::symlink_metadata(dir)?;
    // SAFETY: getuid has no preconditions.
    if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{} is not a private directory", dir.display())));
    }
    if meta.mode() & 0o077 != 0 {
        if !create {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{} is open to other users", dir.display())));
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Whether the socket's directories are safe to connect through.
#[cfg(unix)]
pub fn socket_dirs_private() -> bool {
    socket_dirs().iter().all(|dir| private_dir(dir, false).is_ok())
}

#[cfg(windows)]
pub fn pipe_name() -> String {
    let user: String = std::env::var("USERNAME")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    format!(r"\\.\pipe\keyless-bridge-{user}")
}

pub fn start(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        if let Err(err) = listen(app).await {
            log::warn!("browser bridge unavailable: {err}");
        }
    });
}

#[cfg(unix)]
async fn listen(app: AppHandle) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for dir in socket_dirs() {
        private_dir(&dir, true)?;
    }
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    loop {
        let (stream, _) = listener.accept().await?;
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == uid => {}
            _ => continue,
        }
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = serve(app, stream).await;
        });
    }
}

#[cfg(windows)]
async fn listen(app: AppHandle) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let name = pipe_name();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&name)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new().reject_remote_clients(true).create(&name)?;
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = serve(app, connected).await;
        });
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(app: AppHandle, stream: S) -> std::io::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    loop {
        let mut line = Zeroizing::new(Vec::new());
        let read = (&mut reader).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line).await?;
        if read == 0 {
            return Ok(());
        }
        if line.len() > MAX_LINE {
            return Ok(());
        }
        let response = handle_line(&app, &line).await;
        let mut out = Zeroizing::new(serde_json::to_vec(&response).unwrap_or_default());
        out.push(b'\n');
        writer.write_all(&out).await?;
        writer.flush().await?;
    }
}

use tokio::io::AsyncReadExt;

#[derive(Deserialize)]
struct EncryptedRequest {
    id: String,
    ts: i64,
    cmd: String,
    #[serde(default)]
    args: Value,
}

async fn handle_line(app: &AppHandle, line: &[u8]) -> Value {
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        return json!({ "type": "error", "code": "bad_request" });
    };
    let state = app.state::<AppState>();
    let bridge = &state.bridge;
    let Some(extension_public) = message.get("pub").and_then(Value::as_str).and_then(decode_public_key) else {
        return json!({ "type": "error", "code": "bad_request" });
    };
    let paired = state.store().is_bridge_peer(&encode_public_key(&extension_public)).unwrap_or(false);

    match message.get("type").and_then(Value::as_str) {
        Some("hello") => json!({
            "type": "hello",
            "version": 1,
            "pub": encode_public_key(&bridge.public),
            "paired": paired,
        }),
        Some("pair") => {
            if paired {
                return json!({ "type": "pair", "ok": true });
            }
            let name: String = message
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Browser")
                .chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect();
            let approved = request_pairing(app, &extension_public, &name).await;
            if approved {
                let _ = state.store().add_bridge_peer(&encode_public_key(&extension_public), &name);
            }
            json!({ "type": "pair", "ok": approved })
        }
        Some("enc") => {
            if !paired {
                return json!({ "type": "error", "code": "not_paired" });
            }
            let Some(channel) = Channel::new(&bridge.secret, &bridge.public, &extension_public) else {
                return json!({ "type": "error", "code": "bad_request" });
            };
            let (Some(nonce), Some(ct)) = (message.get("nonce").and_then(Value::as_str), message.get("ct").and_then(Value::as_str))
            else {
                return json!({ "type": "error", "code": "bad_request" });
            };
            let Some(plaintext) = channel.open(nonce, ct) else {
                return json!({ "type": "error", "code": "bad_request" });
            };
            let Ok(mut request) = serde_json::from_slice::<EncryptedRequest>(&plaintext) else {
                return json!({ "type": "error", "code": "bad_request" });
            };
            if !fresh_request(bridge, &request.id, request.ts) {
                return json!({ "type": "error", "code": "replay" });
            }
            let response = match handlers::dispatch(app, &request.cmd, &mut request.args).await {
                Ok(data) => json!({ "id": request.id, "ok": true, "data": data }),
                Err(code) => json!({ "id": request.id, "ok": false, "error": code }),
            };
            let bytes = Zeroizing::new(serde_json::to_vec(&response).unwrap_or_default());
            match channel.seal(&bytes) {
                Some((nonce, ct)) => json!({ "type": "enc", "nonce": nonce, "ct": ct }),
                None => json!({ "type": "error", "code": "internal" }),
            }
        }
        _ => json!({ "type": "error", "code": "bad_request" }),
    }
}

/// Rejects stale timestamps and repeated request ids.
fn fresh_request(bridge: &super::Bridge, id: &str, ts: i64) -> bool {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if (now_ms - ts).abs() > MAX_CLOCK_SKEW_MS || id.is_empty() || id.len() > 64 {
        return false;
    }
    let mut seen = bridge.seen.lock().unwrap_or_else(|e| e.into_inner());
    let window = Duration::from_millis(2 * MAX_CLOCK_SKEW_MS as u64);
    while seen.front().is_some_and(|(_, at)| at.elapsed() > window) {
        seen.pop_front();
    }
    if seen.iter().any(|(seen_id, _)| seen_id == id) {
        return false;
    }
    seen.push_back((id.to_string(), Instant::now()));
    true
}

/// Shows the pairing prompt in the app and waits for the user's decision.
async fn request_pairing(app: &AppHandle, extension_public: &x25519_dalek::PublicKey, name: &str) -> bool {
    let state = app.state::<AppState>();
    let code = pairing_code(extension_public, &state.bridge.public);
    let request_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    {
        let mut pending = state.bridge.pending.lock().unwrap_or_else(|e| e.into_inner());
        if !pending.is_empty() {
            // One prompt at a time.
            return false;
        }
        pending.insert(request_id.clone(), tx);
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    let _ = app.emit(EVENT_PAIR_REQUEST, json!({ "requestId": request_id, "code": code, "name": name }));
    let decision = tokio::time::timeout(PAIRING_TIMEOUT, rx).await;
    state
        .bridge
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&request_id);
    matches!(decision, Ok(Ok(true)))
}

/// Called by the UI when the user answers a pairing prompt.
pub fn respond_to_pairing(state: &AppState, request_id: &str, approve: bool) {
    if let Some(tx) = state
        .bridge
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(request_id)
    {
        let _ = tx.send(approve);
    }
}
