//! The SSH agent, like 1Password's and Bitwarden's. Off by default.
//!
//! SSH and git ask it to sign with the SSH keys kept in items; the private
//! keys never leave Keyless. Every signature needs the user's approval in a
//! Keyless window that says which program asks, for which key and what for
//! (signing in to a server, or signing a git commit or other data); the user
//! can let that program use that key until Keyless locks. While Keyless is
//! locked, a request asks to unlock it first, and nothing is offered if the
//! user does not.
//!
//! The socket (`~/.keyless/agent.sock`) is in a directory only the user can
//! open, and the agent also refuses connections from other users. Keys are
//! read from the unlocked vault for each request; none are kept after a lock.
//! RSA signatures with SHA-1 (`ssh-rsa`) are refused.
//!
//! It listens on Unix only for now; on Windows (a named pipe) it is still to
//! come, hence the `dead_code` allowances there.

use std::{
    collections::{HashSet, VecDeque},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use keyless_core::item::{Category, FieldKind};
use serde::{Deserialize, Serialize};
use ssh_key::PrivateKey;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::oneshot;

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

pub const LABEL: &str = "ssh-approve";
#[cfg_attr(not(unix), allow(dead_code))]
/// How long a request waits for the user (to unlock, then to approve).
const WAIT: Duration = Duration::from_secs(60);

/// What the user is asked to approve.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub id: u64,
    /// The program asking, and the one that started it (e.g. "ssh", "git").
    pub program: String,
    pub parent: Option<String>,
    pub key_title: String,
    pub fingerprint: String,
    /// "login" (signing in to a server), "git" (a git commit or tag), or
    /// "sign" (other data, with `namespace`).
    pub purpose: String,
    pub namespace: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    Deny,
    Once,
    /// This program may use this key until Keyless locks.
    Remember,
}

struct Pending {
    request: Request,
    answer: oneshot::Sender<Answer>,
}

#[derive(Default)]
pub struct SshState {
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    pending: Mutex<VecDeque<Pending>>,
    /// (key fingerprint, program) approved until Keyless locks.
    remembered: Mutex<HashSet<(String, String)>>,
    next_id: AtomicU64,
}

/// Where the agent listens: `~/.keyless/agent.sock`, or the path in
/// `KEYLESS_SSH_AUTH_SOCK` (e.g. when the home path is too long for a socket).
pub fn socket_path() -> Option<PathBuf> {
    custom_path().or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".keyless").join("agent.sock")))
}

fn custom_path() -> Option<PathBuf> {
    std::env::var_os("KEYLESS_SSH_AUTH_SOCK").filter(|p| !p.is_empty()).map(PathBuf::from)
}

/// At startup: runs the agent if it is turned on, and forgets approvals
/// whenever Keyless locks.
pub fn init(app: &AppHandle) {
    apply(app);
    let app = app.clone();
    let mut locked = app.state::<AppState>().lock_state.subscribe();
    tauri::async_runtime::spawn(async move {
        while locked.changed().await.is_ok() {
            if *locked.borrow() {
                app.state::<AppState>().ssh.remembered.lock().unwrap_or_else(|e| e.into_inner()).clear();
            }
        }
    });
}

/// Starts or stops the agent to follow the setting.
pub fn apply(app: &AppHandle) {
    let state = app.state::<AppState>();
    let enabled = state.settings().ssh_agent;
    let mut task = state.ssh.task.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(running) = task.take() {
        running.abort();
        // Turned off: the socket goes too.
        #[cfg(unix)]
        if !enabled && let Some(path) = socket_path() {
            use std::os::unix::fs::FileTypeExt;
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_socket()) {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    #[cfg(unix)]
    if enabled && let Some(path) = socket_path() {
        let app = app.clone();
        *task = Some(tauri::async_runtime::spawn(async move {
            if let Err(err) = unix::serve(app, path).await {
                log::warn!("SSH agent stopped: {err}");
            }
        }));
    }
    #[cfg(not(unix))]
    let _ = enabled;
}

#[cfg_attr(not(unix), allow(dead_code))]
/// SSH key items' keys, from the unlocked vault: (title, key).
async fn keys(app: &AppHandle) -> Vec<(String, PrivateKey)> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let Some(session) = guard.as_ref() else { return Vec::new() };
    let store = state.store();
    let mut keys = Vec::new();
    for (id, cached) in &session.items {
        let o = &cached.overview;
        if o.category != Category::SshKey || o.trashed_at.is_some() || o.archived {
            continue;
        }
        let Ok(Some(local)) = store.item(id) else { continue };
        let (Some(enc), Ok(vault)) = (local.enc_details.as_deref(), session.vault(&local.vault_id)) else { continue };
        let Ok(details) = vault.key.open_details(&local.vault_id, id, enc) else { continue };
        let private = details.all_fields().find(|f| f.kind == FieldKind::Concealed && f.value.contains("-----BEGIN "));
        if let Some(key) = private.and_then(|f| crate::ssh_keys::parse_private(&f.value, None).ok()) {
            keys.push((o.title.clone(), key));
        }
    }
    keys.sort_by_key(|(title, _)| title.to_lowercase());
    keys
}

#[cfg_attr(not(unix), allow(dead_code))]
/// Unlocked, asking the user if needed.
async fn unlocked(app: &AppHandle) -> bool {
    if app.state::<AppState>().session.lock().await.is_some() {
        return true;
    }
    matches!(tokio::time::timeout(WAIT, crate::unlock_prompt::request(app, crate::unlock_prompt::Reason::Ssh)).await, Ok(Ok(())))
}

#[cfg_attr(not(unix), allow(dead_code))]
/// What signed data is for: SSHSIG blobs (git and `ssh-keygen -Y`) start
/// with "SSHSIG" and their namespace; anything else is a sign-in.
fn purpose(data: &[u8]) -> (String, Option<String>) {
    let Some(rest) = data.strip_prefix(b"SSHSIG") else { return ("login".into(), None) };
    let namespace = rest
        .get(..4)
        .map(|len| u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize)
        .and_then(|len| rest.get(4..4 + len))
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    match namespace.as_deref() {
        Some("git") => ("git".into(), namespace),
        _ => ("sign".into(), namespace),
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
/// Asks the user, one request at a time.
async fn approve(app: &AppHandle, mut request: Request) -> Answer {
    let state = app.state::<AppState>();
    let key = (request.fingerprint.clone(), request.program.clone());
    if state.ssh.remembered.lock().unwrap_or_else(|e| e.into_inner()).contains(&key) {
        return Answer::Once;
    }
    request.id = state.ssh.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    let (tx, rx) = oneshot::channel();
    state.ssh.pending.lock().unwrap_or_else(|e| e.into_inner()).push_back(Pending { request, answer: tx });
    if let Err(err) = show(app) {
        log::warn!("SSH approval window: {err}");
    }
    let answer = tokio::time::timeout(WAIT, rx).await.ok().and_then(Result::ok).unwrap_or(Answer::Deny);
    if answer == Answer::Remember {
        state.ssh.remembered.lock().unwrap_or_else(|e| e.into_inner()).insert(key);
    }
    answer
}

#[cfg_attr(not(unix), allow(dead_code))]
fn show(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(LABEL) {
        window.show()?;
        return window.set_focus();
    }
    // Shown by `ready` once its page has rendered.
    WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
        .title("Keyless")
        .inner_size(420.0, 320.0)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .always_on_top(true)
        .disable_drag_drop_handler()
        .center()
        .visible(false)
        .build()?;
    Ok(())
}

/// The request the approval window shows (the oldest waiting).
pub fn current(app: &AppHandle) -> Option<Request> {
    let state = app.state::<AppState>();
    let mut pending = state.ssh.pending.lock().unwrap_or_else(|e| e.into_inner());
    // Requests that gave up waiting are dropped.
    pending.retain(|p| !p.answer.is_closed());
    pending.front().map(|p| p.request.clone())
}

pub fn ready(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(LABEL) {
        window.show()?;
        let _ = window.center();
        window.set_focus()?;
    }
    Ok(())
}

/// The user answered request `id`. The window closes when nothing else waits.
pub fn answer(app: &AppHandle, id: u64, answer: Answer) -> AppResult<bool> {
    let state = app.state::<AppState>();
    let more = {
        let mut pending = state.ssh.pending.lock().unwrap_or_else(|e| e.into_inner());
        let index = pending.iter().position(|p| p.request.id == id).ok_or(AppError::NotFound)?;
        if let Some(p) = pending.remove(index) {
            let _ = p.answer.send(answer);
        }
        pending.retain(|p| !p.answer.is_closed());
        !pending.is_empty()
    };
    if !more && let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.close();
    }
    Ok(more)
}

/// The window was closed: everything waiting is denied.
pub fn closed(app: &AppHandle) {
    let state = app.state::<AppState>();
    for p in state.ssh.pending.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
        let _ = p.answer.send(Answer::Deny);
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
/// The program behind a process id, and its parent's (Linux).
fn program(pid: Option<i32>) -> (String, Option<String>) {
    #[cfg(target_os = "linux")]
    if let Some(pid) = pid {
        let name = |pid: i32| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let parent = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(1)?.parse::<i32>().ok()))
            .filter(|&ppid| ppid > 1)
            .and_then(name);
        if let Some(program) = name(pid) {
            return (program, parent);
        }
    }
    let _ = pid;
    ("unknown".into(), None)
}

#[cfg(unix)]
mod unix {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    use ssh_agent_lib::{
        agent::{Agent, Session, listen},
        error::AgentError,
        proto::{Identity, PublicCredential, SignRequest},
    };
    use ssh_key::{HashAlg, Signature, public::KeyData};
    use tauri::AppHandle;
    use tokio::net::{UnixListener, UnixStream};

    use super::*;

    pub async fn serve(app: AppHandle, path: PathBuf) -> std::io::Result<()> {
        // Keyless's own directory is kept private; a directory the user chose
        // is left as it is (the socket and the peer check still apply).
        if custom_path().is_none() {
            let dir = path.parent().ok_or_else(|| std::io::Error::other("no directory"))?;
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        // A socket left by a previous run is replaced; anything else is kept.
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                return Err(std::io::Error::other(format!("{} exists and is not a socket", path.display())));
            }
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        log::info!("SSH agent listening at {}", path.display());
        listen(listener, Sessions { app }).await.map_err(std::io::Error::other)
    }

    struct Sessions {
        app: AppHandle,
    }

    impl Agent<UnixListener> for Sessions {
        fn new_session(&mut self, socket: &UnixStream) -> impl Session {
            let cred = socket.peer_cred().ok();
            // SAFETY: getuid has no preconditions and cannot fail.
            let own = cred.is_some_and(|c| c.uid() == unsafe { libc::getuid() });
            Connection { app: self.app.clone(), own, pid: cred.and_then(|c| c.pid()) }
        }
    }

    struct Connection {
        app: AppHandle,
        /// The client runs as this user.
        own: bool,
        pid: Option<i32>,
    }

    #[ssh_agent_lib::async_trait]
    impl Session for Connection {
        async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
            if !self.own || !unlocked(&self.app).await {
                return Ok(Vec::new());
            }
            Ok(keys(&self.app)
                .await
                .into_iter()
                .map(|(title, key)| Identity { credential: PublicCredential::Key(key.public_key().key_data().clone()), comment: title })
                .collect())
        }

        async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
            if !self.own || !unlocked(&self.app).await {
                return Err(AgentError::Failure);
            }
            let wanted: &KeyData = request.credential.key_data();
            let Some((title, key)) = keys(&self.app).await.into_iter().find(|(_, k)| k.public_key().key_data() == wanted) else {
                return Err(AgentError::Failure);
            };
            let (program, parent) = program(self.pid);
            let (purpose, namespace) = purpose(&request.data);
            let ask = Request {
                id: 0,
                program,
                parent,
                key_title: title,
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                purpose,
                namespace,
            };
            if approve(&self.app, ask).await == Answer::Deny {
                return Err(AgentError::Failure);
            }
            crate::ssh_keys::sign(&key, &request.data, request.flags).map_err(|e| AgentError::other(std::io::Error::other(e.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_signature_is_for() {
        assert_eq!(purpose(b"\x00\x00\x00\x20session-id...").0, "login");
        let mut git = b"SSHSIG".to_vec();
        git.extend_from_slice(&3u32.to_be_bytes());
        git.extend_from_slice(b"git");
        git.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(purpose(&git), ("git".into(), Some("git".into())));
        let mut file = b"SSHSIG".to_vec();
        file.extend_from_slice(&4u32.to_be_bytes());
        file.extend_from_slice(b"file");
        assert_eq!(purpose(&file), ("sign".into(), Some("file".into())));
        assert_eq!(purpose(b"SSHSIG\x00\x00\xff"), ("sign".into(), None));
    }
}
