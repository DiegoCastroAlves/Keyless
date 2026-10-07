//! Browser extension bridge.
//!
//! ```text
//! extension ──native messaging──▶ keyless (host mode) ──local socket──▶ Keyless app
//! ```
//!
//! - The browser only launches the host for our extension ids
//!   (`allowed_origins` / `allowed_extensions` in the host manifest).
//! - The local socket is per-user (Unix socket with 0600 permissions and a
//!   peer uid check; a per-user named pipe on Windows that rejects remote
//!   clients).
//! - Every request is end-to-end encrypted between the extension and the app
//!   with keys exchanged during pairing, which the user approves in the app
//!   after comparing a code. Other programs that reach the socket can neither
//!   read nor forge requests.

pub mod crypto;
pub mod forms;
pub mod handlers;
pub mod host;
pub mod install;
pub mod logins;
pub mod server;

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::Instant,
};

use x25519_dalek::{PublicKey, StaticSecret};

/// Native messaging host name registered with browsers.
pub const HOST_NAME: &str = "io.github.diegocastroalves.keyless";
/// Chrome/Chromium id of the extension (derived from the public key in its
/// manifest).
pub const CHROME_EXTENSION_IDS: &[&str] = &["mdafhkgmgciicpdegfgkblolngnhebca"];
/// Firefox add-on id.
pub const FIREFOX_EXTENSION_ID: &str = "keyless@diegocastroalves.github.io";

pub struct Bridge {
    pub secret: StaticSecret,
    pub public: PublicKey,
    /// Pairing requests waiting for the user's decision.
    pub pending: Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
    /// Recently seen request ids, to reject replays.
    pub seen: Mutex<VecDeque<(String, Instant)>>,
}

impl Bridge {
    pub fn new(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret);
        Self { secret, public, pending: Mutex::new(HashMap::new()), seen: Mutex::new(VecDeque::new()) }
    }
}
