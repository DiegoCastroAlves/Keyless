//! A new device asking to sign in with another device's help, for testing
//! the approving side (apps/android/scripts/full_run.py). One JSON command
//! per line on stdin, one JSON answer per line on stdout:
//!
//! - `{"op": "start"}` → `{"publicKey", "commitment"}`
//! - `{"op": "code", "approverKey", "approverNonce"}` → `{"code", "nonce"}`
//! - `{"op": "open", "requestId", "approverKey", "approverNonce", "payload"}` → `{"email", "secretKey"}`

use std::io::{BufRead, Write};

use keyless_client::Client;
use serde_json::{Value, json};

fn main() {
    let mut client = Client::new();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let command: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        let answer = match command["op"].as_str() {
            Some("start") => client.call("setupStart", ""),
            Some("code") => client.call("setupCode", &json!({ "approverKey": command["approverKey"], "approverNonce": command["approverNonce"] }).to_string()),
            Some("open") => client.call(
                "setupOpen",
                &json!({ "requestId": command["requestId"], "approverKey": command["approverKey"], "approverNonce": command["approverNonce"], "payload": command["payload"] }).to_string(),
            ),
            _ => json!({ "error": { "key": "invalid_request" } }).to_string(),
        };
        writeln!(stdout, "{answer}").ok();
        stdout.flush().ok();
    }
}
