//! A new device asking to sign in with another device's help, for testing
//! the approving side (apps/android/scripts/full_run.py), and the phone
//! reading a new device's QR code, for testing the asking side. One JSON
//! command per line on stdin, one JSON answer per line on stdout:
//!
//! - `{"op": "start"}` → `{"publicKey", "commitment"}`
//! - `{"op": "code", "approverKey", "approverNonce"}` → `{"code", "nonce"}`
//! - `{"op": "open", "requestId", "approverKey", "approverNonce", "payload"}` → `{"email", "secretKey"}`
//! - `{"op": "qrStart"}` → `{"id", "secret", "link", "bmp"}` (the QR code as a BMP, base64)
//! - `{"op": "qrOpen", "approverKey", "payload"}` → `{"email", "secretKey"}`
//! - `{"op": "qrSeal", "link", "email", "secretKey"}` → `{"id", "approverKey", "payload"}`
//! - `{"op": "scanPng", "path"}` → the QR codes in a PNG picture (a screenshot
//!   of the phone), as a list of their contents

#[path = "shared/qr_bmp.rs"]
mod qr_bmp;

use std::io::{BufRead, Write};

use keyless_client::Client;
use keyless_core::{device_setup::SetupPayload, qr_sign_in::SignInLink};
use serde_json::{Value, json};
use zeroize::Zeroizing;

fn qr_seal(command: &Value) -> Value {
    let (Some(link), Some(email), Some(secret_key)) = (command["link"].as_str(), command["email"].as_str(), command["secretKey"].as_str()) else {
        return json!({ "error": { "key": "invalid_request" } });
    };
    let payload = SetupPayload { email: email.into(), secret_key: Zeroizing::new(secret_key.into()) };
    match SignInLink::parse(link).and_then(|link| link.seal(&payload).map(|(key, envelope)| (link.id().to_string(), key, envelope))) {
        Ok((id, approver_key, payload)) => json!({ "ok": { "id": id, "approverKey": approver_key, "payload": payload } }),
        Err(_) => json!({ "error": { "key": "sign_in_code_invalid" } }),
    }
}

fn scan_png(command: &Value) -> Option<Vec<String>> {
    let file = std::fs::File::open(command["path"].as_str()?).ok()?;
    let mut decoder = png::Decoder::new(std::io::BufReader::new(file));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().ok()?;
    let mut pixels = vec![0; reader.output_buffer_size()?];
    let frame = reader.next_frame(&mut pixels).ok()?;
    let channels = frame.color_type.samples();
    let (width, height) = (frame.width as usize, frame.height as usize);
    // Luma from the first three channels (or the one grey one).
    let grey: Vec<u8> = pixels[..frame.buffer_size()]
        .chunks(channels)
        .map(|p| if channels < 3 { p[0] } else { ((p[0] as u32 * 299 + p[1] as u32 * 587 + p[2] as u32 * 114) / 1000) as u8 })
        .collect();
    Some(keyless_client::qr::decode_grey(&grey, width, height, width))
}

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
            Some("qrStart") => {
                let mut started: Value = serde_json::from_str(&client.call("signInStart", "")).unwrap_or(Value::Null);
                if let Some(bmp) = started["ok"]["link"].as_str().map(qr_bmp::qr_bmp) {
                    started["ok"]["bmp"] = json!(bmp);
                }
                started.to_string()
            }
            Some("qrOpen") => client.call("signInOpen", &json!({ "approverKey": command["approverKey"], "payload": command["payload"] }).to_string()),
            Some("qrSeal") => qr_seal(&command).to_string(),
            Some("scanPng") => match scan_png(&command) {
                Some(found) => json!({ "ok": found }).to_string(),
                None => json!({ "error": { "key": "invalid_request" } }).to_string(),
            },
            _ => json!({ "error": { "key": "invalid_request" } }).to_string(),
        };
        writeln!(stdout, "{answer}").ok();
        stdout.flush().ok();
    }
}
