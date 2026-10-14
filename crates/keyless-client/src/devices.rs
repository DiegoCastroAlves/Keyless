//! The account's devices, as the desktop app handles them (see its
//! `devices` and `device_setup`): what this device says about itself
//! (encrypted with the user key), what the others say, and approving a new
//! device's sign-in from this one (the approver's side of
//! `keyless_core::device_setup`).

use std::collections::HashMap;

use keyless_core::{
    crypto::context,
    device_setup::{SetupApproval, SetupPayload},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{Client, Failure, Outcome, args};

/// Wrong codes typed before a request is refused (as the desktop).
const MAX_CODE_ATTEMPTS: u32 = 3;

/// Requests this device answered: their approval and the wrong codes typed.
#[derive(Default)]
pub(crate) struct Approvals(HashMap<String, (SetupApproval, u32)>);

/// What the other devices show about this one.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct DeviceInfo {
    name: String,
    /// "linux", "windows", "macos", "android", "ios" or "web".
    platform: String,
    os: String,
    app_version: String,
}

fn info_context(user_id: &str, device_id: &str) -> Vec<u8> {
    context("device-info", &[user_id, device_id])
}

impl Client {
    /// This device's description for `register_device`, encrypted.
    pub(crate) fn device_info(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            device_id: String,
            name: String,
            platform: String,
            os: String,
            app_version: String,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let info = DeviceInfo {
            name: a.name.chars().take(64).collect(),
            platform: a.platform,
            os: a.os.chars().take(64).collect(),
            app_version: a.app_version.chars().take(32).collect(),
        };
        let sealed = unlocked.account.user_key().seal(&serde_json::to_vec(&info)?, &info_context(&self.store.user_id, &a.device_id))?;
        Ok(json!(sealed))
    }

    /// The account's devices (`devices` rows), with what each says about
    /// itself decrypted: `name`, `platform`, `os` and `appVersion` added.
    pub(crate) fn device_list(&self, json: &str) -> Outcome<Value> {
        let rows: Vec<Value> = serde_json::from_str(json)?;
        let unlocked = self.unlocked()?;
        Ok(Value::Array(
            rows.into_iter()
                .map(|mut row| {
                    let id = row["id"].as_str().unwrap_or_default().to_string();
                    let info = row["enc_info"]
                        .as_str()
                        .and_then(|e| unlocked.account.user_key().open(e, &info_context(&self.store.user_id, &id)).ok())
                        .and_then(|bytes| serde_json::from_slice::<DeviceInfo>(&bytes).ok())
                        .unwrap_or_default();
                    row["name"] = json!(info.name);
                    row["platform"] = json!(info.platform);
                    row["os"] = json!(info.os);
                    row["appVersion"] = json!(info.app_version);
                    if let Some(map) = row.as_object_mut() {
                        map.remove("enc_info");
                    }
                    row
                })
                .collect(),
        ))
    }

    /// Starts handling a new device's request (`pending_device_setups`):
    /// the key and nonce for `answer_device_setup`.
    pub(crate) fn approval_start(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            id: String,
            public_key: String,
            commitment: String,
        }
        let a: A = args(json)?;
        self.unlocked()?;
        let approval = SetupApproval::new(&a.public_key, &a.commitment).map_err(|_| Failure::new("device_setup_failed"))?;
        let answer = json!({ "publicKey": approval.public_key(), "nonce": approval.nonce() });
        self.approvals.0.insert(a.id, (approval, 0));
        Ok(answer)
    }

    /// The code the new device shows was typed here: when it matches, the
    /// email and Secret Key sealed for the new device (for
    /// `approve_device_setup`). After too many wrong codes the request must
    /// be refused (`device_setup_code_denied`).
    pub(crate) fn approval_seal(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            id: String,
            nonce: String,
            code: String,
            secret_key: Zeroizing<String>,
        }
        let a: A = args(json)?;
        self.unlocked()?;
        let email = self.store.email.clone();
        let (approval, attempts) = self.approvals.0.get_mut(&a.id).ok_or(Failure::new("device_setup_expired"))?;
        if !approval.code_matches(&a.nonce, &a.code).map_err(|_| Failure::new("device_setup_failed"))? {
            *attempts += 1;
            if *attempts < MAX_CODE_ATTEMPTS {
                return Err(Failure::new("device_setup_code_wrong"));
            }
            self.approvals.0.remove(&a.id);
            return Err(Failure::new("device_setup_code_denied"));
        }
        let secret_key = keyless_core::keys::SecretKey::parse(&a.secret_key)?;
        let payload = SetupPayload { email, secret_key: secret_key.to_display() };
        let envelope = approval.seal(&a.id, &a.nonce, &payload).map_err(|_| Failure::new("device_setup_failed"))?;
        self.approvals.0.remove(&a.id);
        Ok(json!(envelope))
    }

    /// Forgets a request this device answered (refused or gone).
    pub(crate) fn approval_forget(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
        }
        let a: A = args(json)?;
        self.approvals.0.remove(&a.id);
        Ok(Value::Null)
    }
}
