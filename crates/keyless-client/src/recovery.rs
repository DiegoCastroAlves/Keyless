//! Account recovery keys (see `keyless_core::recovery` and the desktop's
//! `recovery`). One is made or removed with the master password while
//! signed in; signed out, it opens the account when the master password is
//! forgotten or the Secret Key lost:
//!
//! 1. `recoveryBegin`: the key's proof, for the server's `begin_recovery`.
//! 2. `recoveryOpen`: the server's answer opens the account in memory.
//! 3. `recoveryPrepare`: a new master password, Secret Key and next recovery
//!    key, shown for the user to save, and what `complete_recovery` takes.
//!    Once the server took it, the host signs in with `authSecret` and calls
//!    `signedIn`, as after `derive`.

use keyless_core::{
    account::{AccountBundle, UnlockedAccount, rewrap_account, unlock_account},
    health,
    keys::{KdfParams, SecretKey, derive_account_keys, normalize_master_password},
    recovery::RecoveryKey,
};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{Client, Failure, Outcome, Pending, PendingKey, Secrets, args};

/// The desktop's rules for a new master password.
const MIN_MASTER_PASSWORD_CHARS: usize = 10;
const MIN_MASTER_PASSWORD_SCORE: u8 = 3;

/// A recovery between its steps.
pub(crate) struct Recovery {
    email: String,
    proof: Zeroizing<String>,
    /// Needed again to open what the server answers.
    key: RecoveryKey,
    opened: Option<(String, AccountBundle, UnlockedAccount)>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Password {
    master_password: Zeroizing<String>,
    /// The one the host keeps.
    secret_key: Zeroizing<String>,
}

/// The server's `begin_recovery` answer.
#[derive(Deserialize)]
struct Start {
    user_id: String,
    enc_recovery_user_key: String,
    format: u16,
    public_key: String,
    enc_private_key: String,
}

impl Client {
    /// Checks the master password of the account signed in here.
    fn verify_password(&self, json: &str) -> Outcome<UnlockedAccount> {
        let a: Password = args(json)?;
        self.unlocked()?;
        let bundle = self.store.bundle.clone().ok_or(Failure::new("no_account"))?;
        let secret_key = SecretKey::parse(&a.secret_key)?;
        let keys = derive_account_keys(&a.master_password, &secret_key, &bundle.kdf)?;
        unlock_account(&bundle, &keys.kek, &self.store.user_id).map_err(|_| Failure::new("wrong_password"))
    }

    /// Checks the master password before a change that needs it (removing
    /// the recovery key).
    pub(crate) fn check_password(&self, json: &str) -> Outcome<Value> {
        self.verify_password(json)?;
        Ok(json!(true))
    }

    /// A new recovery key, replacing any other: `recoveryKey` to show, and
    /// `proof` and `encUserKey` for the server's `set_recovery_key`.
    pub(crate) fn recovery_create(&self, json: &str) -> Outcome<Value> {
        let account = self.verify_password(json)?;
        let key = RecoveryKey::generate()?;
        let enc_user_key = key.wrap_user_key(&account, &self.store.user_id)?;
        Ok(json!({ "recoveryKey": key.to_display().as_str(), "proof": key.proof()?.as_str(), "encUserKey": enc_user_key }))
    }

    /// Step 1: the proof of `recoveryKey`, for `begin_recovery` with `email`.
    pub(crate) fn recovery_begin(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            email: String,
            recovery_key: Zeroizing<String>,
        }
        let a: A = args(json)?;
        let email = a.email.trim().to_lowercase();
        if self.store.bundle.is_some() && self.store.email != email {
            return Err(Failure { key: "device_other_account", message: self.store.email.clone() });
        }
        let key = RecoveryKey::parse(&a.recovery_key).map_err(|_| Failure::new("recovery_key_invalid"))?;
        let proof = key.proof()?;
        let answer = json!({ "email": email, "proof": proof.as_str() });
        self.recovery = Some(Recovery { email, proof, key, opened: None });
        Ok(answer)
    }

    /// Step 2: opens the account with what `begin_recovery` answered.
    pub(crate) fn recovery_open(&mut self, json: &str) -> Outcome<Value> {
        let start: Start = args(json)?;
        let recovery = self.recovery.as_mut().ok_or(Failure::new("recovery_expired"))?;
        let bundle = AccountBundle {
            format: start.format,
            kdf: KdfParams::recommended(),
            enc_user_key: String::new(),
            public_key: start.public_key,
            enc_private_key: start.enc_private_key,
        };
        let account = recovery.key.open_account(&bundle, &start.enc_recovery_user_key, &start.user_id).map_err(|_| Failure::new("recovery_failed"))?;
        recovery.opened = Some((start.user_id, bundle, account));
        Ok(json!(true))
    }

    /// Step 3: the new credentials for `masterPassword`. `show` is what the
    /// user saves (email, Secret Key, next recovery key); `send` is the
    /// `complete_recovery` arguments.
    pub(crate) fn recovery_prepare(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            master_password: Zeroizing<String>,
        }
        let a: A = args(json)?;
        let recovery = self.recovery.as_ref().ok_or(Failure::new("recovery_expired"))?;
        let (user_id, bundle, account) = recovery.opened.as_ref().ok_or(Failure::new("recovery_expired"))?;
        let normalized = normalize_master_password(&a.master_password);
        if normalized.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return Err(Failure { key: "password_too_short", message: MIN_MASTER_PASSWORD_CHARS.to_string() });
        }
        let local_part = recovery.email.split('@').next().unwrap_or("");
        if health::strength(&normalized, &[local_part, "keyless"]).score < MIN_MASTER_PASSWORD_SCORE {
            return Err(Failure::new("password_weak"));
        }
        let kdf = KdfParams::recommended();
        let secret_key = SecretKey::generate()?;
        let keys = derive_account_keys(&a.master_password, &secret_key, &kdf)?;
        let new_bundle = rewrap_account(bundle, account, &keys.kek, kdf.clone(), user_id)?;
        let next = RecoveryKey::generate()?;
        let next_enc = next.wrap_user_key(account, user_id)?;
        let answer = json!({
            "show": { "email": recovery.email, "secretKey": secret_key.to_display().as_str(), "recoveryKey": next.to_display().as_str() },
            "send": {
                "p_email": recovery.email,
                "p_proof": recovery.proof.as_str(),
                "p_auth_secret": keys.auth_secret.as_str(),
                "p_kdf": kdf,
                "p_enc_user_key": new_bundle.enc_user_key,
                "p_new_proof": next.proof()?.as_str(),
                "p_new_enc_recovery_user_key": next_enc,
            },
            "authSecret": keys.auth_secret.as_str(),
        });
        // Signing in afterwards goes as after `derive`.
        self.pending = Some(Pending {
            key: PendingKey::Kek(keys.kek),
            email: recovery.email.clone(),
            secrets: Secrets { auth_secret: keys.auth_secret, secret_key: secret_key.to_display() },
        });
        Ok(answer)
    }

    /// Drops a recovery in progress.
    pub(crate) fn recovery_forget(&mut self) -> Outcome<Value> {
        self.recovery = None;
        Ok(Value::Null)
    }
}
