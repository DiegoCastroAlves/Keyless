//! A Keyless client without input or output of its own: what the Android
//! app and the web vault share.
//!
//! The host (Kotlin, JavaScript) talks to the server and keeps files; this
//! crate derives the keys, holds them while unlocked, checks everything the
//! server sends the same way the desktop app does (see its `sync`), and
//! decrypts for display. What the host keeps (`snapshot`) is ciphertext
//! only, the same the server has.
//!
//! The whole interface is [`Client::call`]: a method name and JSON
//! arguments in, JSON out (`{"ok": …}` or `{"error": {"key", "message"}}`),
//! so each host needs a single binding.

pub mod matching;
mod store;

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keyless_core::{
    account::{AccountBundle, UnlockedAccount, open_with_user_key, unlock_account},
    device_setup::{SetupPayload, SetupRequest},
    item::{Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, PasswordHistoryEntry, new_field_id, same_write, stamp_version},
    keys::{KdfParams, SecretKey, derive_account_keys},
    passkey_login::{self, PasskeyBundle, PasskeyKeys},
    setup_code,
    totp::Totp,
    vault::{VaultKey, VaultMeta},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

pub use store::{ItemRow, Store, VaultRow};

/// An error for the host: a key its translations know, and a message for
/// logs.
#[derive(Debug)]
pub struct Failure {
    pub key: &'static str,
    pub message: String,
}

impl Failure {
    fn new(key: &'static str) -> Self {
        Self { key, message: key.to_string() }
    }
}

impl From<keyless_core::Error> for Failure {
    fn from(err: keyless_core::Error) -> Self {
        let key = match err {
            keyless_core::Error::InvalidSecretKey => "secret_key_invalid",
            keyless_core::Error::Decryption => "decryption_failed",
            keyless_core::Error::InvalidTotp(_) => "totp_invalid",
            _ => "internal",
        };
        Self { key, message: err.to_string() }
    }
}

impl From<serde_json::Error> for Failure {
    fn from(err: serde_json::Error) -> Self {
        Self { key: "invalid_request", message: err.to_string() }
    }
}

type Outcome<T> = Result<T, Failure>;

/// An open vault: its key and name, while unlocked.
struct OpenVault {
    key: VaultKey,
    meta: VaultMeta,
    role: String,
}

impl Drop for OpenVault {
    fn drop(&mut self) {
        self.meta.zeroize();
    }
}

struct Unlocked {
    account: UnlockedAccount,
    vaults: BTreeMap<String, OpenVault>,
    /// The sign-in secret and Secret Key, when unlocked with them (a passkey
    /// can be added then).
    credentials: Option<Secrets>,
}

struct Secrets {
    auth_secret: Zeroizing<String>,
    secret_key: Zeroizing<String>,
}

/// What opens the account once the server accepts the sign-in.
enum PendingKey {
    /// Derived from the master password and Secret Key.
    Kek(keyless_core::crypto::SymmetricKey),
    /// From a passkey.
    UserKey(keyless_core::crypto::SymmetricKey),
}

/// A sign-in the server has not answered yet.
struct Pending {
    key: PendingKey,
    email: String,
    secrets: Secrets,
}

#[derive(Default)]
pub struct Client {
    store: Store,
    unlocked: Option<Unlocked>,
    pending: Option<Pending>,
    setup: Option<SetupRequest>,
}

/// Item roles that may write.
fn can_write(role: &str) -> bool {
    matches!(role, "owner" | "editor")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Credentials {
    email: String,
    master_password: Zeroizing<String>,
    secret_key: Zeroizing<String>,
}

/// The profile row as the server gives it.
#[derive(Deserialize)]
struct RemoteProfile {
    format: u16,
    kdf: KdfParams,
    enc_user_key: String,
    public_key: String,
    enc_private_key: String,
    #[serde(default)]
    pending_kdf: Option<KdfParams>,
    #[serde(default)]
    pending_enc_user_key: Option<String>,
}

impl RemoteProfile {
    fn bundle(&self) -> AccountBundle {
        AccountBundle {
            format: self.format,
            kdf: self.kdf.clone(),
            enc_user_key: self.enc_user_key.clone(),
            public_key: self.public_key.clone(),
            enc_private_key: self.enc_private_key.clone(),
        }
    }

    fn pending_bundle(&self) -> Option<AccountBundle> {
        Some(AccountBundle { kdf: self.pending_kdf.clone()?, enc_user_key: self.pending_enc_user_key.clone()?, ..self.bundle() })
    }
}

#[derive(Deserialize)]
struct RemoteVault {
    owner_id: String,
    enc_meta: String,
    seq: i64,
    #[serde(default)]
    deleted_at: Option<String>,
    #[serde(default)]
    enc_tombstone: Option<String>,
}

#[derive(Deserialize)]
struct RemoteMembership {
    vault_id: String,
    role: String,
    enc_vault_key: String,
    vaults: RemoteVault,
}

#[derive(Clone, Deserialize)]
pub struct RemoteItem {
    pub id: String,
    pub vault_id: String,
    pub enc_overview: Option<String>,
    pub enc_details: Option<String>,
    pub revision: i64,
    pub seq: i64,
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub enc_tombstone: Option<String>,
}

/// An item in lists.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemSummary {
    id: String,
    vault_id: String,
    overview: ItemOverview,
}

fn args<T: for<'de> Deserialize<'de>>(json: &str) -> Outcome<T> {
    serde_json::from_str(if json.trim().is_empty() { "{}" } else { json }).map_err(Failure::from)
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `method` with `args` (JSON) and answers in JSON.
    pub fn call(&mut self, method: &str, args: &str) -> String {
        let result = self.dispatch(method, args);
        match result {
            Ok(value) => json!({ "ok": value }).to_string(),
            Err(failure) => json!({ "error": { "key": failure.key, "message": failure.message } }).to_string(),
        }
    }

    fn dispatch(&mut self, method: &str, json: &str) -> Outcome<Value> {
        match method {
            "load" => self.load(json),
            "snapshot" => Ok(serde_json::to_value(&self.store)?),
            "status" => Ok(self.status()),
            "derive" => self.derive(args(json)?),
            "signedIn" => self.signed_in(json),
            "unlock" => self.unlock(args(json)?),
            "unlockWithUserKey" => self.unlock_with_user_key(json),
            "exportUserKey" => self.export_user_key(),
            "lock" => {
                self.lock();
                Ok(Value::Null)
            }
            "forget" => {
                self.lock();
                self.store = Store::default();
                Ok(Value::Null)
            }
            "applyMemberships" => self.apply_memberships(json),
            "applyItems" => self.apply_items(json),
            "cursor" => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct A {
                    vault_id: String,
                }
                let a: A = args(json)?;
                Ok(json!(self.store.cursors.get(&a.vault_id).copied().unwrap_or(0)))
            }
            "vaults" => self.vaults(),
            "items" => self.items(),
            "item" => self.item(json),
            "sealItem" => self.seal_item(json),
            "findLogin" => self.find_login(json),
            "sealLogin" => self.seal_login(json),
            "totp" => totp(json),
            "match" => self.matches(json),
            "parseSetupLink" => parse_setup_link(json),
            "setupStart" => self.setup_start(),
            "passkeySalt" => Ok(json!(URL_SAFE_NO_PAD.encode(passkey_login::prf_salt()))),
            "passkeyRegister" => self.passkey_register(json),
            "passkeyNames" => self.passkey_names(json),
            "passkeyProof" => self.passkey_proof(json),
            "passkeyOpen" => self.passkey_open(json),
            "setupCode" => self.setup_code(json),
            "setupOpen" => self.setup_open(json),
            _ => Err(Failure { key: "invalid_request", message: format!("unknown method {method}") }),
        }
    }

    fn unlocked(&self) -> Outcome<&Unlocked> {
        self.unlocked.as_ref().ok_or(Failure::new("locked"))
    }

    fn lock(&mut self) {
        self.unlocked = None;
        self.pending = None;
        self.setup = None;
    }

    fn status(&self) -> Value {
        json!({
            "account": self.store.bundle.is_some(),
            "email": if self.store.email.is_empty() { None } else { Some(&self.store.email) },
            "userId": if self.store.user_id.is_empty() { None } else { Some(&self.store.user_id) },
            "unlocked": self.unlocked.is_some(),
        })
    }

    /// Restores what the host kept (a `snapshot`).
    fn load(&mut self, json: &str) -> Outcome<Value> {
        self.lock();
        self.store = if json.trim().is_empty() || json.trim() == "null" { Store::default() } else { serde_json::from_str(json)? };
        Ok(self.status())
    }

    /// Derives the sign-in secret from the email, master password and Secret
    /// Key; the host sends it to the server (password grant) and then calls
    /// `signedIn` with the profile.
    fn derive(&mut self, credentials: Credentials) -> Outcome<Value> {
        let secret_key = SecretKey::parse(&credentials.secret_key)?;
        let keys = derive_account_keys(&credentials.master_password, &secret_key, &KdfParams::recommended())?;
        let answer = json!({ "authSecret": keys.auth_secret.as_str() });
        self.pending = Some(Pending {
            key: PendingKey::Kek(keys.kek),
            email: credentials.email.trim().to_lowercase(),
            secrets: Secrets { auth_secret: keys.auth_secret, secret_key: secret_key.to_display() },
        });
        Ok(answer)
    }

    /// The server accepted the sign-in: opens the account keys from its
    /// profile (or the staged ones of an interrupted password change).
    fn signed_in(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            user_id: String,
            profile: Option<RemoteProfile>,
        }
        let a: A = args(json)?;
        let pending = self.pending.take().ok_or(Failure::new("invalid_request"))?;
        let profile = a.profile.ok_or(Failure::new("account_not_set_up"))?;
        let (bundle, account) = match pending.key {
            PendingKey::Kek(kek) => match unlock_account(&profile.bundle(), &kek, &a.user_id) {
                Ok(account) => (profile.bundle(), account),
                Err(_) => {
                    let staged = profile.pending_bundle().ok_or(Failure::new("account_keys_undecryptable"))?;
                    let account = unlock_account(&staged, &kek, &a.user_id).map_err(|_| Failure::new("account_keys_undecryptable"))?;
                    (staged, account)
                }
            },
            PendingKey::UserKey(user_key) => {
                let account = open_with_user_key(&profile.bundle(), user_key, &a.user_id).map_err(|_| Failure::new("account_keys_undecryptable"))?;
                (profile.bundle(), account)
            }
        };
        if self.store.user_id != a.user_id {
            self.store = Store::default();
        }
        self.store.user_id = a.user_id;
        self.store.email = pending.email;
        self.store.bundle = Some(bundle);
        self.open(account, Some(pending.secrets));
        Ok(self.status())
    }

    /// Unlocks with the master password and Secret Key, from what is kept.
    fn unlock(&mut self, credentials: Credentials) -> Outcome<Value> {
        let bundle = self.store.bundle.clone().ok_or(Failure::new("no_account"))?;
        let secret_key = SecretKey::parse(&credentials.secret_key)?;
        let keys = derive_account_keys(&credentials.master_password, &secret_key, &bundle.kdf)?;
        let account = unlock_account(&bundle, &keys.kek, &self.store.user_id).map_err(|_| Failure::new("wrong_password"))?;
        self.open(account, Some(Secrets { auth_secret: keys.auth_secret, secret_key: secret_key.to_display() }));
        Ok(self.status())
    }

    /// Unlocks with the user key the host kept (biometric unlock).
    fn unlock_with_user_key(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            user_key: Zeroizing<String>,
        }
        let a: A = args(json)?;
        let bundle = self.store.bundle.clone().ok_or(Failure::new("no_account"))?;
        let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(a.user_key.trim()).map_err(|_| Failure::new("invalid_request"))?);
        let key = keyless_core::crypto::SymmetricKey::from_slice(&bytes)?;
        let account = open_with_user_key(&bundle, key, &self.store.user_id).map_err(|_| Failure::new("biometric_key_invalid"))?;
        self.open(account, None);
        Ok(self.status())
    }

    /// The user key, for the host to keep behind the system's biometrics.
    fn export_user_key(&self) -> Outcome<Value> {
        let unlocked = self.unlocked()?;
        Ok(json!(URL_SAFE_NO_PAD.encode(unlocked.account.user_key().as_bytes())))
    }

    fn open(&mut self, account: UnlockedAccount, credentials: Option<Secrets>) {
        let mut vaults = BTreeMap::new();
        for (id, row) in &self.store.vaults {
            if let Some(open) = open_vault(&account, id, row) {
                vaults.insert(id.clone(), open);
            }
        }
        self.unlocked = Some(Unlocked { account, vaults, credentials });
    }

    /// A passkey being added (the host made it, with the PRF extension):
    /// the proof and bundle for the server.
    fn passkey_register(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            prf_output: Zeroizing<String>,
            credential_id: String,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let secrets = unlocked.credentials.as_ref().ok_or(Failure::new("passkey_needs_password"))?;
        let prf = Zeroizing::new(URL_SAFE_NO_PAD.decode(a.prf_output.trim()).map_err(|_| Failure::new("invalid_request"))?);
        let keys = PasskeyKeys::derive(&prf, &a.credential_id).map_err(|_| Failure::new("passkey_no_prf"))?;
        let bundle = PasskeyBundle {
            email: self.store.email.clone(),
            auth_secret: secrets.auth_secret.clone(),
            user_key: Zeroizing::new(URL_SAFE_NO_PAD.encode(unlocked.account.user_key().as_bytes())),
            secret_key: secrets.secret_key.clone(),
        };
        let enc_bundle = keys.seal(&self.store.user_id, &bundle)?;
        let enc_name = {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct N {
                name: String,
            }
            let n: N = serde_json::from_str(json).unwrap_or_default();
            unlocked.account.user_key().seal(n.name.as_bytes(), &keyless_core::crypto::context("passkey-name", &[&self.store.user_id, &a.credential_id]))?
        };
        Ok(json!({ "proof": keys.proof(), "encBundle": enc_bundle, "encName": enc_name }))
    }

    /// The names of the account's passkeys (`passkeys` rows: id,
    /// credential_id, enc_name...), decrypted.
    fn passkey_names(&self, json: &str) -> Outcome<Value> {
        let rows: Vec<Value> = serde_json::from_str(json)?;
        let unlocked = self.unlocked()?;
        Ok(Value::Array(
            rows.into_iter()
                .map(|mut row| {
                    let credential = row["credential_id"].as_str().unwrap_or_default().to_string();
                    let name = row["enc_name"]
                        .as_str()
                        .and_then(|e| unlocked.account.user_key().open(e, &keyless_core::crypto::context("passkey-name", &[&self.store.user_id, &credential])).ok())
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default();
                    row["name"] = json!(name);
                    row
                })
                .collect(),
        ))
    }

    /// Signing in with a passkey: opens the bundle the server returned for
    /// the proof; the host then signs in with `authSecret` and calls
    /// `signedIn`.
    fn passkey_open(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            prf_output: Zeroizing<String>,
            credential_id: String,
            user_id: String,
            enc_bundle: String,
        }
        let a: A = args(json)?;
        let prf = Zeroizing::new(URL_SAFE_NO_PAD.decode(a.prf_output.trim()).map_err(|_| Failure::new("invalid_request"))?);
        let keys = PasskeyKeys::derive(&prf, &a.credential_id).map_err(|_| Failure::new("passkey_no_prf"))?;
        let bundle = keys.open(&a.user_id, &a.enc_bundle).map_err(|_| Failure::new("passkey_failed"))?;
        let user_key = Zeroizing::new(URL_SAFE_NO_PAD.decode(bundle.user_key.trim()).map_err(|_| Failure::new("passkey_failed"))?);
        let answer = json!({ "email": bundle.email, "authSecret": bundle.auth_secret.as_str(), "secretKey": bundle.secret_key.as_str() });
        self.pending = Some(Pending {
            key: PendingKey::UserKey(keyless_core::crypto::SymmetricKey::from_slice(&user_key)?),
            email: bundle.email.trim().to_lowercase(),
            secrets: Secrets { auth_secret: bundle.auth_secret, secret_key: bundle.secret_key },
        });
        Ok(answer)
    }

    /// What a passkey sign-in asks the authenticator: the proof for a PRF
    /// output (the host sends it to `passkey_sign_in`).
    fn passkey_proof(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            prf_output: Zeroizing<String>,
            credential_id: String,
        }
        let a: A = args(json)?;
        let prf = Zeroizing::new(URL_SAFE_NO_PAD.decode(a.prf_output.trim()).map_err(|_| Failure::new("invalid_request"))?);
        let keys = PasskeyKeys::derive(&prf, &a.credential_id).map_err(|_| Failure::new("passkey_no_prf"))?;
        Ok(json!({ "proof": keys.proof() }))
    }

    /// The account's vaults from the server (`vault_members` with their
    /// `vaults`). A vault whose key or name does not decrypt is ignored; one
    /// deleted on the server goes only with a valid proof.
    fn apply_memberships(&mut self, json: &str) -> Outcome<Value> {
        let memberships: Vec<RemoteMembership> = serde_json::from_str(json)?;
        let unlocked = self.unlocked.as_mut().ok_or(Failure::new("locked"))?;
        let mut changed = false;
        for m in memberships {
            let row = VaultRow { owner_id: m.vaults.owner_id.clone(), role: m.role.clone(), enc_meta: m.vaults.enc_meta.clone(), enc_vault_key: m.enc_vault_key.clone(), seq: m.vaults.seq };
            let Some(opened) = open_vault(&unlocked.account, &m.vault_id, &row) else { continue };
            if m.vaults.deleted_at.is_some() {
                let genuine = m.vaults.enc_tombstone.as_deref().is_some_and(|t| opened.key.open_vault_tombstone(&m.vault_id, t).is_ok());
                if genuine {
                    if self.store.vaults.remove(&m.vault_id).is_some() {
                        self.store.items.retain(|_, item| item.vault_id != m.vault_id);
                        self.store.cursors.remove(&m.vault_id);
                        unlocked.vaults.remove(&m.vault_id);
                        changed = true;
                    }
                    continue;
                }
            }
            if self.store.vaults.get(&m.vault_id) != Some(&row) {
                changed = true;
            }
            self.store.vaults.insert(m.vault_id.clone(), row);
            unlocked.vaults.insert(m.vault_id, opened);
        }
        Ok(json!({ "changed": changed, "vaults": self.store.vaults.keys().collect::<Vec<_>>() }))
    }

    /// A page of a vault's items from the server, checked like the desktop
    /// app does: content must decrypt with the vault key with its overview
    /// and details from the same write and never go back to an older
    /// version; a deletion needs a tombstone newer than our copy. What fails
    /// is ignored. Returns the new cursor.
    fn apply_items(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            vault_id: String,
            items: Vec<RemoteItem>,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked.as_ref().ok_or(Failure::new("locked"))?;
        let vault = unlocked.vaults.get(&a.vault_id).ok_or(Failure::new("not_found"))?;
        let mut cursor = self.store.cursors.get(&a.vault_id).copied().unwrap_or(0);
        let (mut changed, mut rejected) = (0, 0);
        for remote in &a.items {
            cursor = cursor.max(remote.seq);
            if remote.vault_id != a.vault_id {
                rejected += 1;
                continue;
            }
            let local = self.store.items.get(&remote.id);
            match verify(vault, remote, local) {
                Verdict::Accept { version } => {
                    self.store.items.insert(
                        remote.id.clone(),
                        ItemRow {
                            vault_id: remote.vault_id.clone(),
                            enc_overview: remote.enc_overview.clone(),
                            enc_details: remote.enc_details.clone(),
                            revision: remote.revision,
                            seq: remote.seq,
                            deleted: false,
                            version,
                            enc_tombstone: None,
                        },
                    );
                    changed += 1;
                }
                Verdict::Delete { version } => {
                    self.store.items.insert(
                        remote.id.clone(),
                        ItemRow {
                            vault_id: remote.vault_id.clone(),
                            enc_overview: None,
                            enc_details: None,
                            revision: remote.revision,
                            seq: remote.seq,
                            deleted: true,
                            version,
                            enc_tombstone: remote.enc_tombstone.clone(),
                        },
                    );
                    changed += 1;
                }
                Verdict::Reject => rejected += 1,
            }
        }
        self.store.cursors.insert(a.vault_id, cursor);
        Ok(json!({ "cursor": cursor, "changed": changed, "rejected": rejected }))
    }

    fn vaults(&self) -> Outcome<Value> {
        let unlocked = self.unlocked()?;
        Ok(Value::Array(
            unlocked
                .vaults
                .iter()
                .map(|(id, v)| json!({ "id": id, "name": v.meta.name, "icon": v.meta.icon, "role": v.role, "canWrite": can_write(&v.role) }))
                .collect(),
        ))
    }

    /// Every readable item's overview.
    fn items(&self) -> Outcome<Value> {
        let unlocked = self.unlocked()?;
        let mut list = Vec::new();
        for (id, row) in &self.store.items {
            if row.deleted {
                continue;
            }
            let (Some(vault), Some(enc)) = (unlocked.vaults.get(&row.vault_id), row.enc_overview.as_deref()) else { continue };
            let Ok(overview) = vault.key.open_overview(&row.vault_id, id, enc) else { continue };
            list.push(ItemSummary { id: id.clone(), vault_id: row.vault_id.clone(), overview });
        }
        Ok(serde_json::to_value(list)?)
    }

    fn open_item(&self, id: &str) -> Outcome<(String, ItemOverview, ItemDetails)> {
        let unlocked = self.unlocked()?;
        let row = self.store.items.get(id).filter(|r| !r.deleted).ok_or(Failure::new("not_found"))?;
        let vault = unlocked.vaults.get(&row.vault_id).ok_or(Failure::new("not_found"))?;
        let overview = vault.key.open_overview(&row.vault_id, id, row.enc_overview.as_deref().unwrap_or_default())?;
        let details = vault.key.open_details(&row.vault_id, id, row.enc_details.as_deref().unwrap_or_default())?;
        if !same_write(&overview, &details) {
            return Err(Failure::new("decryption_failed"));
        }
        Ok((row.vault_id.clone(), overview, details))
    }

    /// One item, decrypted.
    fn item(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
        }
        let a: A = args(json)?;
        let (vault_id, overview, details) = self.open_item(&a.id)?;
        let row = &self.store.items[&a.id];
        Ok(json!({ "id": a.id, "vaultId": vault_id, "overview": overview, "details": details, "revision": row.revision }))
    }

    /// Encrypts a new item, or a new version of one, for the host to upload
    /// (insert, or update where the server still has `baseRevision`); the
    /// server's answer then goes through `applyItems`. `now` is Unix
    /// seconds.
    fn seal_item(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            vault_id: String,
            #[serde(default)]
            id: Option<String>,
            overview: ItemOverview,
            details: ItemDetails,
            now: i64,
        }
        let mut a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let vault = unlocked.vaults.get(&a.vault_id).ok_or(Failure::new("not_found"))?;
        if !can_write(&vault.role) {
            return Err(Failure::new("vault_read_only"));
        }
        let existing = a.id.as_ref().and_then(|id| self.store.items.get(id)).cloned();
        let id = a.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let (version, base_revision) = match &existing {
            Some(row) => {
                if row.vault_id != a.vault_id {
                    return Err(Failure::new("invalid_request"));
                }
                (row.version + 1, Some(row.revision))
            }
            None => {
                a.overview.created_at = a.now;
                (1, None)
            }
        };
        a.overview.updated_at = a.now;
        if a.overview.category == Category::Login {
            a.overview.subtitle = a.details.username().unwrap_or_default().to_string();
        }
        stamp_version(&mut a.overview, &mut a.details, version);
        let enc_overview = vault.key.seal_overview(&a.vault_id, &id, &a.overview)?;
        let enc_details = vault.key.seal_details(&a.vault_id, &id, &a.details)?;
        Ok(json!({ "id": id, "vaultId": a.vault_id, "encOverview": enc_overview, "encDetails": enc_details, "baseRevision": base_revision }))
    }

    /// The login for this app or website with this username, if there is
    /// one (saving from autofill then updates it rather than adding another).
    fn find_login(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            #[serde(default)]
            domain: Option<String>,
            #[serde(default)]
            package_name: Option<String>,
            #[serde(default)]
            username: String,
        }
        let a: A = args(json)?;
        let candidates: Vec<Value> = match self.matches(&json!({ "domain": a.domain, "packageName": a.package_name }).to_string())? {
            Value::Array(list) => list,
            _ => Vec::new(),
        };
        for candidate in candidates {
            let Some(id) = candidate["id"].as_str() else { continue };
            let Ok((vault_id, _, details)) = self.open_item(id) else { continue };
            let writable = self.unlocked()?.vaults.get(&vault_id).is_some_and(|v| can_write(&v.role));
            if writable && details.username().unwrap_or_default().eq_ignore_ascii_case(a.username.trim()) {
                return Ok(json!(id));
            }
        }
        Ok(Value::Null)
    }

    /// A login saved from autofill: a new one in `vaultId` (or the first
    /// vault the account owns), or, with `id`, a new password for that one
    /// (the old one goes to its history). Encrypted like `sealItem`.
    fn seal_login(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            vault_id: Option<String>,
            #[serde(default)]
            title: String,
            #[serde(default)]
            url: String,
            #[serde(default)]
            username: Zeroizing<String>,
            password: Zeroizing<String>,
            now: i64,
        }
        let a: A = args(json)?;
        let (vault_id, overview, details) = match &a.id {
            Some(id) => {
                let (vault_id, overview, mut details) = self.open_item(id)?;
                let old = details.password().map(str::to_string);
                if old.as_deref() == Some(a.password.as_str()) {
                    return Ok(Value::Null);
                }
                match details.fields.iter_mut().find(|f| f.purpose == Some(FieldPurpose::Password)) {
                    Some(field) => field.value = a.password.to_string(),
                    None => details.fields.push(field("password", FieldKind::Concealed, &a.password, Some(FieldPurpose::Password))),
                }
                if let Some(old) = old.filter(|o| !o.is_empty()) {
                    details.password_history.insert(0, PasswordHistoryEntry { value: old, changed_at: a.now });
                }
                (vault_id, overview, details)
            }
            None => {
                let unlocked = self.unlocked()?;
                let vault_id = match &a.vault_id {
                    Some(id) => id.clone(),
                    None => unlocked
                        .vaults
                        .iter()
                        .find(|(_, v)| v.role == "owner")
                        .or_else(|| unlocked.vaults.iter().find(|(_, v)| can_write(&v.role)))
                        .map(|(id, _)| id.clone())
                        .ok_or(Failure::new("vault_read_only"))?,
                };
                let mut details = ItemDetails::default();
                if !a.username.trim().is_empty() {
                    details.fields.push(field("username", FieldKind::Text, a.username.trim(), Some(FieldPurpose::Username)));
                }
                details.fields.push(field("password", FieldKind::Concealed, &a.password, Some(FieldPurpose::Password)));
                let title = if a.title.trim().is_empty() { matching::host_of(&a.url).unwrap_or_else(|| a.url.clone()) } else { a.title.trim().to_string() };
                let overview = ItemOverview {
                    title,
                    category: Category::Login,
                    urls: if a.url.trim().is_empty() { Vec::new() } else { vec![ItemUrl { href: a.url.trim().to_string(), ..Default::default() }] },
                    ..Default::default()
                };
                (vault_id, overview, details)
            }
        };
        let sealed = json!({ "vaultId": vault_id, "id": a.id, "overview": overview, "details": details, "now": a.now });
        self.seal_item(&sealed.to_string())
    }

    /// Logins for an app or a website, best first (autofill).
    fn matches(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            #[serde(default)]
            domain: Option<String>,
            #[serde(default)]
            package_name: Option<String>,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let mut found: Vec<(u8, ItemSummary)> = Vec::new();
        for (id, row) in &self.store.items {
            if row.deleted {
                continue;
            }
            let (Some(vault), Some(enc)) = (unlocked.vaults.get(&row.vault_id), row.enc_overview.as_deref()) else { continue };
            let Ok(overview) = vault.key.open_overview(&row.vault_id, id, enc) else { continue };
            if overview.trashed_at.is_some() || overview.category != Category::Login {
                continue;
            }
            let score = overview
                .urls
                .iter()
                .map(|u| matching::score(&u.href, a.domain.as_deref(), a.package_name.as_deref()))
                .max()
                .unwrap_or(0);
            if score > 0 {
                found.push((score, ItemSummary { id: id.clone(), vault_id: row.vault_id.clone(), overview }));
            }
        }
        found.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.overview.favorite.cmp(&a.1.overview.favorite)).then(a.1.overview.title.cmp(&b.1.overview.title)));
        Ok(serde_json::to_value(found.into_iter().map(|(_, s)| s).collect::<Vec<_>>())?)
    }

    fn setup_start(&mut self) -> Outcome<Value> {
        let request = SetupRequest::new()?;
        let answer = json!({ "publicKey": request.public_key(), "commitment": request.commitment() });
        self.setup = Some(request);
        Ok(answer)
    }

    /// The other device answered: the code to show, and the nonce to reveal.
    fn setup_code(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            approver_key: String,
            approver_nonce: String,
        }
        let a: A = args(json)?;
        let request = self.setup.as_ref().ok_or(Failure::new("device_setup_expired"))?;
        let code = request.code(&a.approver_key, &a.approver_nonce).map_err(|_| Failure::new("device_setup_failed"))?;
        Ok(json!({ "code": code, "nonce": request.nonce() }))
    }

    /// The other device approved: the email and Secret Key it sent.
    fn setup_open(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            request_id: String,
            approver_key: String,
            approver_nonce: String,
            payload: String,
        }
        let a: A = args(json)?;
        let request = self.setup.take().ok_or(Failure::new("device_setup_expired"))?;
        let SetupPayload { email, secret_key } =
            request.open(&a.request_id, &a.approver_key, &a.approver_nonce, &a.payload).map_err(|_| Failure::new("device_setup_failed"))?;
        SecretKey::parse(&secret_key).map_err(|_| Failure::new("device_setup_failed"))?;
        Ok(json!({ "email": email, "secretKey": secret_key.as_str() }))
    }
}

fn field(label: &str, kind: FieldKind, value: &str, purpose: Option<FieldPurpose>) -> Field {
    Field { id: new_field_id(), label: label.into(), kind, value: value.into(), purpose, extra: Default::default() }
}

fn open_vault(account: &UnlockedAccount, id: &str, row: &VaultRow) -> Option<OpenVault> {
    let key = VaultKey::unwrap(account.user_key(), id, &row.enc_vault_key).ok()?;
    let meta = key.open_meta(id, &row.enc_meta).ok()?;
    Some(OpenVault { key, meta, role: row.role.clone() })
}

enum Verdict {
    Accept { version: u64 },
    Delete { version: u64 },
    Reject,
}

fn verify(vault: &OpenVault, remote: &RemoteItem, local: Option<&ItemRow>) -> Verdict {
    let local_version = local.map(|l| l.version).unwrap_or(0);
    if remote.deleted_at.is_some() {
        let tombstone = remote.enc_tombstone.as_deref().and_then(|t| vault.key.open_tombstone(&remote.vault_id, &remote.id, t).ok());
        return match (tombstone, local) {
            (Some(t), None) => Verdict::Delete { version: t.version },
            (Some(t), Some(l)) if t.version > l.version => Verdict::Delete { version: t.version },
            (Some(t), Some(l)) if l.deleted && t.version == l.version => Verdict::Delete { version: t.version },
            _ => Verdict::Reject,
        };
    }
    let (Some(enc_overview), Some(enc_details)) = (remote.enc_overview.as_deref(), remote.enc_details.as_deref()) else {
        return Verdict::Reject;
    };
    let (Ok(overview), Ok(details)) =
        (vault.key.open_overview(&remote.vault_id, &remote.id, enc_overview), vault.key.open_details(&remote.vault_id, &remote.id, enc_details))
    else {
        return Verdict::Reject;
    };
    if !same_write(&overview, &details) {
        return Verdict::Reject;
    }
    match local {
        None => Verdict::Accept { version: overview.version },
        Some(_) if overview.version > local_version => Verdict::Accept { version: overview.version },
        Some(l) if overview.version == local_version && !l.deleted => {
            let ours = l.enc_overview.as_deref().and_then(|e| vault.key.open_overview(&remote.vault_id, &remote.id, e).ok()).map(|o| o.content_id);
            if ours.as_deref() == Some(overview.content_id.as_str()) { Verdict::Accept { version: overview.version } } else { Verdict::Reject }
        }
        Some(_) => Verdict::Reject,
    }
}

fn totp(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        uri: Zeroizing<String>,
        now: u64,
    }
    let a: A = args(json)?;
    let totp = Totp::parse(&a.uri)?;
    Ok(json!({ "code": totp.code_at(a.now).as_str(), "period": totp.period, "remaining": totp.seconds_remaining(a.now) }))
}

fn parse_setup_link(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        text: Zeroizing<String>,
    }
    let a: A = args(json)?;
    let (email, key) = setup_code::parse_setup_link(&a.text).map_err(|_| Failure::new("setup_code_invalid"))?;
    Ok(json!({ "email": email, "secretKey": key.to_display().as_str() }))
}

#[cfg(test)]
mod tests;
