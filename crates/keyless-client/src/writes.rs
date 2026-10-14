//! Writes beyond `sealItem`: deleting for good, and settling a write the
//! server refused because the item changed meanwhile, with the desktop's
//! rules (see its `sync`): the most recent edit wins and the other one is
//! kept as a "conflicted copy"; an edit survives a deletion elsewhere.

use keyless_core::{
    generator::{GeneratorOptions, generate},
    item::stamp_version,
    vault::Tombstone,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Client, Failure, OpenVault, Outcome, RemoteItem, Verdict, args, can_write, verify};

impl Client {
    /// A password for these generator options (`{"kind": "random" |
    /// "memorable" | "pin", ...}`, as the desktop's generator).
    pub(crate) fn generate(&self, json: &str) -> Outcome<Value> {
        let options: GeneratorOptions = args(json)?;
        let generated = generate(&options).map_err(|e| Failure { key: "invalid_request", message: e.to_string() })?;
        Ok(json!({ "password": generated.password.as_str(), "entropyBits": generated.entropy_bits }))
    }

    /// Deletes an item for good (after Recently Deleted): the tombstone to
    /// upload where the server still has `baseRevision`.
    pub(crate) fn seal_tombstone(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
            now: i64,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let row = self.store.items.get(&a.id).filter(|r| !r.deleted).ok_or(Failure::new("not_found"))?;
        let vault = unlocked.vaults.get(&row.vault_id).ok_or(Failure::new("not_found"))?;
        if !can_write(&vault.role) {
            return Err(Failure::new("vault_read_only"));
        }
        let tombstone = vault.key.seal_tombstone(&row.vault_id, &a.id, &Tombstone { version: row.version + 1, deleted_at: a.now })?;
        Ok(json!({ "id": a.id, "vaultId": row.vault_id, "encTombstone": tombstone, "baseRevision": row.revision }))
    }

    /// A write (`sealItem` or `sealTombstone`) the server refused because
    /// it has `remote` now. Answers `{"plan": "overwrite", "body", "copy"}`
    /// (write `body` where the server has `remote.revision`) or `{"plan":
    /// "take_remote", "copy"}`; `copy`, when not null, is the losing edit
    /// as a new item to insert. The host then applies the server's rows.
    pub(crate) fn plan_conflict(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            id: String,
            vault_id: String,
            #[serde(default)]
            enc_overview: Option<String>,
            #[serde(default)]
            enc_details: Option<String>,
            #[serde(default)]
            enc_tombstone: Option<String>,
            remote: RemoteItem,
        }
        let a: A = args(json)?;
        if a.remote.id != a.id || a.remote.vault_id != a.vault_id {
            return Err(Failure::new("invalid_request"));
        }
        let unlocked = self.unlocked()?;
        let vault = unlocked.vaults.get(&a.vault_id).ok_or(Failure::new("not_found"))?;
        let own = Pending::open(vault, &a.vault_id, &a.id, a.enc_overview, a.enc_details, a.enc_tombstone)?;
        let overwrite = |body: Value, copy: Value| Ok(json!({ "plan": "overwrite", "body": body, "copy": copy }));
        let take_remote = |copy: Value| Ok(json!({ "plan": "take_remote", "copy": copy }));
        match verify(vault, &a.remote, None) {
            // A forged copy on the server: ours goes over it as it is.
            Verdict::Reject => overwrite(own.body(), Value::Null),
            Verdict::Delete { .. } if own.deleted => take_remote(Value::Null),
            // Deleted elsewhere, edited here: the edit survives.
            Verdict::Delete { version } => overwrite(own.restamped(vault, version)?, Value::Null),
            // Edited elsewhere, deleted here: the edit survives.
            Verdict::Accept { .. } if own.deleted => take_remote(Value::Null),
            Verdict::Accept { version } => {
                let remote_overview = vault.key.open_overview(&a.vault_id, &a.id, a.remote.enc_overview.as_deref().unwrap_or_default())?;
                let remote_details = vault.key.open_details(&a.vault_id, &a.id, a.remote.enc_details.as_deref().unwrap_or_default())?;
                let (ours, ours_details) = own.content.as_ref().ok_or(Failure::new("invalid_request"))?;
                if remote_overview.content_id == ours.content_id {
                    return take_remote(Value::Null);
                }
                let ours_newer = ours.updated_at >= remote_overview.updated_at;
                let (mut lost, mut lost_details) =
                    if ours_newer { (remote_overview, remote_details) } else { (ours.clone(), ours_details.clone()) };
                lost.title = format!("{} (conflicted copy)", lost.title);
                stamp_version(&mut lost, &mut lost_details, 1);
                let copy_id = uuid::Uuid::new_v4().to_string();
                let copy = json!({
                    "id": copy_id,
                    "vaultId": a.vault_id,
                    "encOverview": vault.key.seal_overview(&a.vault_id, &copy_id, &lost)?,
                    "encDetails": vault.key.seal_details(&a.vault_id, &copy_id, &lost_details)?,
                });
                if ours_newer { overwrite(own.restamped(vault, version)?, copy) } else { take_remote(copy) }
            }
        }
    }
}

/// Our refused write, opened.
struct Pending {
    id: String,
    vault_id: String,
    deleted: bool,
    version: u64,
    content: Option<(keyless_core::item::ItemOverview, keyless_core::item::ItemDetails)>,
    /// The ciphertext as it was sent.
    sent: Value,
}

impl Pending {
    fn open(
        vault: &OpenVault,
        vault_id: &str,
        id: &str,
        enc_overview: Option<String>,
        enc_details: Option<String>,
        enc_tombstone: Option<String>,
    ) -> Outcome<Self> {
        if let Some(tombstone) = enc_tombstone {
            let opened = vault.key.open_tombstone(vault_id, id, &tombstone)?;
            let sent = json!({ "enc_tombstone": tombstone });
            return Ok(Self { id: id.into(), vault_id: vault_id.into(), deleted: true, version: opened.version, content: None, sent });
        }
        let (Some(o), Some(d)) = (enc_overview, enc_details) else { return Err(Failure::new("invalid_request")) };
        let overview = vault.key.open_overview(vault_id, id, &o)?;
        let details = vault.key.open_details(vault_id, id, &d)?;
        let sent = json!({ "enc_overview": o, "enc_details": d, "enc_tombstone": Value::Null });
        Ok(Self { id: id.into(), vault_id: vault_id.into(), deleted: false, version: overview.version, content: Some((overview, details)), sent })
    }

    /// The write as it was.
    fn body(&self) -> Value {
        self.sent.clone()
    }

    /// Our content again, with a version above both copies.
    fn restamped(&self, vault: &OpenVault, remote_version: u64) -> Outcome<Value> {
        let (overview, details) = self.content.as_ref().ok_or(Failure::new("invalid_request"))?;
        let (mut overview, mut details) = (overview.clone(), details.clone());
        stamp_version(&mut overview, &mut details, self.version.max(remote_version) + 1);
        Ok(json!({
            "enc_overview": vault.key.seal_overview(&self.vault_id, &self.id, &overview)?,
            "enc_details": vault.key.seal_details(&self.vault_id, &self.id, &details)?,
            "enc_tombstone": Value::Null,
        }))
    }
}
