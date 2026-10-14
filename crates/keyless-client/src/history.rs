//! An item's earlier versions, as the desktop shows them (see its
//! `item_versions`): the ciphertext the server kept for each write it
//! replaced, decrypted and checked like synced items (both documents open
//! with the vault key, bound to this vault and item, from the same write, and
//! older than the current item). Restoring one saves its content as a new
//! write, so an old version number never comes back.

use keyless_core::{
    draft::ItemDraft,
    history::changes,
    item::{ItemDetails, ItemOverview, same_write},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Client, Failure, Outcome, args};

/// A row of `item_versions`.
#[derive(Deserialize)]
struct RemoteVersion {
    revision: i64,
    enc_overview: String,
    enc_details: String,
}

struct Version {
    revision: i64,
    overview: ItemOverview,
    details: ItemDetails,
}

impl Client {
    /// The versions that check out, newest first, with the current item.
    fn versions(&self, id: &str, rows: Vec<RemoteVersion>) -> Outcome<(Vec<Version>, ItemOverview, ItemDetails)> {
        let (vault_id, current, current_details) = self.open_item(id)?;
        let unlocked = self.unlocked()?;
        let vault = unlocked.vaults.get(&vault_id).ok_or(Failure::new("not_found"))?;
        let mut versions: Vec<Version> = rows
            .into_iter()
            .filter_map(|v| {
                let overview = vault.key.open_overview(&vault_id, id, &v.enc_overview).ok()?;
                let details = vault.key.open_details(&vault_id, id, &v.enc_details).ok()?;
                (same_write(&overview, &details) && overview.version < current.version).then_some(Version { revision: v.revision, overview, details })
            })
            .collect();
        versions.sort_by_key(|v| std::cmp::Reverse(v.overview.version));
        versions.dedup_by_key(|v| v.overview.version);
        Ok((versions, current, current_details))
    }

    /// An item's history (`rows`: its `item_versions`), newest first: each
    /// version's content and what the next one changed.
    pub(crate) fn item_versions(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
            rows: Vec<RemoteVersion>,
        }
        let a: A = args(json)?;
        let (versions, current, current_details) = self.versions(&a.id, a.rows)?;
        let mut out = Vec::with_capacity(versions.len());
        for (i, v) in versions.iter().enumerate() {
            let newer = match i {
                0 => (&current, &current_details),
                _ => (&versions[i - 1].overview, &versions[i - 1].details),
            };
            let mut details = v.details.clone();
            details.sort_main_fields();
            out.push(json!({
                "revision": v.revision,
                "updatedAt": v.overview.updated_at,
                "overview": v.overview,
                "details": details,
                "changed": changes((&v.overview, &v.details), newer),
            }));
        }
        Ok(Value::Array(out))
    }

    /// Saves version `revision` (of `rows`) as the item's newest: the write
    /// to upload, like `saveDraft`. It stays where it is (vault, favorite,
    /// archive), and the password it replaces goes to the password history.
    pub(crate) fn restore_version(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
            rows: Vec<RemoteVersion>,
            revision: i64,
            now: i64,
        }
        let a: A = args(json)?;
        let (versions, current, _) = self.versions(&a.id, a.rows)?;
        let mut v = versions.into_iter().find(|v| v.revision == a.revision).ok_or(Failure::new("not_found"))?;
        let vault_id = self.store.items.get(&a.id).map(|row| row.vault_id.clone()).ok_or(Failure::new("not_found"))?;
        let draft = ItemDraft {
            id: Some(a.id),
            vault_id,
            title: v.overview.title.clone(),
            category: v.overview.category,
            urls: v.overview.urls.clone(),
            tags: v.overview.tags.clone(),
            favorite: current.favorite,
            fields: std::mem::take(&mut v.details.fields),
            sections: std::mem::take(&mut v.details.sections),
            notes: std::mem::take(&mut v.details.notes),
            icon: std::mem::take(&mut v.details.icon),
        };
        self.save_draft(&json!({ "draft": draft, "now": a.now }).to_string())
    }
}
