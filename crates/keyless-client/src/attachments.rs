//! Attachments (see `keyless_core::attachment`): files kept in an item,
//! encrypted in chunks with a key of their own, kept in the item's details.
//! The keys never leave this crate: the host moves ciphertext between the
//! server's Storage and this client, one chunk at a time
//! (`attachmentSeal`/`attachmentOpen`, raw bytes through the binding).

use std::collections::HashMap;

use keyless_core::{
    attachment::{Attachment, CHUNK_OVERHEAD, CHUNK_SIZE},
    draft::{self, ItemDraft},
    item::{Category, Field, FieldKind},
};
use serde::Deserialize;
use zeroize::Zeroizing;
use serde_json::{Value, json};

use crate::{Client, Failure, Outcome, args, can_write};

/// Files being uploaded, until they join their item (`attachmentsAdd`).
#[derive(Default)]
pub(crate) struct PendingFiles(HashMap<String, (Attachment, String)>);

/// What the host needs to move a file: no key.
fn view(attachment: &Attachment, vault_id: &str) -> Value {
    json!({
        "id": attachment.id,
        "name": attachment.name,
        "size": attachment.size,
        "createdAt": attachment.created_at,
        "chunks": attachment.chunks(),
        "chunkLens": (0..attachment.chunks()).map(|i| attachment.chunk_len(i)).collect::<Vec<_>>(),
        "objects": (0..attachment.chunks()).map(|i| attachment.object_name(vault_id, i)).collect::<Vec<_>>(),
    })
}

impl Client {
    /// An item's attachments.
    pub(crate) fn attachments(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            item_id: String,
        }
        let a: A = args(json)?;
        let (vault_id, _, details) = self.open_item(&a.item_id)?;
        Ok(Value::Array(details.attachments.iter().map(|f| view(f, &vault_id)).collect()))
    }

    /// A new file of `size` bytes for vault `vaultId`: where its chunks go,
    /// and how many bytes each one holds. It joins an item with
    /// `attachmentsAdd` once uploaded. `stored` is how much the server will
    /// count (for its quota).
    pub(crate) fn attachment_new(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            name: String,
            size: u64,
            vault_id: String,
            now: i64,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let vault = unlocked.vaults.get(&a.vault_id).ok_or(Failure::new("not_found"))?;
        if !can_write(&vault.role) {
            return Err(Failure::new("vault_read_only"));
        }
        let attachment = Attachment::new(&a.name, a.size, a.now)?;
        let mut answer = view(&attachment, &a.vault_id);
        answer["stored"] = json!(attachment.size + attachment.chunks() as u64 * CHUNK_OVERHEAD as u64);
        answer["chunkSize"] = json!(CHUNK_SIZE);
        self.files.0.insert(attachment.id.clone(), (attachment, a.vault_id));
        Ok(answer)
    }

    /// Encrypts chunk `index` of a new file (raw bytes, from the binding).
    pub fn attachment_seal(&self, attachment_id: &str, index: u32, plain: &[u8]) -> Result<Vec<u8>, Failure> {
        let (attachment, _) = self.files.0.get(attachment_id).ok_or(Failure::new("not_found"))?;
        // A chunk of another size: the file changed while it was read.
        if index >= attachment.chunks() || plain.len() != attachment.chunk_len(index) {
            return Err(Failure::new("file_changed"));
        }
        Ok(attachment.seal_chunk(&attachment.key()?, index, plain)?)
    }

    /// Decrypts chunk `index` of an item's attachment (raw bytes).
    pub fn attachment_open(&self, item_id: &str, attachment_id: &str, index: u32, raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let (_, _, details) = self.open_item(item_id)?;
        let attachment = details.attachments.iter().find(|f| f.id == attachment_id).ok_or(Failure::new("not_found"))?;
        let damaged = |_| Failure::new("attachment_damaged");
        attachment.open_chunk(&attachment.key().map_err(damaged)?, index, raw).map_err(damaged)
    }

    /// The uploaded files `ids` join item `itemId` (in their vault): the
    /// write to upload, like `sealItem`.
    pub(crate) fn attachments_add(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            item_id: String,
            ids: Vec<String>,
            now: i64,
        }
        let a: A = args(json)?;
        let (vault_id, overview, mut details) = self.open_item(&a.item_id)?;
        for id in &a.ids {
            let (attachment, file_vault) = self.files.0.get(id).ok_or(Failure::new("not_found"))?;
            if *file_vault != vault_id {
                return Err(Failure::new("attachment_item_moved"));
            }
            details.attachments.push(attachment.clone());
        }
        let sealed = self.seal_item(&json!({ "vaultId": vault_id, "id": a.item_id, "overview": overview, "details": details, "now": a.now }).to_string())?;
        for id in &a.ids {
            self.files.0.remove(id);
        }
        Ok(sealed)
    }

    /// A new Document item holding the uploaded file `id` (the share menu's
    /// "Save in Keyless"), as the desktop's Document template: the write to
    /// upload.
    pub(crate) fn document_new(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            id: String,
            #[serde(default)]
            title: String,
            /// The file field's label, in the app's language.
            label: String,
            now: i64,
        }
        let a: A = args(json)?;
        let (attachment, vault_id) = self.files.0.get(&a.id).cloned().ok_or(Failure::new("not_found"))?;
        let title = if a.title.trim().is_empty() { attachment.name.clone() } else { a.title.trim().to_string() };
        let mut field = Field::default();
        (field.label, field.kind, field.value) = (a.label, FieldKind::File, attachment.id.clone());
        let mut draft = ItemDraft {
            vault_id: vault_id.clone(),
            title,
            category: Category::Document,
            fields: vec![field],
            ..Default::default()
        };
        draft::validate(&draft)?;
        draft::normalize(&mut draft);
        let (overview, mut details) = draft::build(draft, None, a.now)?;
        details.attachments.push(attachment);
        let sealed = self.seal_item(&json!({ "vaultId": vault_id, "overview": overview, "details": details, "now": a.now }).to_string())?;
        self.files.0.remove(&a.id);
        Ok(sealed)
    }

    /// Removes attachment `attachmentId` from an item: the write to upload,
    /// and the objects to delete once it is saved.
    pub(crate) fn attachment_remove(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            item_id: String,
            attachment_id: String,
            now: i64,
        }
        let a: A = args(json)?;
        let (vault_id, overview, mut details) = self.open_item(&a.item_id)?;
        let at = details.attachments.iter().position(|f| f.id == a.attachment_id).ok_or(Failure::new("not_found"))?;
        let gone = details.attachments.remove(at);
        let objects: Vec<String> = (0..gone.chunks()).map(|i| gone.object_name(&vault_id, i)).collect();
        let mut sealed = self.seal_item(&json!({ "vaultId": vault_id, "id": a.item_id, "overview": overview, "details": details, "now": a.now }).to_string())?;
        sealed["objects"] = json!(objects);
        Ok(sealed)
    }

    /// Forgets a file whose upload was given up.
    pub(crate) fn attachment_forget(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
        }
        let a: A = args(json)?;
        self.files.0.remove(&a.id);
        Ok(Value::Null)
    }
}
