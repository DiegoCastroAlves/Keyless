//! Importing and exporting, as the desktop's `import` (see
//! `keyless_core::import`, `export`, `cxf` and `backup`).
//!
//! The host reads the file the user chose and hands its bytes over
//! (`import_parse`); the items wait here until the user confirms. Their
//! attached files are read from the file, encrypted and handed back one
//! chunk at a time (`import_file`), then `importCommit` gives the items to
//! upload.
//!
//! An export is made here, in memory: `exportStart` collects every item the
//! user can read and lists the attached files to download; the host feeds
//! their chunks as the server keeps them (`export_chunk`) and gets the
//! file's bytes from `export_finish`.

use std::{
    collections::{HashMap, HashSet},
    io::Cursor,
    sync::Arc,
};

use keyless_core::{
    attachment::{Attachment, CHUNK_OVERHEAD, CHUNK_SIZE},
    backup::{BackupData, BackupItem, BackupVault, BackupWriter, open_backup},
    draft, export,
    export::{ExportZip, ZipLayout},
    health,
    import::{
        ImportArchive, ImportResult, ImportedFile, bitwarden, csv::parse_csv, csv::parse_keeper_csv, dashlane::parse_dashlane_zip, kdbx::parse_kdbx, keeper,
        keyless::parse_keyless_export, onepif::parse_1pif, onepux::parse_1pux,
        reconcile::{self, Existing, Outcome as Found, Plan},
    },
    item::{ItemDetails, ItemOverview},
    item::stamp_version,
    keys::normalize_master_password,
    vault::{VaultKey, VaultMeta},
};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{Client, Failure, Outcome, args, can_write};

/// Import files larger than this are refused.
pub const MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;
/// The zxcvbn score a backup password needs (see the desktop's `import`).
const BACKUP_PASSWORD_SCORE: u8 = 4;
const MIN_BACKUP_PASSWORD_CHARS: usize = 10;

/// An import waiting for the user to confirm it.
pub(crate) struct PendingImport {
    result: ImportResult,
    /// The file, when it holds attached files (a zip archive).
    archive: Option<Arc<Zeroizing<Vec<u8>>>>,
    /// Attachments made for its files: by attachment id, the file, and
    /// where in the result its item is (vault, item).
    files: HashMap<String, (ImportedFile, Attachment, String, (usize, usize))>,
    /// What each item is next to the account's (new, the same, changed...).
    plan: Plan,
    /// The ids of the account's items the plan points to.
    existing_ids: Vec<String>,
}

/// An export being made.
pub(crate) enum PendingExport {
    Text(Zeroizing<Vec<u8>>),
    Zip { writer: ExportZip<Cursor<Vec<u8>>>, data: BackupData, files: HashMap<String, Attachment> },
    Backup { writer: BackupWriter<Cursor<Vec<u8>>>, data: BackupData, files: HashMap<String, Attachment>, password: Zeroizing<String>, failed: HashSet<String> },
}

/// What a file the host reads for an import holds: the desktop's import
/// formats.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    OnePux,
    Csv,
    KeylessBackup,
    KeylessExport,
    Json,
    Kdbx,
    OnePif,
    KeeperCsv,
    DashlaneZip,
}

impl Client {
    /// Reads an import file (`file`, with a KeePass `key_file`); the items
    /// wait for `importCommit`. Answers like `call`, with the import's
    /// counts.
    pub fn import_parse(&mut self, json: &str, file: Zeroizing<Vec<u8>>, key_file: Option<Zeroizing<Vec<u8>>>) -> String {
        let parsed = self.parse_import(json, file, key_file);
        crate::answer(parsed)
    }

    fn parse_import(&mut self, json: &str, file: Zeroizing<Vec<u8>>, key_file: Option<Zeroizing<Vec<u8>>>) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            format: Format,
            #[serde(default)]
            password: Option<Zeroizing<String>>,
            /// The vault for a file without vaults of its own.
            name: String,
        }
        let a: A = args(json)?;
        self.unlocked()?;
        self.import = None;
        if file.len() > MAX_IMPORT_BYTES {
            return Err(Failure::new("file_too_large"));
        }
        let password = a.password.as_deref().map(|p| p.as_str());
        let name = a.name.as_str();
        let wrong_password = |err: keyless_core::Error| match err {
            keyless_core::Error::Decryption => Failure::new("import_wrong_password"),
            other => other.into(),
        };
        let file = Arc::new(file);
        // With the name of its format, kept in each item so that importing
        // it again finds what it brought (`reconcile`).
        let (mut result, archive, origin) = match a.format {
            Format::Json => {
                let json: Value = serde_json::from_slice(&file).map_err(|_| Failure::new("import_unknown_json"))?;
                if keyless_core::cxf::detect(&json) {
                    (keyless_core::cxf::parse_cxf(&json)?, None, "cxf")
                } else if bitwarden::detect(&json) {
                    (bitwarden::parse_bitwarden_json(&json, password, name).map_err(wrong_password)?, None, "bitwarden")
                } else if keeper::detect(&json) {
                    (keeper::parse_keeper_json(&json, name)?, None, "keeper")
                } else {
                    return Err(Failure::new("import_unknown_json"));
                }
            }
            Format::Kdbx => (parse_kdbx(&file, password, key_file.as_ref().map(|k| k.as_slice()), name).map_err(wrong_password)?, None, "keepass"),
            Format::OnePif => (parse_1pif(&String::from_utf8_lossy(&file), name)?, None, "1password"),
            Format::KeeperCsv => (parse_keeper_csv(file.as_slice(), name)?, None, "keeper"),
            Format::Csv => (parse_csv(file.as_slice(), name)?, None, "csv"),
            Format::DashlaneZip => (parse_dashlane_zip(Cursor::new(file.as_slice()), "Dashlane")?, None, "dashlane"),
            Format::OnePux => (parse_1pux(Cursor::new(file.as_slice()))?, Some(file), "1password"),
            Format::KeylessExport => (parse_keyless_export(Cursor::new(file.as_slice()))?, Some(file), "keyless"),
            Format::KeylessBackup => {
                let password = password.ok_or(Failure::new("backup_password_required"))?;
                match open_backup(password, Cursor::new(file.as_slice())) {
                    Ok(backup) => (backup.into_import(), Some(file), "keyless"),
                    Err(keyless_core::Error::Decryption) => return Err(Failure::new("backup_wrong_password")),
                    Err(err) => return Err(err.into()),
                }
            }
        };
        if result.vaults.iter().all(|v| v.items.is_empty()) {
            return Err(Failure::new("import_empty"));
        }
        reconcile::mark_sources(&mut result, origin);
        let owned = self.existing_items()?;
        let existing: Vec<Existing> = owned.iter().map(|(id, vault_id, overview, details)| Existing { id, vault_id, overview, details }).collect();
        let plan = reconcile::reconcile(&result, &existing);
        let existing_ids = owned.iter().map(|(id, ..)| id.clone()).collect();
        let summary = result.summary_with(&plan);
        self.import = Some(PendingImport { result, archive, files: HashMap::new(), plan, existing_ids });
        Ok(serde_json::to_value(summary)?)
    }

    /// The account's items outside Recently Deleted, decrypted, for an
    /// import to compare its items with: id, vault, overview and details.
    fn existing_items(&self) -> Outcome<Vec<(String, String, ItemOverview, ItemDetails)>> {
        let mut out = Vec::new();
        for (id, row) in &self.store.items {
            if row.deleted {
                continue;
            }
            let Ok((vault_id, overview, details)) = self.open_item(id) else { continue };
            if overview.trashed_at.is_none() {
                out.push((id.clone(), vault_id, overview, details));
            }
        }
        Ok(out)
    }

    /// The account's item an import changed, with its new version (the
    /// file's content over what only Keyless has).
    fn import_update(&self, item_id: &str, item: &keyless_core::import::ImportedItem, now: i64) -> Outcome<(String, ItemOverview, ItemDetails)> {
        let (vault_id, overview, details) = self.open_item(item_id)?;
        let existing = Existing { id: item_id, vault_id: &vault_id, overview: &overview, details: &details };
        let (overview, details) = reconcile::merged(&existing, item, now);
        Ok((vault_id, overview, details))
    }

    /// The vault each of the import's vaults goes to, checked.
    fn import_targets(&self, targets: &[String]) -> Outcome<()> {
        let pending = self.import.as_ref().ok_or(Failure::new("import_no_file"))?;
        if targets.len() != pending.result.vaults.len() {
            return Err(Failure::new("invalid_request"));
        }
        let unlocked = self.unlocked()?;
        let fresh = pending.plan.new_by_vault();
        for (v, target) in targets.iter().enumerate() {
            if fresh.get(v).copied().unwrap_or(0) == 0 {
                continue;
            }
            let open = unlocked.vaults.get(target).ok_or(Failure::new("not_found"))?;
            if !can_write(&open.role) {
                return Err(Failure::new("vault_read_only"));
            }
        }
        Ok(())
    }

    /// The import's attached files, as new attachments in the vaults
    /// `targets` (one for each of the import's vaults): what the host
    /// uploads with `import_file`. `stored` is what the server will count.
    pub(crate) fn import_files(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            targets: Vec<String>,
            now: i64,
            /// Whether changed items are updated (their new files go too).
            #[serde(default = "yes")]
            update_changed: bool,
        }
        let a: A = args(json)?;
        self.import_targets(&a.targets)?;
        // Where each item's files go, with the files (name, size) it has
        // there already: the target for new items, the item's own vault for
        // changed ones (only the files it lacks).
        type Place = (String, Vec<(String, u64)>);
        let mut places: HashMap<(usize, usize), Place> = HashMap::new();
        {
            let pending = self.import.as_ref().ok_or(Failure::new("import_no_file"))?;
            for (v, outcomes) in pending.plan.outcomes.iter().enumerate() {
                for (i, outcome) in outcomes.iter().enumerate() {
                    match outcome {
                        Found::New => {
                            places.insert((v, i), (a.targets[v].clone(), Vec::new()));
                        }
                        Found::Changed(index) if a.update_changed => {
                            let (vault_id, _, details) = self.open_item(&pending.existing_ids[*index])?;
                            places.insert((v, i), (vault_id, details.attachments.iter().map(|f| (f.name.clone(), f.size)).collect()));
                        }
                        _ => {}
                    }
                }
            }
        }
        let pending = self.import.as_mut().ok_or(Failure::new("import_no_file"))?;
        pending.files.clear();
        let mut list = Vec::new();
        if pending.archive.is_none() {
            return Ok(Value::Array(list));
        }
        for (v, vault) in pending.result.vaults.iter().enumerate() {
            for (i, item) in vault.items.iter().enumerate() {
                let Some((vault_id, has)) = places.get(&(v, i)) else { continue };
                for file in item.files.iter().filter(|f| !has.contains(&(f.name.clone(), f.size))) {
                    let attachment = Attachment::new(&file.name, file.size, a.now)?;
                    let objects: Vec<String> = (0..attachment.chunks()).map(|n| attachment.object_name(vault_id, n)).collect();
                    list.push(json!({
                        "id": attachment.id,
                        "name": attachment.name,
                        "size": attachment.size,
                        "chunks": attachment.chunks(),
                        "objects": objects,
                        "stored": attachment.size + attachment.chunks() as u64 * CHUNK_OVERHEAD as u64,
                        "chunkSize": CHUNK_SIZE,
                    }));
                    pending.files.insert(attachment.id.clone(), (file.clone(), attachment, vault_id.clone(), (v, i)));
                }
            }
        }
        Ok(Value::Array(list))
    }

    /// The import's file `attachment_id`, to read without holding the
    /// client.
    pub fn import_file_source(&self, attachment_id: &str) -> Result<ImportFile, Failure> {
        let pending = self.import.as_ref().ok_or(Failure::new("import_no_file"))?;
        let archive = pending.archive.clone().ok_or(Failure::new("file_unreadable"))?;
        let (file, attachment, _, _) = pending.files.get(attachment_id).ok_or(Failure::new("not_found"))?;
        Ok(ImportFile { archive, file: file.clone(), attachment: attachment.clone() })
    }

    /// The items to upload once the files `uploaded` are on the server,
    /// in the vaults `targets`: new items, like `sealItem`'s, each in its
    /// vault. Files that did not upload are left out.
    pub(crate) fn import_commit(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            targets: Vec<String>,
            #[serde(default)]
            uploaded: Vec<String>,
            now: i64,
            #[serde(default = "yes")]
            update_changed: bool,
        }
        let a: A = args(json)?;
        self.import_targets(&a.targets)?;
        let PendingImport { result, files, plan, existing_ids, .. } = self.import.take().ok_or(Failure::new("import_no_file"))?;
        let mut attached: HashMap<(usize, usize), Vec<Attachment>> = HashMap::new();
        let uploaded: HashSet<&String> = a.uploaded.iter().collect();
        let (mut files_added, mut files_failed) = (0, 0);
        for (id, (_, attachment, _, at)) in files {
            if uploaded.contains(&id) {
                attached.entry(at).or_default().push(attachment);
                files_added += 1;
            } else {
                files_failed += 1;
            }
        }
        let mut rows = Vec::new();
        let mut updates = Vec::new();
        for (v, vault) in result.vaults.into_iter().enumerate() {
            for (i, item) in vault.items.into_iter().enumerate() {
                let mut files = attached.remove(&(v, i)).unwrap_or_default();
                files.sort_by(|x, y| x.name.cmp(&y.name));
                match plan.outcomes.get(v).and_then(|o| o.get(i)).copied().unwrap_or(Found::New) {
                    Found::New => {
                        let vault_id = &a.targets[v];
                        let unlocked = self.unlocked()?;
                        let Some(open) = unlocked.vaults.get(vault_id) else { continue };
                        let (mut overview, mut details) = (item.overview, item.details);
                        if overview.created_at == 0 {
                            overview.created_at = a.now;
                        }
                        if overview.updated_at == 0 {
                            overview.updated_at = a.now;
                        }
                        if overview.subtitle.is_empty() {
                            overview.subtitle = draft::subtitle(overview.category, &details);
                        }
                        details.attachments.extend(files);
                        stamp_version(&mut overview, &mut details, 1);
                        rows.push(json!({
                            "id": item.id,
                            "vaultId": vault_id,
                            "encOverview": open.key.seal_overview(vault_id, &item.id, &overview)?,
                            "encDetails": open.key.seal_details(vault_id, &item.id, &details)?,
                            "baseRevision": null,
                        }));
                    }
                    Found::Changed(index) if a.update_changed => {
                        let item_id = &existing_ids[index];
                        let Ok((vault_id, mut overview, mut details)) = self.import_update(item_id, &item, a.now) else { continue };
                        let Some(row) = self.store.items.get(item_id) else { continue };
                        let unlocked = self.unlocked()?;
                        let Some(open) = unlocked.vaults.get(&vault_id) else { continue };
                        if !can_write(&open.role) {
                            continue;
                        }
                        overview.subtitle = draft::subtitle(overview.category, &details);
                        details.attachments.extend(files);
                        stamp_version(&mut overview, &mut details, row.version + 1);
                        updates.push(json!({
                            "id": item_id,
                            "vaultId": vault_id,
                            "encOverview": open.key.seal_overview(&vault_id, item_id, &overview)?,
                            "encDetails": open.key.seal_details(&vault_id, item_id, &details)?,
                            "baseRevision": row.revision,
                        }));
                    }
                    _ => {}
                }
            }
        }
        Ok(json!({ "items": rows, "updates": updates, "files": files_added, "filesFailed": files_failed }))
    }

    pub(crate) fn import_cancel(&mut self) -> Outcome<Value> {
        self.import = None;
        Ok(Value::Null)
    }

    /// A new vault named `name`: what the server's `create_vault` takes
    /// (`p_id`, `p_enc_meta`, `p_enc_vault_key`). The host then reloads the
    /// memberships.
    pub(crate) fn vault_new(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            name: String,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let meta = VaultMeta { name: a.name.trim().to_string(), ..Default::default() };
        if meta.name.is_empty() {
            return Err(Failure::new("vault_name_required"));
        }
        if meta.name.len() > 100 {
            return Err(Failure::new("vault_details_too_long"));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let key = VaultKey::generate()?;
        Ok(json!({ "p_id": id, "p_enc_meta": key.seal_meta(&id, &meta)?, "p_enc_vault_key": key.wrap(unlocked.account.user_key(), &id)? }))
    }

    /// Every item the user can read, except Recently Deleted, by vault;
    /// with each vault's id.
    fn collect(&self, now: i64) -> Outcome<(BackupData, Vec<String>)> {
        let unlocked = self.unlocked()?;
        let mut vaults: Vec<(String, BackupVault)> = unlocked
            .vaults
            .iter()
            .map(|(id, v)| (id.clone(), BackupVault { name: v.meta.name.clone(), description: v.meta.description.clone(), items: Vec::new() }))
            .collect();
        for (id, row) in &self.store.items {
            if row.deleted {
                continue;
            }
            let Ok((vault_id, overview, details)) = self.open_item(id) else { continue };
            if overview.trashed_at.is_some() {
                continue;
            }
            if let Some((_, vault)) = vaults.iter_mut().find(|(v, _)| *v == vault_id) {
                vault.items.push(BackupItem { id: id.clone(), overview, details });
            }
        }
        let (ids, vaults) = vaults.into_iter().unzip();
        Ok((BackupData { exported_at: now, vaults }, ids))
    }

    /// Starts an export of everything the user can read (after the master
    /// password, always asked: the file holds every secret): `format` is
    /// csv, json, cxf, zip, 1pux or backup (encrypted with `password`,
    /// without passkeys unless `includePasskeys`). Answers the attached
    /// files to download and feed to `export_chunk`, then `export_finish`
    /// gives the file.
    pub(crate) fn export_start(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            format: String,
            #[serde(default)]
            password: Option<Zeroizing<String>>,
            #[serde(default)]
            include_passkeys: bool,
            now: i64,
        }
        self.verify_password(json)?;
        let a: A = args(json)?;
        self.export = None;
        let (mut data, vault_ids) = self.collect(a.now)?;
        let items: usize = data.vaults.iter().map(|v| v.items.len()).sum();
        let mut files = HashMap::new();
        let mut list = Vec::new();
        for (vault, vault_id) in data.vaults.iter().zip(&vault_ids) {
            for attachment in vault.items.iter().flat_map(|i| &i.details.attachments) {
                // Conflict copies of an item list the same file.
                if files.contains_key(&attachment.id) {
                    continue;
                }
                let objects: Vec<String> = (0..attachment.chunks()).map(|n| attachment.object_name(vault_id, n)).collect();
                list.push(json!({ "id": attachment.id, "name": attachment.name, "size": attachment.size, "objects": objects }));
                files.insert(attachment.id.clone(), attachment.clone());
            }
        }
        let export = match a.format.as_str() {
            "csv" => PendingExport::Text(Zeroizing::new(export::to_csv(&data)?)),
            "json" => PendingExport::Text(Zeroizing::new(export::to_json(&data)?)),
            "cxf" => PendingExport::Text(Zeroizing::new(keyless_core::cxf::to_cxf(&data, &self.store.email)?)),
            "zip" | "1pux" => {
                let layout = if a.format == "1pux" { ZipLayout::OnePux } else { ZipLayout::Keyless };
                PendingExport::Zip { writer: ExportZip::with_layout(Cursor::new(Vec::new()), layout), data, files }
            }
            "backup" => {
                // A backup has no Secret Key: its password alone protects it
                // against offline guessing, so it must be strong.
                let password = a.password.ok_or(Failure::new("backup_password_required"))?;
                let normalized = normalize_master_password(&password);
                if normalized.chars().count() < MIN_BACKUP_PASSWORD_CHARS {
                    return Err(Failure { key: "backup_password_too_short", message: MIN_BACKUP_PASSWORD_CHARS.to_string() });
                }
                if health::strength(&normalized, &["keyless"]).score < BACKUP_PASSWORD_SCORE {
                    return Err(Failure::new("backup_password_weak"));
                }
                // Left out for a backup handed to someone else: with them,
                // whoever imports it signs in to those websites as the user.
                if !a.include_passkeys {
                    for item in data.vaults.iter_mut().flat_map(|v| &mut v.items) {
                        item.details.passkeys.clear();
                    }
                }
                PendingExport::Backup { writer: BackupWriter::new(Cursor::new(Vec::new())), data, files, password, failed: HashSet::new() }
            }
            _ => return Err(Failure::new("invalid_request")),
        };
        if matches!(export, PendingExport::Text(_)) {
            list.clear();
        }
        self.export = Some(export);
        Ok(json!({ "items": items, "files": list }))
    }

    /// Chunk `index` of attached file `attachment_id`, as the server keeps
    /// it: checked and written to the export. The file starts with its first
    /// chunk and is complete with its last.
    pub fn export_chunk(&mut self, attachment_id: &str, index: u32, raw: &[u8]) -> Result<(), Failure> {
        let damaged = |_| Failure::new("attachment_damaged");
        match self.export.as_mut().ok_or(Failure::new("not_found"))? {
            PendingExport::Text(_) => Err(Failure::new("invalid_request")),
            PendingExport::Zip { writer, files, .. } => {
                let attachment = files.get(attachment_id).ok_or(Failure::new("not_found"))?;
                let plain = attachment.open_chunk(&attachment.key().map_err(damaged)?, index, raw).map_err(damaged)?;
                if index == 0 {
                    writer.start_file(attachment)?;
                }
                writer.write(&plain)?;
                if index + 1 == attachment.chunks() {
                    writer.end_file();
                }
                Ok(())
            }
            PendingExport::Backup { writer, files, .. } => {
                let attachment = files.get(attachment_id).ok_or(Failure::new("not_found"))?;
                attachment.open_chunk(&attachment.key().map_err(damaged)?, index, raw).map_err(damaged)?;
                if index == 0 {
                    writer.start_file(attachment)?;
                }
                writer.write_chunk(raw)?;
                if index + 1 == attachment.chunks() {
                    writer.end_file();
                }
                Ok(())
            }
        }
    }

    /// Leaves out attached file `id` (it could not be downloaded whole).
    pub(crate) fn export_file_failed(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
        }
        let a: A = args(json)?;
        match self.export.as_mut().ok_or(Failure::new("not_found"))? {
            PendingExport::Text(_) => {}
            PendingExport::Zip { writer, .. } => writer.abort_file()?,
            PendingExport::Backup { writer, failed, .. } => {
                writer.abort_file()?;
                failed.insert(a.id);
            }
        }
        Ok(Value::Null)
    }

    /// The export's file.
    pub fn export_finish(&mut self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let bytes = match self.export.take().ok_or(Failure::new("not_found"))? {
            PendingExport::Text(bytes) => return Ok(bytes),
            PendingExport::Zip { writer, data, .. } => writer.finish(&data)?.into_inner(),
            PendingExport::Backup { writer, mut data, password, failed, .. } => {
                // The backup lists only the files it holds.
                for item in data.vaults.iter_mut().flat_map(|v| &mut v.items) {
                    item.details.attachments.retain(|a| !failed.contains(&a.id));
                }
                writer.finish(&password, &data)?.into_inner()
            }
        };
        Ok(Zeroizing::new(bytes))
    }

    pub(crate) fn export_cancel(&mut self) -> Outcome<Value> {
        self.export = None;
        Ok(Value::Null)
    }
}

/// An attached file of an import, in the import file.
pub struct ImportFile {
    archive: Arc<Zeroizing<Vec<u8>>>,
    file: ImportedFile,
    attachment: Attachment,
}

impl ImportFile {
    /// Reads the file, encrypting each chunk as its new attachment's and
    /// handing it to `each` (chunk index, sealed bytes), which answers
    /// whether the upload went well.
    pub fn read(&self, mut each: impl FnMut(u32, Vec<u8>) -> bool) -> Result<(), Failure> {
        let key = self.attachment.key()?;
        let mut archive = ImportArchive::open(Cursor::new(self.archive.as_slice()))?;
        let mut index = 0;
        archive.read_file(&self.file, |chunk| {
            let sealed = self.attachment.seal_chunk(&key, index, &chunk)?;
            if !each(index, sealed) {
                return Err(keyless_core::Error::Import("the upload stopped".into()));
            }
            index += 1;
            Ok(())
        })?;
        Ok(())
    }
}

fn yes() -> bool {
    true
}
