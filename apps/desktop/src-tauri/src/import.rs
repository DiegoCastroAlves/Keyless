//! Importing from 1Password (.1pux), CSV exports, Keyless backups and
//! Keyless's own unencrypted exports (JSON or zip), and writing backups and
//! unencrypted exports.
//!
//! Files are chosen in native dialogs opened from Rust, so the UI never
//! supplies file paths. Parsed items are held in memory (wiped on lock)
//! until the user confirms; their attached files stay in the import file
//! until then, and each is uploaded as a new attachment (a new id and key).
//! Backups and zip exports download every attached file the user can read.

use std::{
    collections::HashSet,
    fs::File,
    io::{BufReader, BufWriter, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use keyless_core::{
    attachment::{Attachment, CHUNK_OVERHEAD, CHUNK_SIZE},
    backup::{BackupData, BackupItem, BackupVault, BackupWriter, open_backup},
    export::ExportZip,
    import::{ImportArchive, ImportResult, ImportSummary, ImportedFile, csv::parse_csv, keyless::parse_keyless_export, onepux::parse_1pux},
    vault::VaultMeta,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::{
    api::now_secs,
    attachments::{self, Gone, Source},
    auth::MIN_MASTER_PASSWORD_CHARS,
    error::{AppError, AppResult, Msg},
    items,
    state::AppState,
    sync,
};

/// The zxcvbn score a backup password needs: the top one ("very strong"). A
/// backup has no Secret Key, so its password alone resists offline guessing.
pub const BACKUP_PASSWORD_SCORE: u8 = 4;
/// CSV files larger than this are refused.
const MAX_CSV_BYTES: u64 = 512 * 1024 * 1024;
/// Progress of the attached files of an import or export.
pub const EVENT_PROGRESS: &str = "keyless://files-progress";

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    OnePux,
    Csv,
    KeylessBackup,
    /// Keyless's unencrypted export: the JSON, or the zip with the files.
    KeylessExport,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ImportTarget {
    /// Recreate the source vaults as new Keyless vaults.
    NewVaults,
    /// Put everything into one existing vault.
    Vault {
        #[serde(rename = "vaultId")]
        vault_id: String,
    },
    /// Put everything into one new vault with this name.
    NewVault { name: String },
}

/// An import waiting for the user to confirm it.
pub struct PendingImport {
    result: ImportResult,
    /// The file it came from, which holds its attached files.
    file: Option<PathBuf>,
}

/// Bytes of attached files done, out of `total`.
#[derive(Clone, Serialize)]
struct FilesProgress {
    done: u64,
    total: u64,
}

#[derive(Clone)]
struct Progress {
    app: AppHandle,
    total: u64,
    done: Arc<AtomicU64>,
}

impl Progress {
    fn new(app: &AppHandle, total: u64) -> Self {
        Self { app: app.clone(), total, done: Arc::new(AtomicU64::new(0)) }
    }

    fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    fn add(&self, bytes: u64) {
        let done = self.done.fetch_add(bytes, Ordering::Relaxed) + bytes;
        self.emit(done);
    }

    /// Counts the whole file that started at `start` as done (it failed).
    fn skip_file(&self, start: u64, size: u64) {
        let done = self.done.fetch_max(start + size, Ordering::Relaxed).max(start + size);
        self.emit(done);
    }

    fn emit(&self, done: u64) {
        let _ = self.app.emit(EVENT_PROGRESS, FilesProgress { done: done.min(self.total), total: self.total });
    }
}

pub async fn pick_and_parse(app: &AppHandle, format: ImportFormat, password: Option<Zeroizing<String>>) -> AppResult<ImportSummary> {
    let state = app.state::<AppState>();
    if state.session.lock().await.is_none() {
        return Err(AppError::Locked);
    }
    let dialog = app.dialog().file().set_title("Choose a file to import");
    let dialog = match format {
        ImportFormat::OnePux => dialog.add_filter("1Password export", &["1pux"]),
        ImportFormat::Csv => dialog.add_filter("CSV file", &["csv"]),
        ImportFormat::KeylessBackup => dialog.add_filter("Keyless backup", &["keyless"]),
        ImportFormat::KeylessExport => dialog.add_filter("Keyless export", &["json", "zip"]),
    };
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_pick_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unreadable")))?;

    let pending = tauri::async_runtime::spawn_blocking(move || -> AppResult<PendingImport> {
        let unreadable = |e: std::io::Error| AppError::Invalid(Msg::new("file_unreadable").with("detail", e));
        let file = File::open(&path).map_err(unreadable)?;
        match format {
            ImportFormat::OnePux => Ok(PendingImport { result: parse_1pux(BufReader::new(file))?, file: Some(path) }),
            ImportFormat::KeylessExport => Ok(PendingImport { result: parse_keyless_export(BufReader::new(file))?, file: Some(path) }),
            ImportFormat::Csv => {
                if file.metadata().map(|m| m.len()).unwrap_or(0) > MAX_CSV_BYTES {
                    return Err(AppError::Invalid(Msg::new("file_too_large")));
                }
                let mut contents = Zeroizing::new(Vec::new());
                file.take(MAX_CSV_BYTES).read_to_end(&mut contents).map_err(unreadable)?;
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| format!("Imported ({s})"))
                    .unwrap_or_else(|| "Imported".into());
                Ok(PendingImport { result: parse_csv(contents.as_slice(), &name)?, file: None })
            }
            ImportFormat::KeylessBackup => {
                let password = password.ok_or_else(|| AppError::Invalid(Msg::new("backup_password_required")))?;
                match open_backup(&password, BufReader::new(file)) {
                    Ok(backup) => Ok(PendingImport { result: backup.into_import(), file: Some(path) }),
                    Err(keyless_core::Error::Decryption) => Err(AppError::Invalid(Msg::new("backup_wrong_password"))),
                    Err(err) => Err(err.into()),
                }
            }
        }
    })
    .await
    .map_err(|e| AppError::Store(e.to_string()))??;

    let summary = pending.result.summary();
    if summary.total_items == 0 {
        return Err(AppError::Invalid(Msg::new("import_empty")));
    }
    *state.pending_import.lock().unwrap_or_else(|e| e.into_inner()) = Some(pending);
    Ok(summary)
}

/// What an import added.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutcome {
    items: usize,
    files: usize,
    /// Attached files that could not be added (no room, damaged, offline).
    files_failed: usize,
}

pub async fn commit(app: &AppHandle, target: ImportTarget) -> AppResult<ImportOutcome> {
    let state = app.state::<AppState>();
    let PendingImport { result, file } = state
        .pending_import
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| AppError::Invalid(Msg::new("import_no_file")))?;

    let progress = Progress::new(app, result.summary().file_bytes);
    // Room for the files: the server checks a whole chunk ahead.
    let mut space = match progress.total {
        0 => None,
        _ => attachments::space(&state).await.ok().flatten(),
    };
    let mut outcome = ImportOutcome::default();
    // The vault of ImportTarget::NewVault, once made.
    let mut new_vault: Option<String> = None;
    for vault in result.vaults {
        if vault.items.is_empty() {
            continue;
        }
        let vault_id = match &target {
            ImportTarget::NewVaults => {
                items::create_vault(app, VaultMeta { name: vault.name.clone(), ..Default::default() }).await?
            }
            ImportTarget::Vault { vault_id } => vault_id.clone(),
            ImportTarget::NewVault { name } => match &new_vault {
                Some(id) => id.clone(),
                None => {
                    let id = items::create_vault(app, VaultMeta { name: name.trim().to_string(), ..Default::default() }).await?;
                    new_vault = Some(id.clone());
                    id
                }
            },
        };
        {
            let guard = state.session.lock().await;
            let session = guard.as_ref().ok_or(AppError::Locked)?;
            if !session.vault(&vault_id)?.can_write() {
                return Err(AppError::Invalid(Msg::new("vault_read_only")));
            }
        }

        let mut batch = Vec::with_capacity(vault.items.len());
        let mut uploaded = Vec::new();
        for item in vault.items {
            let mut details = item.details;
            for imported in item.files {
                let start = progress.done();
                let size = imported.size;
                let needed = size + imported_chunks(size) * CHUNK_OVERHEAD as u64;
                let room = space.as_ref().is_none_or(|s| s.used + needed + (CHUNK_SIZE + CHUNK_OVERHEAD) as u64 <= s.quota);
                let added = match &file {
                    Some(path) if room => upload_imported(app, &vault_id, path, imported, &progress).await,
                    Some(_) => Err(AppError::Invalid(Msg::new("attachment_space_full"))),
                    None => Err(AppError::Invalid(Msg::new("file_unreadable"))),
                };
                match added {
                    Ok(attachment) => {
                        if let Some(space) = space.as_mut() {
                            space.used += needed;
                        }
                        uploaded.push(Gone::of(&vault_id, &attachment));
                        details.attachments.push(attachment);
                        outcome.files += 1;
                    }
                    Err(AppError::Locked) => {
                        attachments::forget(app, uploaded);
                        return Err(AppError::Locked);
                    }
                    Err(err) => {
                        log::warn!("import: an attached file was not added: {err}");
                        outcome.files_failed += 1;
                        progress.skip_file(start, size);
                    }
                }
            }
            batch.push((item.overview, details));
        }
        match items::insert_imported(&state, &vault_id, batch).await {
            Ok(count) => outcome.items += count,
            Err(err) => {
                attachments::forget(app, uploaded);
                return Err(err);
            }
        }
    }
    sync::spawn_sync(app);
    Ok(outcome)
}

fn imported_chunks(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE as u64).max(1)
}

/// Uploads `file`, read from the import file at `path`, as a new attachment
/// in `vault_id`. Whatever reached the server goes if it fails.
async fn upload_imported(app: &AppHandle, vault_id: &str, path: &Path, file: ImportedFile, progress: &Progress) -> AppResult<Attachment> {
    let attachment = Attachment::new(&file.name, file.size, now_secs())?;
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let path = path.to_path_buf();
    let reporter = progress.clone();
    let reader = tauri::async_runtime::spawn_blocking(move || -> keyless_core::Result<()> {
        let source = File::open(&path).map_err(|e| keyless_core::Error::Import(e.to_string()))?;
        let mut archive = ImportArchive::open(BufReader::new(source))?;
        archive.read_file(&file, |chunk| {
            let len = chunk.len() as u64;
            // Fails once the upload stopped.
            sender.blocking_send(chunk).map_err(|_| keyless_core::Error::Import("the upload stopped".into()))?;
            reporter.add(len);
            Ok(())
        })
    });
    let uploaded = attachments::upload(app, "", vault_id, &attachment, Source::Chunks(receiver)).await;
    let read = reader.await.map_err(|e| AppError::Store(e.to_string()))?;
    match (uploaded, read) {
        (Ok(()), Ok(())) => Ok(attachment),
        (uploaded, read) => {
            attachments::forget(app, vec![Gone::of(vault_id, &attachment)]);
            // The reader knows best what went wrong with the file.
            Err(match read {
                Err(err) => AppError::from(err),
                Ok(()) => uploaded.err().unwrap_or_else(|| AppError::Invalid(Msg::new("attachment_damaged"))),
            })
        }
    }
}

pub fn cancel(state: &AppState) {
    *state.pending_import.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Everything the user can read, except Recently Deleted, by vault; with
/// each vault's id.
async fn collect(state: &AppState) -> AppResult<(BackupData, Vec<String>)> {
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let store = state.store();
    let mut vaults: Vec<(String, BackupVault)> = session
        .vaults
        .iter()
        .map(|(id, v)| (id.clone(), BackupVault { name: v.meta.name.clone(), description: v.meta.description.clone(), items: Vec::new() }))
        .collect();
    for item in store.items()? {
        let Some(cached) = session.items.get(&item.id) else { continue };
        if cached.overview.trashed_at.is_some() {
            continue;
        }
        let (Some(enc), Ok(vault)) = (item.enc_details.as_deref(), session.vault(&item.vault_id)) else { continue };
        let details = vault.key.open_details(&item.vault_id, &item.id, enc)?;
        if let Some((_, target)) = vaults.iter_mut().find(|(id, _)| *id == item.vault_id) {
            target.items.push(BackupItem { overview: cached.overview.clone(), details });
        }
    }
    let (ids, vaults) = vaults.into_iter().unzip();
    Ok((BackupData { exported_at: now_secs(), vaults }, ids))
}

/// Where downloaded attached files go.
trait FileSink {
    fn start(&mut self, attachment: &Attachment) -> keyless_core::Result<()>;
    /// A chunk, as the server keeps it and decrypted.
    fn chunk(&mut self, sealed: &[u8], plaintext: &[u8]) -> keyless_core::Result<()>;
    fn end(&mut self);
    fn abort(&mut self) -> keyless_core::Result<()>;
}

impl<W: Write + Seek> FileSink for BackupWriter<W> {
    fn start(&mut self, attachment: &Attachment) -> keyless_core::Result<()> {
        self.start_file(attachment)
    }
    fn chunk(&mut self, sealed: &[u8], _: &[u8]) -> keyless_core::Result<()> {
        self.write_chunk(sealed)
    }
    fn end(&mut self) {
        self.end_file();
    }
    fn abort(&mut self) -> keyless_core::Result<()> {
        self.abort_file()
    }
}

impl<W: Write + Seek> FileSink for ExportZip<W> {
    fn start(&mut self, attachment: &Attachment) -> keyless_core::Result<()> {
        self.start_file(attachment)
    }
    fn chunk(&mut self, _: &[u8], plaintext: &[u8]) -> keyless_core::Result<()> {
        self.write(plaintext)
    }
    fn end(&mut self) {
        self.end_file();
    }
    fn abort(&mut self) -> keyless_core::Result<()> {
        self.abort_file()
    }
}

/// Downloads the attached files of `data`'s items (its vaults are
/// `vault_ids`) into `sink`, each file once, checking every chunk. Returns
/// the attachments that could not be downloaded whole.
async fn download_files(app: &AppHandle, data: &BackupData, vault_ids: &[String], sink: &mut impl FileSink) -> AppResult<HashSet<String>> {
    let state = app.state::<AppState>();
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for (vault, vault_id) in data.vaults.iter().zip(vault_ids) {
        for attachment in vault.items.iter().flat_map(|i| &i.details.attachments) {
            // Conflict copies of an item list the same file.
            if seen.insert(attachment.id.clone()) {
                files.push((vault_id, attachment));
            }
        }
    }
    let progress = Progress::new(app, files.iter().map(|(_, a)| a.size).sum());
    let mut failed = HashSet::new();
    for (vault_id, attachment) in files {
        let start = progress.done();
        let downloaded = async {
            let key = attachment.key()?;
            sink.start(attachment)?;
            for index in 0..attachment.chunks() {
                let (_, token) = sync::ensure_token(&state).await?;
                let sealed = state.api.download_attachment(&token, &attachment.object_name(vault_id, index)).await?;
                let plaintext = attachment.open_chunk(&key, index, &sealed)?;
                sink.chunk(&sealed, &plaintext)?;
                // A transfer the user started counts as activity for auto-lock.
                state.touch();
                progress.add(plaintext.len() as u64);
            }
            Ok::<(), AppError>(())
        }
        .await;
        match downloaded {
            Ok(()) => sink.end(),
            Err(AppError::Locked) => return Err(AppError::Locked),
            Err(err) => {
                log::warn!("export: an attached file was left out: {err}");
                sink.abort()?;
                failed.insert(attachment.id.clone());
                progress.skip_file(start, attachment.size);
            }
        }
    }
    Ok(failed)
}

/// What an export wrote.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOutcome {
    items: usize,
    files: usize,
    /// Attached files that could not be downloaded (offline, damaged).
    files_missing: usize,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlainFormat {
    Csv,
    Json,
    /// The JSON and the attached files, in a zip archive.
    Zip,
}

/// Exports every vault the user can read into a file that is NOT encrypted,
/// for moving to another password manager. Needs the master password; the
/// UI warns first.
pub async fn export_plain(app: &AppHandle, master_password: Zeroizing<String>, format: PlainFormat) -> AppResult<ExportOutcome> {
    let state = app.state::<AppState>();
    crate::auth::confirm_master_password(&state, master_password).await?;
    let (data, vault_ids) = collect(&state).await?;
    let items = data.vaults.iter().map(|v| v.items.len()).sum();

    let (filter, extension) = match format {
        PlainFormat::Csv => ("CSV", "csv"),
        PlainFormat::Json => ("JSON", "json"),
        PlainFormat::Zip => ("ZIP", "zip"),
    };
    let dialog = app
        .dialog()
        .file()
        .set_title("Save unencrypted export")
        .add_filter(filter, &[extension])
        .set_file_name(format!("keyless-export-{}.{extension}", today()));
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unwritable")))?;

    if !matches!(format, PlainFormat::Zip) {
        tauri::async_runtime::spawn_blocking(move || -> AppResult<()> {
            let contents = Zeroizing::new(match format {
                PlainFormat::Json => keyless_core::export::to_json(&data)?,
                _ => keyless_core::export::to_csv(&data)?,
            });
            write_private(&path, &contents)
        })
        .await
        .map_err(|e| AppError::Store(e.to_string()))??;
        return Ok(ExportOutcome { items, files: 0, files_missing: 0 });
    }

    let part = part_of(&path);
    let written = async {
        let mut export = ExportZip::new(BufWriter::new(create_private(&part)?));
        let failed = download_files(app, &data, &vault_ids, &mut export).await?;
        let files = unique_files(&data) - failed.len();
        finish_off_thread(move || export.finish(&data)).await?;
        Ok(ExportOutcome { items, files, files_missing: failed.len() })
    }
    .await;
    complete(written, &part, &path)
}

/// Exports every vault the user can read, with the attached files, into an
/// encrypted `.keyless` file. Fails with `Cancelled` if no file was chosen.
pub async fn export(app: &AppHandle, master_password: Zeroizing<String>, password: Zeroizing<String>) -> AppResult<ExportOutcome> {
    let state = app.state::<AppState>();
    // A backup holds every secret in the vault: ask for the master password
    // even when the vault was unlocked another way.
    crate::auth::confirm_master_password(&state, master_password).await?;
    // A backup has no Secret Key: its password alone protects it against
    // offline guessing, so it must be strong.
    let normalized = keyless_core::keys::normalize_master_password(&password);
    if normalized.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(AppError::Invalid(Msg::new("backup_password_too_short").with("min", MIN_MASTER_PASSWORD_CHARS)));
    }
    if crate::health::strength(&normalized, &["keyless"]).score < BACKUP_PASSWORD_SCORE {
        return Err(AppError::Invalid(Msg::new("backup_password_weak")));
    }

    let (mut data, vault_ids) = collect(&state).await?;
    let items = data.vaults.iter().map(|v| v.items.len()).sum();

    let dialog = app
        .dialog()
        .file()
        .set_title("Save encrypted backup")
        .add_filter("Keyless backup", &["keyless"])
        .set_file_name(format!("keyless-backup-{}.keyless", today()));
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unwritable")))?;

    let part = part_of(&path);
    let written = async {
        let mut backup = BackupWriter::new(BufWriter::new(create_private(&part)?));
        let failed = download_files(app, &data, &vault_ids, &mut backup).await?;
        // The backup lists only the files it holds.
        for item in data.vaults.iter_mut().flat_map(|v| &mut v.items) {
            item.details.attachments.retain(|a| !failed.contains(&a.id));
        }
        let files = unique_files(&data);
        // Deriving the key takes a while.
        finish_off_thread(move || backup.finish(&password, &data)).await?;
        Ok(ExportOutcome { items, files, files_missing: failed.len() })
    }
    .await;
    complete(written, &part, &path)
}

fn unique_files(data: &BackupData) -> usize {
    data.vaults.iter().flat_map(|v| &v.items).flat_map(|i| &i.details.attachments).map(|a| &a.id).collect::<HashSet<_>>().len()
}

/// Ends an archive away from the async threads and flushes it to disk.
async fn finish_off_thread(finish: impl FnOnce() -> keyless_core::Result<BufWriter<File>> + Send + 'static) -> AppResult<()> {
    tauri::async_runtime::spawn_blocking(move || -> AppResult<()> {
        let unwritable = |e: std::io::Error| AppError::Invalid(Msg::new("file_unwritable").with("detail", e));
        let file = finish()?.into_inner().map_err(|e| unwritable(e.into_error()))?;
        file.sync_all().map_err(unwritable)
    })
    .await
    .map_err(|e| AppError::Store(e.to_string()))?
}

/// The hidden file next to `path` a file is written into; it takes its name
/// only once complete (see [`complete`]).
fn part_of(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "export".into());
    path.with_file_name(format!(".{name}.keyless-part"))
}

/// Gives the written `part` its name, or removes it if writing failed.
fn complete<T>(written: AppResult<T>, part: &Path, path: &Path) -> AppResult<T> {
    match written {
        Ok(value) => {
            std::fs::rename(part, path).map_err(|e| AppError::Invalid(Msg::new("file_unwritable").with("detail", e)))?;
            Ok(value)
        }
        Err(err) => {
            let _ = std::fs::remove_file(part);
            Err(err)
        }
    }
}

/// A new file only this user can read.
fn create_private(path: &Path) -> AppResult<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| AppError::Invalid(Msg::new("file_unwritable").with("detail", e)))
}

fn write_private(path: &Path, contents: &[u8]) -> AppResult<()> {
    let mut file = create_private(path)?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|e| AppError::Invalid(Msg::new("file_unwritable").with("detail", e)))
}

fn today() -> String {
    let days = now_secs().div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}
