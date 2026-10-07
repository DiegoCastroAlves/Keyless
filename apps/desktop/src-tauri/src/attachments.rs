//! Files kept in items (see `keyless_core::attachment` and the `attachments`
//! migration). Each file's name, size and key travel in the item's encrypted
//! details; the server keeps only encrypted chunks. Adding, saving and moving
//! attachments need the network; the item itself syncs as usual.
//!
//! Removing an attachment, or deleting its item for good, deletes its chunks
//! right away, or after a later sync when offline: such deletions wait in a
//! list on this device and are skipped while an item of the vault still
//! lists the attachment (a conflict copy, for example). Chunks this account
//! uploaded to vaults it no longer belongs to are removed too.

use std::{
    collections::HashSet,
    path::PathBuf,
    time::{Duration, Instant},
};

use keyless_core::attachment::{Attachment, CHUNK_OVERHEAD, CHUNK_SIZE};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{
    api::{AttachmentSpace, now_secs},
    error::{AppError, AppResult, Msg},
    items::{self, Extras, ItemSummary},
    state::AppState,
    sync,
};

/// Deletions waiting on this device (store setting).
const PENDING: &str = "attachment_deletions";
pub const EVENT_PROGRESS: &str = "keyless://attachment-progress";
/// How often chunks left in vaults the account no longer belongs to are
/// looked for.
const STRANDED_EVERY: Duration = Duration::from_secs(24 * 3600);

/// One cleanup at a time.
static CLEAN_UP: tokio::sync::Mutex<Option<Instant>> = tokio::sync::Mutex::const_new(None);

/// An attachment whose chunks are to be deleted from the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gone {
    vault_id: String,
    id: String,
    chunks: u32,
}

impl Gone {
    pub fn of(vault_id: &str, attachment: &Attachment) -> Self {
        Self { vault_id: vault_id.to_string(), id: attachment.id.clone(), chunks: attachment.chunks() }
    }

    fn names(&self) -> impl Iterator<Item = String> + '_ {
        (0..self.chunks).map(|i| format!("{}/{}/{i}", self.vault_id, self.id))
    }
}

/// An attachment as the item view shows it (never its key).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub created_at: i64,
}

pub fn view(attachment: &Attachment) -> AttachmentView {
    AttachmentView { id: attachment.id.clone(), name: attachment.name.clone(), size: attachment.size, created_at: attachment.created_at }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    item_id: String,
    name: String,
    /// "upload" or "download".
    direction: &'static str,
    done: u64,
    total: u64,
}

/// The item's vault and attachments; `write` also checks the user may
/// change them.
async fn item_files(state: &AppState, item_id: &str, write: bool) -> AppResult<(String, Vec<Attachment>)> {
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let cached = session.items.get(item_id).ok_or(AppError::NotFound)?;
    if write && !session.vault(&cached.vault_id)?.can_write() {
        return Err(AppError::Invalid(Msg::new("vault_read_only")));
    }
    let (_, details) = items::load_details(state, session, item_id)?;
    Ok((cached.vault_id.clone(), details.attachments.clone()))
}

fn progress(app: &AppHandle, item_id: &str, attachment: &Attachment, direction: &'static str, chunks_done: u32) {
    let done = (chunks_done as u64 * CHUNK_SIZE as u64).min(attachment.size);
    let _ = app.emit(EVENT_PROGRESS, Progress { item_id: item_id.to_string(), name: attachment.name.clone(), direction, done, total: attachment.size });
}

/// Asks for a file and adds it to item `item_id`.
pub async fn add(app: &AppHandle, item_id: &str) -> AppResult<ItemSummary> {
    let state = app.state::<AppState>();
    let (vault_id, _) = item_files(&state, item_id, true).await?;

    let dialog = app.dialog().file().set_title("Choose a file to attach");
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_pick_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unreadable")))?;
    let unreadable = |e: std::io::Error| AppError::Invalid(Msg::new("file_unreadable").with("detail", e));
    let meta = tokio::fs::metadata(&path).await.map_err(unreadable)?;
    if !meta.is_file() {
        return Err(AppError::Invalid(Msg::new("file_unreadable")));
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let attachment = Attachment::new(&name, meta.len(), now_secs())?;

    // Room for it: the server checks a whole chunk ahead.
    let (_, token) = sync::ensure_token(&state).await?;
    if let Some(space) = state.api.attachment_space(&token).await? {
        let needed = attachment.size + attachment.chunks() as u64 * CHUNK_OVERHEAD as u64;
        if space.used + needed + (CHUNK_SIZE + CHUNK_OVERHEAD) as u64 > space.quota {
            return Err(AppError::Invalid(Msg::new("attachment_space_full").with("quota", space.quota / (1024 * 1024))));
        }
    }

    let uploaded = upload(app, item_id, &vault_id, &attachment, path).await;
    if let Err(err) = uploaded {
        // Whatever reached the server goes.
        forget(app, vec![Gone::of(&vault_id, &attachment)]);
        return Err(err);
    }

    let draft = items::get_item_draft(&state, item_id).await?;
    let (now_in, mut list) = item_files(&state, item_id, true).await?;
    if now_in != vault_id {
        // The item moved meanwhile.
        forget(app, vec![Gone::of(&vault_id, &attachment)]);
        return Err(AppError::Invalid(Msg::new("attachment_item_moved")));
    }
    list.push(attachment.clone());
    match items::save_item_with(app, draft, Extras { attachments: Some(list), ..Default::default() }).await {
        Ok(summary) => Ok(summary),
        Err(err) => {
            forget(app, vec![Gone::of(&vault_id, &attachment)]);
            Err(err)
        }
    }
}

async fn upload(app: &AppHandle, item_id: &str, vault_id: &str, attachment: &Attachment, path: PathBuf) -> AppResult<()> {
    let state = app.state::<AppState>();
    let key = attachment.key()?;
    let changed = || AppError::Invalid(Msg::new("file_changed"));
    let mut file = tokio::fs::File::open(&path).await.map_err(|e| AppError::Invalid(Msg::new("file_unreadable").with("detail", e)))?;
    progress(app, item_id, attachment, "upload", 0);
    for index in 0..attachment.chunks() {
        let mut chunk = Zeroizing::new(vec![0u8; attachment.chunk_len(index)]);
        file.read_exact(&mut chunk).await.map_err(|_| changed())?;
        let sealed = attachment.seal_chunk(&key, index, &chunk)?;
        drop(chunk);
        // The session may need refreshing during a long upload.
        let (_, token) = sync::ensure_token(&state).await?;
        state.api.upload_attachment(&token, &attachment.object_name(vault_id, index), sealed).await?;
        // A transfer the user started counts as activity for auto-lock.
        state.touch();
        progress(app, item_id, attachment, "upload", index + 1);
    }
    // The file must not have grown while it was read.
    let mut more = [0u8; 1];
    if file.read(&mut more).await.map_err(|_| changed())? != 0 {
        return Err(changed());
    }
    Ok(())
}

/// Asks where to save attachment `attachment_id` of item `item_id`, then
/// downloads and decrypts it there. A file is written under its final name
/// only once every chunk checked out.
pub async fn save(app: &AppHandle, item_id: &str, attachment_id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let (vault_id, list) = item_files(&state, item_id, false).await?;
    let attachment = list.into_iter().find(|a| a.id == attachment_id).ok_or(AppError::NotFound)?;
    let key = attachment.key().map_err(|_| AppError::Invalid(Msg::new("attachment_damaged")))?;

    let dialog = app.dialog().file().set_title("Save attachment").set_file_name(&attachment.name);
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unwritable")))?;
    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "attachment".into());
    let part = path.with_file_name(format!(".{file_name}.keyless-part"));

    let written = async {
        let unwritable = |e: std::io::Error| AppError::Invalid(Msg::new("file_unwritable").with("detail", e));
        let mut out = tokio::fs::File::create(&part).await.map_err(unwritable)?;
        progress(app, item_id, &attachment, "download", 0);
        for index in 0..attachment.chunks() {
            let (_, token) = sync::ensure_token(&state).await?;
            let raw = state.api.download_attachment(&token, &attachment.object_name(&vault_id, index)).await.map_err(|err| match err {
                AppError::NotFound => AppError::Invalid(Msg::new("attachment_missing")),
                other => other,
            })?;
            let plain = attachment.open_chunk(&key, index, &raw).map_err(|_| AppError::Invalid(Msg::new("attachment_damaged")))?;
            out.write_all(&plain).await.map_err(unwritable)?;
            state.touch();
            progress(app, item_id, &attachment, "download", index + 1);
        }
        out.sync_all().await.map_err(unwritable)?;
        Ok::<(), AppError>(())
    }
    .await;
    match written {
        Ok(()) => tokio::fs::rename(&part, &path).await.map_err(|e| AppError::Invalid(Msg::new("file_unwritable").with("detail", e))),
        Err(err) => {
            let _ = tokio::fs::remove_file(&part).await;
            Err(err)
        }
    }
}

/// Removes attachment `attachment_id` from item `item_id`; its file is
/// deleted from the server for good.
pub async fn delete(app: &AppHandle, item_id: &str, attachment_id: &str) -> AppResult<ItemSummary> {
    let state = app.state::<AppState>();
    let draft = items::get_item_draft(&state, item_id).await?;
    let (vault_id, mut list) = item_files(&state, item_id, true).await?;
    let index = list.iter().position(|a| a.id == attachment_id).ok_or(AppError::NotFound)?;
    let gone = Gone::of(&vault_id, &list.remove(index));
    let summary = items::save_item_with(app, draft, Extras { attachments: Some(list), ..Default::default() }).await?;
    forget(app, vec![gone]);
    Ok(summary)
}

/// Before item `item_id` moves to `to_vault`: copies its attachments there
/// (needs the network). Returns the old copies, to forget once the move is
/// saved; `None` when the item stays where it is or has no attachments.
pub async fn copy_for_move(app: &AppHandle, item_id: &str, to_vault: &str) -> AppResult<Option<Vec<Gone>>> {
    let state = app.state::<AppState>();
    let (from_vault, list) = match item_files(&state, item_id, false).await {
        Ok(files) => files,
        // Not an item this can move: the caller says why.
        Err(AppError::NotFound) => return Ok(None),
        Err(err) => return Err(err),
    };
    if from_vault == to_vault || list.is_empty() {
        return Ok(None);
    }
    for attachment in &list {
        for index in 0..attachment.chunks() {
            let (_, token) = sync::ensure_token(&state).await?;
            state
                .api
                .copy_attachment(&token, &attachment.object_name(&from_vault, index), &attachment.object_name(to_vault, index))
                .await?;
        }
    }
    Ok(Some(list.iter().map(|a| Gone::of(&from_vault, a)).collect()))
}

/// How much attachment space the account uses.
pub async fn space(state: &AppState) -> AppResult<Option<AttachmentSpace>> {
    let (_, token) = sync::ensure_token(state).await?;
    state.api.attachment_space(&token).await
}

/// Deletes these attachments' chunks from the server, now or after a later
/// sync.
pub fn forget(app: &AppHandle, gone: Vec<Gone>) {
    if gone.is_empty() {
        return;
    }
    {
        let state = app.state::<AppState>();
        let store = state.store();
        let mut pending: Vec<Gone> = store.setting(PENDING).ok().flatten().unwrap_or_default();
        for g in gone {
            if !pending.contains(&g) {
                pending.push(g);
            }
        }
        let _ = store.set_setting(PENDING, &pending);
    }
    spawn_clean_up(app);
}

pub fn spawn_clean_up(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { clean_up(&app).await });
}

/// Runs the deletions waiting on this device, then (once a day) removes the
/// chunks this account left in vaults it no longer belongs to.
async fn clean_up(app: &AppHandle) {
    let state = app.state::<AppState>();
    let mut last_stranded = CLEAN_UP.lock().await;
    let pending: Vec<Gone> = state.store().setting(PENDING).ok().flatten().unwrap_or_default();
    let stranded_due = last_stranded.is_none_or(|at| at.elapsed() >= STRANDED_EVERY);
    if pending.is_empty() && !stranded_due {
        return;
    }
    let Ok((_, token)) = sync::ensure_token(&state).await else { return };

    if !pending.is_empty() {
        // Attachments an item of their vault still lists stay; so does
        // everything in a vault whose items could not all be read.
        let (listed, unsure) = {
            let guard = state.session.lock().await;
            let Some(session) = guard.as_ref() else { return };
            let mut listed = HashSet::new();
            let mut unsure = HashSet::new();
            for (id, cached) in &session.items {
                match items::load_details(&state, session, id) {
                    Ok((_, details)) => listed.extend(details.attachments.iter().map(|a| (cached.vault_id.clone(), a.id.clone()))),
                    Err(_) => {
                        unsure.insert(cached.vault_id.clone());
                    }
                }
            }
            (listed, unsure)
        };
        let (keep, delete): (Vec<Gone>, Vec<Gone>) = pending.iter().cloned().partition(|g| unsure.contains(&g.vault_id));
        let delete: Vec<Gone> = delete.into_iter().filter(|g| !listed.contains(&(g.vault_id.clone(), g.id.clone()))).collect();
        let names: Vec<String> = delete.iter().flat_map(Gone::names).collect();
        if names.is_empty() || state.api.delete_attachments(&token, &names).await.is_ok() {
            // Done with all but those kept for later (others may have been
            // added meanwhile).
            let store = state.store();
            let now: Vec<Gone> = store.setting(PENDING).ok().flatten().unwrap_or_default();
            let left: Vec<Gone> = now.into_iter().filter(|g| keep.contains(g) || !pending.contains(g)).collect();
            let _ = store.set_setting(PENDING, &left);
        }
    }

    if stranded_due {
        match state.api.stranded_attachments(&token).await {
            Ok(names) => {
                if names.is_empty() || state.api.delete_attachments(&token, &names).await.is_ok() {
                    *last_stranded = Some(Instant::now());
                }
            }
            Err(err) => log::info!("stranded attachments: {err}"),
        }
    }
}
