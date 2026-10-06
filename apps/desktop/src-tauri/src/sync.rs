//! Synchronisation with the server.
//!
//! Local writes go to SQLite first (marked dirty) and are pushed in the
//! background, so the app keeps working offline. Pulls are incremental per
//! vault using the server's per-vault counter (`seq`).
//!
//! Nothing from the server is trusted blindly:
//!
//! - content must decrypt with the vault key, the overview and details must
//!   come from the same write, and the version must not go backwards
//!   (rollback protection);
//! - deletions must carry a tombstone encrypted with the vault key, newer
//!   than our copy;
//! - a vault disappearing from the server never deletes the local copy.
//!
//! Anything that fails these checks is ignored and our copy is uploaded
//! again, which repairs the server. Conflicts (an item edited on two
//! devices) never lose data: the most recent edit wins and the other one is
//! kept as a "conflicted copy".

use std::time::Duration;

use keyless_core::{
    crypto::SymmetricKey,
    item::{ItemDetails, ItemOverview, same_write, stamp_version},
    vault::VaultKey,
};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::{
    api::{RemoteItem, now_secs},
    error::{AppError, AppResult, Msg},
    state::{AppState, CachedItem, OpenVault, Session, SyncStatus, Tokens},
    store::{Dirty, LocalItem, LocalVault, Store},
};

pub const EVENT_ITEMS_CHANGED: &str = "keyless://items-changed";
pub const EVENT_SYNC_STATUS: &str = "keyless://sync-status";
pub const EVENT_LOCKED: &str = "keyless://locked";

const PAGE: usize = 500;
pub const ORPHANED_ROLE: &str = "orphaned";

/// Decrypts and caches an item's overview. Returns false if it could not be
/// decrypted.
pub fn cache_item(session: &mut Session, item: &LocalItem) -> bool {
    if item.deleted {
        session.items.remove(&item.id);
        return true;
    }
    let (Some(enc_overview), Some(vault)) = (item.enc_overview.as_deref(), session.vaults.get(&item.vault_id)) else {
        return false;
    };
    match vault.key.open_overview(&item.vault_id, &item.id, enc_overview) {
        Ok(overview) => {
            session
                .items
                .insert(item.id.clone(), CachedItem { vault_id: item.vault_id.clone(), overview });
            true
        }
        Err(err) => {
            log::warn!("item {} could not be decrypted: {err}", item.id);
            false
        }
    }
}

/// Unwraps a vault key and decrypts its metadata.
pub fn unlock_vault(user_key: &SymmetricKey, vault: &LocalVault) -> Option<OpenVault> {
    let key = match VaultKey::unwrap(user_key, &vault.id, &vault.enc_vault_key) {
        Ok(key) => key,
        Err(err) => {
            log::warn!("vault {} key could not be decrypted: {err}", vault.id);
            return None;
        }
    };
    let meta = match key.open_meta(&vault.id, &vault.enc_meta) {
        Ok(meta) => meta,
        Err(err) => {
            log::warn!("vault {} metadata could not be decrypted: {err}", vault.id);
            return None;
        }
    };
    Some(OpenVault { key, meta, role: vault.role.clone() })
}

pub fn open_vault(session: &mut Session, vault: &LocalVault) -> bool {
    match unlock_vault(session.account.user_key(), vault) {
        Some(open) => {
            session.vaults.insert(vault.id.clone(), open);
            true
        }
        None => false,
    }
}

/// Builds the in-memory caches from the local database.
pub fn load_caches(session: &mut Session, store: &Store) -> AppResult<()> {
    session.vaults.clear();
    session.items.clear();
    for vault in store.vaults()? {
        open_vault(session, &vault);
    }
    let mut unreadable = 0;
    for item in store.items()? {
        if !cache_item(session, &item) {
            unreadable += 1;
        }
    }
    session.unreadable_items = unreadable;
    Ok(())
}

/// Returns `(user_id, access_token)`, refreshing the session if needed.
pub async fn ensure_token(state: &AppState) -> AppResult<(String, Zeroizing<String>)> {
    let refresh = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        match &session.tokens {
            Some(tokens) if tokens.expires_at - 60 > now_secs() => {
                return Ok((session.user_id.clone(), tokens.access.clone()));
            }
            Some(tokens) => tokens.refresh.clone(),
            None => {
                // Fall back to the refresh token saved (encrypted) on disk.
                let account = state.store().account()?.ok_or(AppError::NoAccount)?;
                let enc = account
                    .enc_session
                    .ok_or_else(|| AppError::Auth(Msg::new("session_expired")))?;
                let bytes = session.account.user_key().open(&enc, &session.session_context())?;
                Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| AppError::Store("corrupt session".into()))?)
            }
        }
    };

    let refreshed = state.api.refresh(&refresh).await;
    let mut guard = state.session.lock().await;
    let session = guard.as_mut().ok_or(AppError::Locked)?;
    match refreshed {
        Ok(auth) => {
            let enc = session
                .account
                .user_key()
                .seal(auth.refresh_token.as_bytes(), &session.session_context())?;
            state.store().set_enc_session(&session.user_id, Some(&enc))?;
            let access = auth.access_token.clone();
            session.tokens = Some(Tokens::from(auth));
            Ok((session.user_id.clone(), access))
        }
        Err(AppError::Auth(_)) => {
            session.tokens = None;
            state.store().set_enc_session(&session.user_id, None)?;
            Err(AppError::Auth(Msg::new("session_expired")))
        }
        Err(err) => Err(err),
    }
}

// ----- verification ---------------------------------------------------------

/// What to do with an item received from the server.
enum Verdict {
    /// Authentic content at least as new as ours.
    Accept { version: u64 },
    /// Authentic deletion newer than our copy.
    Delete { version: u64 },
    /// Forged, stale or mixed: keep (and re-upload) our copy.
    Reject,
}

fn open_pair(vault: &OpenVault, vault_id: &str, id: &str, enc_overview: &str, enc_details: &str) -> Option<(ItemOverview, ItemDetails)> {
    let overview = vault.key.open_overview(vault_id, id, enc_overview).ok()?;
    let details = vault.key.open_details(vault_id, id, enc_details).ok()?;
    same_write(&overview, &details).then_some((overview, details))
}

fn local_content_id(vault: &OpenVault, local: &LocalItem) -> Option<String> {
    let enc = local.enc_overview.as_deref()?;
    vault.key.open_overview(&local.vault_id, &local.id, enc).ok().map(|o| o.content_id)
}

fn verify(vault: &OpenVault, remote: &RemoteItem, local: Option<&LocalItem>) -> Verdict {
    let local_version = local.map(|l| l.version).unwrap_or(0);
    if remote.deleted_at.is_some() {
        let tombstone = remote
            .enc_tombstone
            .as_deref()
            .and_then(|t| vault.key.open_tombstone(&remote.vault_id, &remote.id, t).ok());
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
    let Some((overview, _)) = open_pair(vault, &remote.vault_id, &remote.id, enc_overview, enc_details) else {
        return Verdict::Reject;
    };
    match local {
        None => Verdict::Accept { version: overview.version },
        Some(l) if overview.version > local_version => {
            let _ = l;
            Verdict::Accept { version: overview.version }
        }
        Some(l) if overview.version == local_version && !l.deleted => {
            if local_content_id(vault, l).as_deref() == Some(overview.content_id.as_str()) {
                Verdict::Accept { version: overview.version }
            } else {
                Verdict::Reject
            }
        }
        // Older than our copy (rollback) or older than our deletion.
        Some(_) => Verdict::Reject,
    }
}

fn apply_accepted(store: &Store, session: &mut Session, remote: &RemoteItem, version: u64) -> AppResult<()> {
    let local = LocalItem {
        id: remote.id.clone(),
        vault_id: remote.vault_id.clone(),
        enc_overview: remote.enc_overview.clone(),
        enc_details: remote.enc_details.clone(),
        revision: remote.revision,
        seq: remote.seq,
        deleted: false,
        dirty: Dirty::Clean,
        version,
        enc_tombstone: None,
    };
    store.upsert_item(&local)?;
    cache_item(session, &local);
    Ok(())
}

fn apply_deletion(store: &Store, session: &mut Session, remote: &RemoteItem, version: u64) -> AppResult<()> {
    // Keep a local tombstone so an older copy can never come back.
    let tombstone = LocalItem {
        id: remote.id.clone(),
        vault_id: remote.vault_id.clone(),
        enc_overview: None,
        enc_details: None,
        revision: remote.revision,
        seq: remote.seq,
        deleted: true,
        dirty: Dirty::Clean,
        version,
        enc_tombstone: remote.enc_tombstone.clone(),
    };
    store.upsert_item(&tombstone)?;
    session.items.remove(&remote.id);
    Ok(())
}

/// The server copy failed verification: schedule our copy (or, if we have
/// none, the server's last authentic content) to be uploaded again.
fn schedule_repair(store: &Store, vault: &OpenVault, remote: &RemoteItem, local: Option<LocalItem>) -> AppResult<Option<LocalItem>> {
    match local {
        Some(mut local) => {
            local.revision = remote.revision;
            local.dirty = if local.deleted { Dirty::Delete } else { Dirty::Upsert };
            store.upsert_item(&local)?;
            log::warn!("item {}: server copy rejected, re-uploading ours", local.id);
            Ok(None)
        }
        None => {
            // A deletion without proof of an item we never had: restore the
            // server's content if it is authentic.
            let (Some(o), Some(d)) = (remote.enc_overview.as_deref(), remote.enc_details.as_deref()) else {
                return Ok(None);
            };
            let Some((overview, _)) = open_pair(vault, &remote.vault_id, &remote.id, o, d) else {
                return Ok(None);
            };
            let restored = LocalItem {
                id: remote.id.clone(),
                vault_id: remote.vault_id.clone(),
                enc_overview: Some(o.to_string()),
                enc_details: Some(d.to_string()),
                revision: remote.revision,
                seq: remote.seq,
                deleted: false,
                dirty: Dirty::Upsert,
                version: overview.version,
                enc_tombstone: None,
            };
            store.upsert_item(&restored)?;
            Ok(Some(restored))
        }
    }
}

// ----- push -------------------------------------------------------------------

fn content_body(item: &LocalItem) -> Value {
    json!({
        "enc_overview": item.enc_overview,
        "enc_details": item.enc_details,
        "enc_tombstone": Value::Null,
    })
}

fn mark_pushed(store: &Store, session: Option<&mut Session>, pushed: &LocalItem, remote: &RemoteItem) -> AppResult<()> {
    // Only mark clean if nothing changed locally while we were uploading.
    match store.item(&pushed.id)? {
        Some(mut current)
            if current.enc_overview == pushed.enc_overview
                && current.enc_details == pushed.enc_details
                && current.enc_tombstone == pushed.enc_tombstone =>
        {
            current.revision = remote.revision;
            current.seq = remote.seq;
            current.dirty = Dirty::Clean;
            store.upsert_item(&current)?;
            if let Some(session) = session {
                cache_item(session, &current);
            }
        }
        Some(mut current) => {
            current.revision = remote.revision;
            store.upsert_item(&current)?;
        }
        None => {}
    }
    Ok(())
}

async fn push(state: &AppState) -> AppResult<bool> {
    let dirty = state.store().dirty_items()?;
    if dirty.is_empty() {
        return Ok(false);
    }
    let (_, token) = ensure_token(state).await?;
    let mut changed = false;

    for item in dirty {
        let result = match item.dirty {
            Dirty::Clean => continue,
            Dirty::Delete if item.revision == 0 => {
                // Never uploaded: nothing to delete on the server.
                let mut clean = item.clone();
                clean.dirty = Dirty::Clean;
                state.store().upsert_item(&clean)?;
                continue;
            }
            Dirty::Delete => {
                let body = json!({ "enc_tombstone": item.enc_tombstone });
                match state.api.update_item(&token, &item.id, item.revision, &body).await? {
                    Some(remote) => Some(remote),
                    None => resolve_conflict(state, &token, &item).await?,
                }
            }
            Dirty::Upsert if item.revision == 0 => {
                match state
                    .api
                    .insert_item(
                        &token,
                        &item.id,
                        &item.vault_id,
                        item.enc_overview.as_deref().unwrap_or_default(),
                        item.enc_details.as_deref().unwrap_or_default(),
                    )
                    .await?
                {
                    Some(remote) => Some(remote),
                    // Already exists (a lost response): reconcile.
                    None => resolve_conflict(state, &token, &item).await?,
                }
            }
            Dirty::Upsert => match state.api.update_item(&token, &item.id, item.revision, &content_body(&item)).await? {
                Some(remote) => Some(remote),
                None => resolve_conflict(state, &token, &item).await?,
            },
        };
        if let Some(remote) = result {
            let mut guard = state.session.lock().await;
            let store = state.store();
            let pushed = store.item(&item.id)?.unwrap_or_else(|| item.clone());
            mark_pushed(&store, guard.as_mut(), &pushed, &remote)?;
            changed = true;
        }
    }
    Ok(changed)
}

/// Re-encrypts an item's content with a new version.
fn restamp(vault: &OpenVault, item: &LocalItem, version: u64) -> AppResult<(String, String)> {
    let (Some(o), Some(d)) = (item.enc_overview.as_deref(), item.enc_details.as_deref()) else {
        return Err(AppError::NotFound);
    };
    let mut overview = vault.key.open_overview(&item.vault_id, &item.id, o)?;
    let mut details = vault.key.open_details(&item.vault_id, &item.id, d)?;
    stamp_version(&mut overview, &mut details, version);
    Ok((
        vault.key.seal_overview(&item.vault_id, &item.id, &overview)?,
        vault.key.seal_details(&item.vault_id, &item.id, &details)?,
    ))
}

enum Plan {
    /// Write this body (our content or tombstone) over the server's copy.
    Overwrite { body: Value, version: u64 },
    /// The server copy wins; nothing to upload.
    TakeRemote,
}

/// The server has a different revision than the one our change is based on.
async fn resolve_conflict(state: &AppState, token: &str, local: &LocalItem) -> AppResult<Option<RemoteItem>> {
    let Some(remote) = state.api.item(token, &local.id).await? else {
        return Ok(None);
    };

    let (plan, conflict_copy) = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        let vault = session.vault(&local.vault_id)?;
        plan_conflict(vault, local, &remote)?
    };

    if let Some(copy) = conflict_copy {
        state.store().upsert_item(&copy)?;
    }
    match plan {
        Plan::TakeRemote => {
            let mut guard = state.session.lock().await;
            let store = state.store();
            if let Some(session) = guard.as_mut()
                && let Some(vault) = session.vaults.get(&remote.vault_id)
            {
                match verify(vault, &remote, None) {
                    Verdict::Accept { version } => apply_accepted(&store, session, &remote, version)?,
                    Verdict::Delete { version } => apply_deletion(&store, session, &remote, version)?,
                    Verdict::Reject => {}
                }
            }
            Ok(None)
        }
        Plan::Overwrite { body, version } => {
            let written = state.api.update_item(token, &local.id, remote.revision, &body).await?;
            if let Some(remote) = &written {
                // Record what we actually wrote as the local copy.
                let mut updated = local.clone();
                if let Some(o) = body.get("enc_overview").and_then(Value::as_str) {
                    updated.enc_overview = Some(o.to_string());
                }
                if let Some(d) = body.get("enc_details").and_then(Value::as_str) {
                    updated.enc_details = Some(d.to_string());
                }
                updated.version = version;
                updated.revision = remote.revision;
                state.store().upsert_item(&updated)?;
            }
            Ok(written)
        }
    }
}

fn plan_conflict(vault: &OpenVault, local: &LocalItem, remote: &RemoteItem) -> AppResult<(Plan, Option<LocalItem>)> {
    let own_body = |item: &LocalItem| {
        if item.deleted { json!({ "enc_tombstone": item.enc_tombstone }) } else { content_body(item) }
    };
    match verify(vault, remote, None) {
        // Forged server copy: ours wins as is.
        Verdict::Reject => Ok((Plan::Overwrite { body: own_body(local), version: local.version }, None)),
        Verdict::Delete { .. } if local.deleted => Ok((Plan::TakeRemote, None)),
        Verdict::Delete { version: remote_version } => {
            // Deleted elsewhere but edited here: keep the edit.
            let version = local.version.max(remote_version) + 1;
            let (o, d) = restamp(vault, local, version)?;
            Ok((Plan::Overwrite { body: json!({ "enc_overview": o, "enc_details": d, "enc_tombstone": Value::Null }), version }, None))
        }
        // Edited elsewhere, deleted here: the edit survives.
        Verdict::Accept { .. } if local.deleted => Ok((Plan::TakeRemote, None)),
        Verdict::Accept { version: remote_version } => {
            let remote_overview = vault
                .key
                .open_overview(&remote.vault_id, &remote.id, remote.enc_overview.as_deref().unwrap_or_default())?;
            let local_overview = vault
                .key
                .open_overview(&local.vault_id, &local.id, local.enc_overview.as_deref().unwrap_or_default())?;
            if remote_overview.content_id == local_overview.content_id {
                return Ok((Plan::TakeRemote, None));
            }
            let local_newer = local_overview.updated_at >= remote_overview.updated_at;
            // The losing version is kept as a new item.
            let loser = if local_newer {
                (remote.enc_overview.as_deref(), remote.enc_details.as_deref())
            } else {
                (local.enc_overview.as_deref(), local.enc_details.as_deref())
            };
            let copy = match loser {
                (Some(o), Some(d)) => {
                    let mut overview = vault.key.open_overview(&local.vault_id, &local.id, o)?;
                    let mut details = vault.key.open_details(&local.vault_id, &local.id, d)?;
                    overview.title = format!("{} (conflicted copy)", overview.title);
                    stamp_version(&mut overview, &mut details, 1);
                    let new_id = uuid::Uuid::new_v4().to_string();
                    Some(LocalItem {
                        enc_overview: Some(vault.key.seal_overview(&local.vault_id, &new_id, &overview)?),
                        enc_details: Some(vault.key.seal_details(&local.vault_id, &new_id, &details)?),
                        id: new_id,
                        vault_id: local.vault_id.clone(),
                        revision: 0,
                        seq: 0,
                        deleted: false,
                        dirty: Dirty::Upsert,
                        version: 1,
                        enc_tombstone: None,
                    })
                }
                _ => None,
            };
            if local_newer {
                let version = local.version.max(remote_version) + 1;
                let (o, d) = restamp(vault, local, version)?;
                Ok((Plan::Overwrite { body: json!({ "enc_overview": o, "enc_details": d, "enc_tombstone": Value::Null }), version }, copy))
            } else {
                Ok((Plan::TakeRemote, copy))
            }
        }
    }
}

// ----- pull -------------------------------------------------------------------

async fn pull(state: &AppState) -> AppResult<bool> {
    let (user_id, token) = ensure_token(state).await?;
    let memberships = state.api.memberships(&token, &user_id).await?;
    let mut changed = false;
    let mut restore: Vec<String> = Vec::new();
    let mut active: Vec<String> = Vec::new();

    // Vaults: add/update what we are a member of; deletions need a proof.
    {
        let mut guard = state.session.lock().await;
        let session = guard.as_mut().ok_or(AppError::Locked)?;
        let store = state.store();
        let known = store.vaults()?;
        for m in &memberships {
            let vault = LocalVault {
                id: m.vault_id.clone(),
                owner_id: m.vaults.owner_id.clone(),
                role: m.role.clone(),
                enc_meta: m.vaults.enc_meta.clone(),
                enc_vault_key: m.enc_vault_key.clone(),
                seq: m.vaults.seq,
            };
            // Metadata and key are verified by decrypting them first.
            let Some(opened) = unlock_vault(session.account.user_key(), &vault) else {
                continue;
            };
            if m.vaults.deleted_at.is_some() {
                let genuine = m
                    .vaults
                    .enc_tombstone
                    .as_deref()
                    .is_some_and(|t| opened.key.open_vault_tombstone(&vault.id, t).is_ok());
                if genuine {
                    if known.iter().any(|v| v.id == vault.id) {
                        store.delete_vault(&vault.id)?;
                        session.vaults.remove(&vault.id);
                        session.items.retain(|_, item| item.vault_id != vault.id);
                        changed = true;
                    }
                    continue;
                }
                // A deletion without a valid proof: undo it.
                if m.role == "owner" {
                    restore.push(vault.id.clone());
                }
            }
            if !known.iter().any(|v| v.id == vault.id && v.role == vault.role && v.enc_meta == vault.enc_meta) {
                changed = true;
            }
            store.upsert_vault(&vault)?;
            session.vaults.insert(vault.id.clone(), opened);
            active.push(vault.id.clone());
        }
        // Vaults that disappeared from the server are kept locally, read-only.
        for mut vault in known {
            if !memberships.iter().any(|m| m.vault_id == vault.id) && vault.role != ORPHANED_ROLE {
                log::warn!("vault {} is no longer on the server; keeping the local copy", vault.id);
                vault.role = ORPHANED_ROLE.into();
                store.upsert_vault(&vault)?;
                if let Some(open) = session.vaults.get_mut(&vault.id) {
                    open.role = ORPHANED_ROLE.into();
                }
                changed = true;
            }
        }
    }

    for vault_id in restore {
        if let Err(err) = state.api.restore_vault(&token, &vault_id).await {
            log::warn!("could not restore vault {vault_id}: {err}");
        }
    }

    // Items, per vault, from the last cursor.
    for vault_id in &active {
        loop {
            let cursor = state.store().cursor(vault_id)?;
            let page = state.api.items_since(&token, vault_id, cursor, PAGE).await?;
            if page.is_empty() {
                break;
            }
            let mut guard = state.session.lock().await;
            let session = guard.as_mut().ok_or(AppError::Locked)?;
            let store = state.store();
            let mut max_seq = cursor;
            for remote in &page {
                max_seq = max_seq.max(remote.seq);
                if &remote.vault_id != vault_id {
                    continue;
                }
                let local = store.item(&remote.id)?;
                if local.as_ref().is_some_and(|l| l.dirty != Dirty::Clean) {
                    // Our pending change is pushed (and reconciled) first.
                    continue;
                }
                let Some(vault) = session.vaults.get(vault_id) else { continue };
                let same_ciphertext = local
                    .as_ref()
                    .is_some_and(|l| !l.deleted && l.enc_overview == remote.enc_overview && l.enc_details == remote.enc_details);
                match verify(vault, remote, local.as_ref()) {
                    Verdict::Accept { .. } if same_ciphertext => {
                        // Our own write coming back: just record the counters.
                        let mut l = local.clone().expect("same_ciphertext implies a local copy");
                        l.revision = remote.revision;
                        l.seq = remote.seq;
                        store.upsert_item(&l)?;
                    }
                    Verdict::Accept { version } => {
                        apply_accepted(&store, session, remote, version)?;
                        changed = true;
                    }
                    Verdict::Delete { version } => {
                        apply_deletion(&store, session, remote, version)?;
                        changed = true;
                    }
                    Verdict::Reject => {
                        if let Some(restored) = schedule_repair(&store, vault, remote, local)? {
                            cache_item(session, &restored);
                        }
                        changed = true;
                    }
                }
            }
            store.set_cursor(vault_id, max_seq)?;
            if page.len() < PAGE {
                break;
            }
        }
    }
    Ok(changed)
}

/// Pushes local changes and pulls remote ones. Safe to call concurrently:
/// calls are serialised.
pub async fn sync_now(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let _gate = state.sync_gate.lock().await;
    if state.session.lock().await.is_none() {
        return Err(AppError::Locked);
    }
    let previous = state.sync_status();
    state.set_sync_status(SyncStatus { state: "syncing".into(), ..previous.clone() });
    let _ = app.emit(EVENT_SYNC_STATUS, state.sync_status());

    let result = async {
        let pushed = push(&state).await?;
        let pulled = pull(&state).await?;
        // Repairs and conflict copies produced by the pull.
        let pushed_again = push(&state).await?;
        Ok::<bool, AppError>(pushed || pulled || pushed_again)
    }
    .await;

    let status = match &result {
        Ok(_) => SyncStatus { state: "idle".into(), last_synced_at: Some(now_secs()), message: None },
        Err(AppError::Offline) => SyncStatus { state: "offline".into(), ..previous.clone() },
        Err(AppError::Auth(_)) => SyncStatus { state: "signed_out".into(), ..previous.clone() },
        Err(AppError::Locked) => previous.clone(),
        Err(err) => SyncStatus { state: "error".into(), message: Some(err.to_string()), ..previous.clone() },
    };
    state.set_sync_status(status);
    let _ = app.emit(EVENT_SYNC_STATUS, state.sync_status());
    match result {
        Ok(changed) => {
            if changed {
                let _ = app.emit(EVENT_ITEMS_CHANGED, ());
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Starts a sync in the background without waiting for it.
pub fn spawn_sync(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(err) = sync_now(&app).await {
            log::info!("sync: {err}");
        }
    });
}

/// Periodic sync while unlocked.
pub fn start_background_sync(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let unlocked = app.state::<AppState>().session.lock().await.is_some();
            if unlocked && let Err(err) = sync_now(&app).await {
                log::info!("background sync: {err}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyless_core::{
        item::{Category, Field, FieldKind, FieldPurpose},
        vault::{Tombstone, VaultMeta},
    };

    fn vault() -> OpenVault {
        OpenVault { key: VaultKey::generate().unwrap(), meta: VaultMeta::default(), role: "owner".into() }
    }

    fn content(vault: &OpenVault, id: &str, version: u64, password: &str) -> (String, String) {
        let mut overview = ItemOverview { title: "t".into(), category: Category::Login, ..Default::default() };
        let mut details = ItemDetails::default();
        details.fields.push(Field {
            id: "p".into(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: password.into(),
            purpose: Some(FieldPurpose::Password),
        });
        stamp_version(&mut overview, &mut details, version);
        (vault.key.seal_overview("v", id, &overview).unwrap(), vault.key.seal_details("v", id, &details).unwrap())
    }

    fn remote(o: Option<String>, d: Option<String>, tombstone: Option<String>) -> RemoteItem {
        RemoteItem {
            id: "i".into(),
            vault_id: "v".into(),
            deleted_at: tombstone.as_ref().map(|_| "2026-01-01T00:00:00Z".into()),
            enc_overview: o,
            enc_details: d,
            enc_tombstone: tombstone,
            revision: 5,
            seq: 9,
        }
    }

    fn local(o: &str, d: &str, version: u64) -> LocalItem {
        LocalItem {
            id: "i".into(),
            vault_id: "v".into(),
            enc_overview: Some(o.into()),
            enc_details: Some(d.into()),
            revision: 4,
            seq: 8,
            deleted: false,
            dirty: Dirty::Clean,
            version,
            enc_tombstone: None,
        }
    }

    #[test]
    fn accepts_newer_and_rejects_rollback() {
        let v = vault();
        let (o2, d2) = content(&v, "i", 2, "new");
        let (o1, d1) = content(&v, "i", 1, "old");
        let mine = local(&o2, &d2, 2);
        assert!(matches!(verify(&v, &remote(Some(o1.clone()), Some(d1.clone()), None), Some(&mine)), Verdict::Reject));
        let (o3, d3) = content(&v, "i", 3, "newer");
        assert!(matches!(verify(&v, &remote(Some(o3), Some(d3), None), Some(&mine)), Verdict::Accept { version: 3 }));
        assert!(matches!(verify(&v, &remote(Some(o1), Some(d1), None), None), Verdict::Accept { version: 1 }));
    }

    #[test]
    fn rejects_mixed_and_forged_content() {
        let v = vault();
        let (o2, _) = content(&v, "i", 2, "a");
        let (_, d2b) = content(&v, "i", 2, "b");
        assert!(matches!(verify(&v, &remote(Some(o2), Some(d2b), None), None), Verdict::Reject));
        assert!(matches!(verify(&v, &remote(Some("k1.garbage".into()), Some("k1.x".into()), None), None), Verdict::Reject));
        let other = vault();
        let (o, d) = content(&other, "i", 1, "x");
        assert!(matches!(verify(&v, &remote(Some(o), Some(d), None), None), Verdict::Reject));
    }

    #[test]
    fn deletions_need_a_valid_newer_tombstone() {
        let v = vault();
        let (o2, d2) = content(&v, "i", 2, "a");
        let mine = local(&o2, &d2, 2);
        let forged = remote(Some(o2.clone()), Some(d2.clone()), Some("k1.forged".into()));
        assert!(matches!(verify(&v, &forged, Some(&mine)), Verdict::Reject));
        let stale = v.key.seal_tombstone("v", "i", &Tombstone { version: 2, deleted_at: 1 }).unwrap();
        assert!(matches!(verify(&v, &remote(None, None, Some(stale)), Some(&mine)), Verdict::Reject));
        let genuine = v.key.seal_tombstone("v", "i", &Tombstone { version: 3, deleted_at: 1 }).unwrap();
        assert!(matches!(verify(&v, &remote(None, None, Some(genuine)), Some(&mine)), Verdict::Delete { version: 3 }));
    }
}
