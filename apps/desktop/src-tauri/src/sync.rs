//! Synchronisation with the server.
//!
//! Local writes go to SQLite first (marked dirty) and are pushed in the
//! background, so the app keeps working offline. Pulls are incremental per
//! vault using the server's monotonically increasing `seq`.
//!
//! Conflicts (an item changed on two devices) never lose data: the most
//! recently edited version wins and the other one is kept as a
//! "conflicted copy".

use std::time::Duration;

use keyless_core::{
    item::ItemOverview,
    vault::VaultKey,
};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::{
    api::{ItemWrite, RemoteItem, now_secs},
    error::{AppError, AppResult, Msg},
    state::{AppState, CachedItem, OpenVault, Session, SyncStatus, Tokens},
    store::{Dirty, LocalItem, LocalVault, Store},
};

pub const EVENT_ITEMS_CHANGED: &str = "keyless://items-changed";
pub const EVENT_SYNC_STATUS: &str = "keyless://sync-status";
pub const EVENT_LOCKED: &str = "keyless://locked";

const PAGE: usize = 500;

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

/// Unwraps a vault key and decrypts its metadata into the session.
pub fn open_vault(session: &mut Session, vault: &LocalVault) -> bool {
    let key = match VaultKey::unwrap(session.account.user_key(), &vault.id, &vault.enc_vault_key) {
        Ok(key) => key,
        Err(err) => {
            log::warn!("vault {} key could not be decrypted: {err}", vault.id);
            return false;
        }
    };
    let meta = match key.open_meta(&vault.id, &vault.enc_meta) {
        Ok(meta) => meta,
        Err(err) => {
            log::warn!("vault {} metadata could not be decrypted: {err}", vault.id);
            return false;
        }
    };
    session.vaults.insert(
        vault.id.clone(),
        OpenVault { key, meta, role: vault.role.clone() },
    );
    true
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

fn rfc3339_now() -> String {
    // PostgREST accepts ISO 8601; we only need second precision.
    let secs = now_secs();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn apply_remote(store: &Store, session: &mut Session, remote: &RemoteItem) -> AppResult<()> {
    if remote.deleted_at.is_some() {
        store.purge_item(&remote.id)?;
        session.items.remove(&remote.id);
        return Ok(());
    }
    let local = LocalItem {
        id: remote.id.clone(),
        vault_id: remote.vault_id.clone(),
        enc_overview: remote.enc_overview.clone(),
        enc_details: remote.enc_details.clone(),
        revision: remote.revision,
        seq: remote.seq,
        deleted: false,
        dirty: Dirty::Clean,
    };
    store.upsert_item(&local)?;
    cache_item(session, &local);
    Ok(())
}

fn overview_updated_at(vault: &OpenVault, item_id: &str, vault_id: &str, enc: Option<&str>) -> i64 {
    enc.and_then(|e| vault.key.open_overview(vault_id, item_id, e).ok())
        .map(|o: ItemOverview| o.updated_at)
        .unwrap_or(0)
}

async fn push(state: &AppState) -> AppResult<bool> {
    let dirty = state.store().dirty_items()?;
    if dirty.is_empty() {
        return Ok(false);
    }
    let (_, token) = ensure_token(state).await?;
    let mut changed = false;

    for item in dirty {
        match item.dirty {
            Dirty::Clean => {}
            Dirty::Delete => {
                if item.revision == 0 {
                    state.store().purge_item(&item.id)?;
                    continue;
                }
                let write = ItemWrite { enc_overview: None, enc_details: None, deleted_at: Some(rfc3339_now()) };
                let deleted = state.api.update_item(&token, &item.id, item.revision, &write).await?;
                // Changed elsewhere since: deletion still wins.
                if deleted.is_none()
                    && let Some(remote) = state.api.item(&token, &item.id).await?
                    && remote.deleted_at.is_none()
                {
                    state.api.update_item(&token, &item.id, remote.revision, &write).await?;
                }
                state.store().purge_item(&item.id)?;
            }
            Dirty::Upsert => {
                let (Some(enc_overview), Some(enc_details)) = (item.enc_overview.as_deref(), item.enc_details.as_deref()) else {
                    continue;
                };
                let remote = if item.revision == 0 {
                    match state
                        .api
                        .insert_item(&token, &item.id, &item.vault_id, enc_overview, enc_details)
                        .await?
                    {
                        Some(remote) => Some(remote),
                        // Already exists (a lost response): update it instead.
                        None => match state.api.item(&token, &item.id).await? {
                            Some(existing) => {
                                let write = ItemWrite {
                                    enc_overview: Some(enc_overview),
                                    enc_details: Some(enc_details),
                                    deleted_at: None,
                                };
                                state.api.update_item(&token, &item.id, existing.revision, &write).await?
                            }
                            None => None,
                        },
                    }
                } else {
                    let write = ItemWrite { enc_overview: Some(enc_overview), enc_details: Some(enc_details), deleted_at: None };
                    match state.api.update_item(&token, &item.id, item.revision, &write).await? {
                        Some(remote) => Some(remote),
                        None => resolve_conflict(state, &token, &item).await?,
                    }
                };
                if let Some(remote) = remote {
                    let mut guard = state.session.lock().await;
                    let store = state.store();
                    // Only mark clean if nothing changed locally meanwhile.
                    if let Some(current) = store.item(&item.id)?
                        && current.enc_overview == item.enc_overview
                        && current.enc_details == item.enc_details
                    {
                        if let Some(session) = guard.as_mut() {
                            apply_remote(&store, session, &remote)?;
                        }
                    } else {
                        let mut current = store.item(&item.id)?.unwrap_or(item.clone());
                        current.revision = remote.revision;
                        store.upsert_item(&current)?;
                    }
                    changed = true;
                }
            }
        }
    }
    Ok(changed)
}

/// The server has a newer revision than the one our edit is based on.
/// The most recently edited version wins; the other is saved as a copy.
async fn resolve_conflict(state: &AppState, token: &str, local: &LocalItem) -> AppResult<Option<RemoteItem>> {
    let Some(remote) = state.api.item(token, &local.id).await? else {
        return Ok(None);
    };
    let (local_newer, conflict_copy) = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        let vault = session.vault(&local.vault_id)?;
        if remote.deleted_at.is_some() {
            (true, None)
        } else {
            let local_ts = overview_updated_at(vault, &local.id, &local.vault_id, local.enc_overview.as_deref());
            let remote_ts = overview_updated_at(vault, &remote.id, &remote.vault_id, remote.enc_overview.as_deref());
            let local_newer = local_ts >= remote_ts;
            // Re-encrypt the losing version as a new item so nothing is lost.
            let loser_overview = if local_newer { remote.enc_overview.as_deref() } else { local.enc_overview.as_deref() };
            let loser_details = if local_newer { remote.enc_details.as_deref() } else { local.enc_details.as_deref() };
            let copy = match (loser_overview, loser_details) {
                (Some(o), Some(d)) => {
                    let mut overview = vault.key.open_overview(&local.vault_id, &local.id, o)?;
                    let details = vault.key.open_details(&local.vault_id, &local.id, d)?;
                    overview.title = format!("{} (conflicted copy)", overview.title);
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
                    })
                }
                _ => None,
            };
            (local_newer, copy)
        }
    };
    if let Some(copy) = conflict_copy {
        state.store().upsert_item(&copy)?;
    }
    if local_newer {
        let write = ItemWrite {
            enc_overview: local.enc_overview.as_deref(),
            enc_details: local.enc_details.as_deref(),
            deleted_at: None,
        };
        state.api.update_item(token, &local.id, remote.revision, &write).await
    } else {
        Ok(Some(remote))
    }
}

async fn pull(state: &AppState) -> AppResult<bool> {
    let (user_id, token) = ensure_token(state).await?;
    let memberships = state.api.memberships(&token, &user_id).await?;
    let mut changed = false;

    // Vaults: add/update what we are a member of, drop the rest.
    {
        let mut guard = state.session.lock().await;
        let session = guard.as_mut().ok_or(AppError::Locked)?;
        let store = state.store();
        let known: Vec<String> = store.vaults()?.into_iter().map(|v| v.id).collect();
        for m in &memberships {
            let vault = LocalVault {
                id: m.vault_id.clone(),
                owner_id: m.vaults.owner_id.clone(),
                role: m.role.clone(),
                enc_meta: m.vaults.enc_meta.clone(),
                enc_vault_key: m.enc_vault_key.clone(),
                seq: m.vaults.seq,
            };
            if open_vault(session, &vault) {
                store.upsert_vault(&vault)?;
                if !known.contains(&vault.id) {
                    changed = true;
                }
            }
        }
        for id in known {
            if !memberships.iter().any(|m| m.vault_id == id) {
                store.delete_vault(&id)?;
                session.vaults.remove(&id);
                session.items.retain(|_, item| item.vault_id != id);
                changed = true;
            }
        }
    }

    // Items, per vault, from the last cursor.
    for m in &memberships {
        loop {
            let cursor = state.store().cursor(&m.vault_id)?;
            let page = state.api.items_since(&token, &m.vault_id, cursor, PAGE).await?;
            if page.is_empty() {
                break;
            }
            let mut guard = state.session.lock().await;
            let session = guard.as_mut().ok_or(AppError::Locked)?;
            let store = state.store();
            let mut max_seq = cursor;
            for remote in &page {
                max_seq = max_seq.max(remote.seq);
                if remote.vault_id != m.vault_id {
                    continue;
                }
                if let Some(local) = store.item(&remote.id)?
                    && local.dirty != Dirty::Clean
                {
                    // Our pending change is pushed (and reconciled) first.
                    continue;
                }
                apply_remote(&store, session, remote)?;
                changed = true;
            }
            store.set_cursor(&m.vault_id, max_seq)?;
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
        // A conflict may have produced a copy that still needs uploading.
        let pushed_again = push(&state).await?;
        Ok::<bool, AppError>(pushed || pulled || pushed_again)
    }
    .await;

    let status = match &result {
        Ok(_) => SyncStatus { state: "idle".into(), last_synced_at: Some(now_secs()), message: None },
        Err(AppError::Offline) => SyncStatus {
            state: "offline".into(),
            last_synced_at: previous.last_synced_at,
            message: None,
        },
        Err(AppError::Auth(_)) => SyncStatus {
            state: "signed_out".into(),
            last_synced_at: previous.last_synced_at,
            message: None,
        },
        Err(AppError::Locked) => previous,
        Err(err) => SyncStatus {
            state: "error".into(),
            last_synced_at: previous.last_synced_at,
            message: Some(err.to_string()),
        },
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

    #[test]
    fn rfc3339_formatting() {
        let s = rfc3339_now();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }
}
