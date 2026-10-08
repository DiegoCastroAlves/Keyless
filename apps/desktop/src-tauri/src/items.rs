//! Item and vault operations exposed to the UI.
//!
//! Secret field values are never included in item views: the UI gets them
//! only when the user explicitly reveals or edits a field, and copying
//! happens entirely in Rust.

use keyless_core::{
    item::{
        Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, PasswordHistoryEntry, Section, new_field_id,
        same_write, stamp_version,
    },
    totp::Totp,
    vault::{Tombstone, VaultKey, VaultMeta},
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    api::now_secs,
    error::{AppError, AppResult, Msg},
    state::{AppState, CachedItem, Session},
    store::{Dirty, LocalItem, LocalVault},
    sync::{self, ORPHANED_ROLE, cache_item, open_vault},
};

const MAX_TITLE: usize = 512;
const MAX_FIELDS: usize = 200;
const MAX_VALUE: usize = 64 * 1024;
const MAX_NOTES: usize = 64 * 1024;
/// Serialized details must fit the server's 256 KiB ciphertext limit.
const MAX_DETAILS_JSON: usize = 180 * 1024;
const MAX_HISTORY: usize = 30;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDto {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub color: String,
    pub role: String,
    pub can_write: bool,
    pub item_count: usize,
    /// The vault no longer exists on the server; this is the local copy.
    pub orphaned: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub id: String,
    pub vault_id: String,
    pub title: String,
    pub subtitle: String,
    pub category: Category,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub archived: bool,
    pub trashed_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Times the item was used on this device (copied, revealed, opened,
    /// filled). Local only.
    pub uses: u32,
    pub last_used_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub id: String,
    pub label: String,
    pub kind: FieldKind,
    pub purpose: Option<FieldPurpose>,
    /// Present only for non-secret fields.
    pub value: Option<String>,
    pub has_value: bool,
}

/// A passkey kept in the item, without its key.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyView {
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    pub created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionView {
    pub id: String,
    pub title: String,
    pub fields: Vec<FieldView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDetailView {
    #[serde(flatten)]
    pub summary: ItemSummary,
    pub url_entries: Vec<ItemUrl>,
    pub fields: Vec<FieldView>,
    pub sections: Vec<SectionView>,
    pub notes: String,
    pub passkeys: Vec<PasskeyView>,
    pub attachments: Vec<crate::attachments::AttachmentView>,
    pub password_history_count: usize,
    pub can_edit: bool,
}

/// Full plaintext of an item, used only by the edit form.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub title: String,
    pub category: Category,
    #[serde(default)]
    pub urls: Vec<ItemUrl>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub value: String,
    pub changed_at: i64,
}

fn summary(id: &str, item: &CachedItem) -> ItemSummary {
    let o = &item.overview;
    ItemSummary {
        id: id.to_string(),
        vault_id: item.vault_id.clone(),
        title: o.title.clone(),
        subtitle: o.subtitle.clone(),
        category: o.category,
        urls: o.urls.iter().map(|u| u.href.clone()).collect(),
        tags: o.tags.clone(),
        favorite: o.favorite,
        archived: o.archived,
        trashed_at: o.trashed_at,
        created_at: o.created_at,
        updated_at: o.updated_at,
        uses: 0,
        last_used_at: None,
    }
}

pub(crate) fn field_view(field: &Field) -> FieldView {
    let secret = field.kind.is_secret() || field.purpose == Some(FieldPurpose::Password);
    FieldView {
        id: field.id.clone(),
        label: field.label.clone(),
        kind: field.kind,
        purpose: field.purpose,
        value: if secret { None } else { Some(field.value.clone()) },
        has_value: !field.value.is_empty(),
    }
}

fn unlocked<'a>(guard: &'a mut tokio::sync::MutexGuard<'_, Option<Session>>) -> AppResult<&'a mut Session> {
    guard.as_mut().ok_or(AppError::Locked)
}

pub(crate) fn load_details(state: &AppState, session: &Session, item_id: &str) -> AppResult<(LocalItem, ItemDetails)> {
    let local = state.store().item(item_id)?.ok_or(AppError::NotFound)?;
    let enc = local.enc_details.as_deref().ok_or(AppError::NotFound)?;
    let vault = session.vault(&local.vault_id)?;
    let details = vault.key.open_details(&local.vault_id, &local.id, enc)?;
    if let Some(cached) = session.items.get(item_id)
        && !same_write(&cached.overview, &details)
    {
        return Err(AppError::Invalid(Msg::new("item_integrity")));
    }
    Ok((local, details))
}

fn find_field<'a>(details: &'a ItemDetails, field_id: &str) -> AppResult<&'a Field> {
    details.all_fields().find(|f| f.id == field_id).ok_or(AppError::NotFound)
}

// ----- vaults -------------------------------------------------------------

pub async fn list_vaults(state: &AppState) -> AppResult<Vec<VaultDto>> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let mut vaults: Vec<VaultDto> = session
        .vaults
        .iter()
        .map(|(id, v)| VaultDto {
            id: id.clone(),
            name: v.meta.name.clone(),
            description: v.meta.description.clone(),
            icon: v.meta.icon.clone(),
            color: v.meta.color.clone(),
            role: v.role.clone(),
            can_write: v.can_write(),
            orphaned: v.role == ORPHANED_ROLE,
            item_count: session
                .items
                .values()
                .filter(|i| &i.vault_id == id && i.overview.trashed_at.is_none() && !i.overview.archived)
                .count(),
        })
        .collect();
    vaults.sort_by(|a, b| {
        (a.name != "Personal", a.name.to_lowercase()).cmp(&(b.name != "Personal", b.name.to_lowercase()))
    });
    Ok(vaults)
}

fn validate_vault_meta(meta: &VaultMeta) -> AppResult<()> {
    if meta.name.trim().is_empty() {
        return Err(AppError::Invalid(Msg::new("vault_name_required")));
    }
    if meta.name.len() > 100 || meta.description.len() > 1000 || meta.icon.len() > 40 || meta.color.len() > 40 {
        return Err(AppError::Invalid(Msg::new("vault_details_too_long")));
    }
    Ok(())
}

pub async fn create_vault(app: &AppHandle, meta: VaultMeta) -> AppResult<String> {
    let state = app.state::<AppState>();
    validate_vault_meta(&meta)?;
    let (_, token) = sync::ensure_token(&state).await?;
    let vault_id = uuid::Uuid::new_v4().to_string();
    let (enc_meta, enc_vault_key) = {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        let key = VaultKey::generate()?;
        (key.seal_meta(&vault_id, &meta)?, key.wrap(session.account.user_key(), &vault_id)?)
    };
    let remote = state.api.create_vault(&token, &vault_id, &enc_meta, &enc_vault_key).await?;
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let local = LocalVault {
        id: vault_id.clone(),
        owner_id: remote.owner_id,
        role: "owner".into(),
        enc_meta,
        enc_vault_key,
        seq: remote.seq,
    };
    state.store().upsert_vault(&local)?;
    open_vault(session, &local);
    Ok(vault_id)
}

pub async fn update_vault(app: &AppHandle, vault_id: &str, meta: VaultMeta) -> AppResult<()> {
    let state = app.state::<AppState>();
    validate_vault_meta(&meta)?;
    let enc_meta = {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        let vault = session.vault(vault_id)?;
        if vault.role != "owner" {
            return Err(AppError::Invalid(Msg::new("vault_owner_only")));
        }
        vault.key.seal_meta(vault_id, &meta)?
    };
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.update_vault_meta(&token, vault_id, &enc_meta).await?;
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    if let Some(vault) = session.vaults.get_mut(vault_id) {
        vault.meta = meta;
    }
    let store = state.store();
    if let Some(mut local) = store.vaults()?.into_iter().find(|v| v.id == vault_id) {
        local.enc_meta = enc_meta;
        store.upsert_vault(&local)?;
    }
    Ok(())
}

pub async fn delete_vault(app: &AppHandle, vault_id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        let vault = session.vault(vault_id)?;
        if vault.role != "owner" {
            return Err(AppError::Invalid(Msg::new("vault_owner_only")));
        }
        if session.vaults.values().filter(|v| v.role == "owner").count() <= 1 {
            return Err(AppError::Invalid(Msg::new("vault_last")));
        }
    }
    let proof = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        session.vault(vault_id)?.key.seal_vault_tombstone(vault_id, now_secs())?
    };
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.delete_vault(&token, vault_id, &proof).await?;
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    state.store().delete_vault(vault_id)?;
    session.vaults.remove(vault_id);
    session.items.retain(|_, i| i.vault_id != vault_id);
    Ok(())
}

// ----- reading items ------------------------------------------------------

pub async fn list_items(state: &AppState) -> AppResult<Vec<ItemSummary>> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let usage = state.store().item_usage().unwrap_or_default();
    let mut items: Vec<ItemSummary> = session
        .items
        .iter()
        .map(|(id, item)| {
            let mut summary = summary(id, item);
            if let Some((uses, last_used_at)) = usage.get(id) {
                summary.uses = *uses;
                summary.last_used_at = Some(*last_used_at);
            }
            summary
        })
        .collect();
    items.sort_by_key(|a| a.title.to_lowercase());
    Ok(items)
}

pub async fn get_item(state: &AppState, item_id: &str) -> AppResult<ItemDetailView> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let cached = session.items.get(item_id).ok_or(AppError::NotFound)?;
    let (local, mut details) = load_details(state, session, item_id)?;
    details.sort_main_fields();
    let can_edit = session.vault(&local.vault_id)?.can_write();
    Ok(ItemDetailView {
        summary: summary(item_id, cached),
        url_entries: cached.overview.urls.clone(),
        fields: details.fields.iter().map(field_view).collect(),
        sections: details
            .sections
            .iter()
            .map(|s| SectionView { id: s.id.clone(), title: s.title.clone(), fields: s.fields.iter().map(field_view).collect() })
            .collect(),
        notes: details.notes.clone(),
        passkeys: details
            .passkeys
            .iter()
            .map(|p| PasskeyView {
                credential_id: p.credential_id.clone(),
                rp_id: p.rp_id.clone(),
                user_name: if p.user_name.is_empty() { p.user_display_name.clone() } else { p.user_name.clone() },
                created_at: p.created_at,
            })
            .collect(),
        attachments: details.attachments.iter().map(crate::attachments::view).collect(),
        password_history_count: details.password_history.len(),
        can_edit,
    })
}

pub async fn get_item_draft(state: &AppState, item_id: &str) -> AppResult<ItemDraft> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let cached = session.items.get(item_id).ok_or(AppError::NotFound)?;
    let (_, mut details) = load_details(state, session, item_id)?;
    // Same order as the item view; saving keeps it.
    details.sort_main_fields();
    let o = &cached.overview;
    Ok(ItemDraft {
        id: Some(item_id.to_string()),
        vault_id: cached.vault_id.clone(),
        title: o.title.clone(),
        category: o.category,
        urls: o.urls.clone(),
        tags: o.tags.clone(),
        favorite: o.favorite,
        fields: details.fields.clone(),
        sections: details.sections.clone(),
        notes: details.notes.clone(),
    })
}

/// Deletes one of the item's passkeys (the site keeps its public key, but
/// it can no longer be used from Keyless).
pub async fn delete_passkey(app: &AppHandle, item_id: &str, credential_id: &str) -> AppResult<ItemSummary> {
    let state = app.state::<AppState>();
    let draft = get_item_draft(&state, item_id).await?;
    let mut passkeys = {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        load_details(&state, session, item_id)?.1.passkeys.clone()
    };
    passkeys.retain(|p| p.credential_id != credential_id);
    save_item_with(app, draft, Extras { passkeys: Some(passkeys), ..Default::default() }).await
}

pub async fn reveal_field(state: &AppState, item_id: &str, field_id: &str) -> AppResult<Zeroizing<String>> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let (_, details) = load_details(state, session, item_id)?;
    Ok(Zeroizing::new(find_field(&details, field_id)?.value.clone()))
}

pub async fn password_history(state: &AppState, item_id: &str) -> AppResult<Vec<HistoryEntry>> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let (_, details) = load_details(state, session, item_id)?;
    Ok(details
        .password_history
        .iter()
        .rev()
        .map(|h| HistoryEntry { value: h.value.clone(), changed_at: h.changed_at })
        .collect())
}

pub async fn totp_code(state: &AppState, item_id: &str, field_id: &str) -> AppResult<TotpCode> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let (_, details) = load_details(state, session, item_id)?;
    let totp = Totp::parse(&find_field(&details, field_id)?.value)?;
    let now = now_secs().max(0) as u64;
    Ok(TotpCode { code: totp.code_at(now).to_string(), period: totp.period, remaining: totp.seconds_remaining(now) })
}

/// The value to put on the clipboard for a field (TOTP fields copy the
/// current code, not the secret).
pub async fn copy_value(state: &AppState, item_id: &str, field_id: Option<&str>, purpose: Option<&str>) -> AppResult<Zeroizing<String>> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let (_, details) = load_details(state, session, item_id)?;
    let field = match (field_id, purpose) {
        (Some(id), _) => find_field(&details, id)?,
        (None, Some("username")) => details.field_by_purpose(FieldPurpose::Username).ok_or(AppError::NotFound)?,
        (None, Some("password")) => details.field_by_purpose(FieldPurpose::Password).ok_or(AppError::NotFound)?,
        (None, Some("totp")) => details.all_fields().find(|f| f.kind == FieldKind::Totp).ok_or(AppError::NotFound)?,
        _ => return Err(AppError::NotFound),
    };
    if field.kind == FieldKind::Totp {
        let totp = Totp::parse(&field.value)?;
        return Ok(totp.code_at(now_secs().max(0) as u64));
    }
    Ok(Zeroizing::new(field.value.clone()))
}

pub async fn item_url(state: &AppState, item_id: &str, index: usize) -> AppResult<url::Url> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let cached = session.items.get(item_id).ok_or(AppError::NotFound)?;
    let href = cached.overview.urls.get(index).ok_or(AppError::NotFound)?.href.clone();
    let url = url::Url::parse(&normalize_url(&href)).map_err(|_| AppError::Invalid(Msg::new("url_invalid")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::Invalid(Msg::new("url_scheme")));
    }
    Ok(url)
}

// ----- writing items ------------------------------------------------------

fn normalize_url(href: &str) -> String {
    let href = href.trim();
    if href.is_empty() || href.contains("://") {
        href.to_string()
    } else {
        format!("https://{href}")
    }
}

fn compute_subtitle(category: Category, details: &ItemDetails) -> String {
    let first_text = || {
        details
            .all_fields()
            .find(|f| !f.value.is_empty() && !f.kind.is_secret() && f.purpose != Some(FieldPurpose::Password))
            .map(|f| f.value.chars().take(80).collect::<String>())
            .unwrap_or_default()
    };
    match category {
        Category::CreditCard => details
            .all_fields()
            .find(|f| f.kind == FieldKind::CardNumber && !f.value.is_empty())
            .map(|f| {
                let digits: String = f.value.chars().filter(char::is_ascii_digit).collect();
                let last4 = &digits[digits.len().saturating_sub(4)..];
                format!("•••• {last4}")
            })
            .unwrap_or_default(),
        Category::SecureNote => details.notes.lines().next().unwrap_or("").chars().take(80).collect(),
        Category::Login | Category::Password | Category::EmailAccount | Category::Database | Category::Server => {
            details.username().map(String::from).unwrap_or_else(first_text)
        }
        _ => first_text(),
    }
}

fn validate_draft(draft: &ItemDraft) -> AppResult<()> {
    let total_fields = draft.fields.len() + draft.sections.iter().map(|s| s.fields.len()).sum::<usize>();
    if draft.title.len() > MAX_TITLE {
        return Err(AppError::Invalid(Msg::new("title_too_long")));
    }
    if total_fields > MAX_FIELDS || draft.sections.len() > 50 || draft.urls.len() > 50 || draft.tags.len() > 50 {
        return Err(AppError::Invalid(Msg::new("too_many_fields")));
    }
    if draft.notes.len() > MAX_NOTES {
        return Err(AppError::Invalid(Msg::new("notes_too_long")));
    }
    for field in draft.fields.iter().chain(draft.sections.iter().flat_map(|s| s.fields.iter())) {
        if field.value.len() > MAX_VALUE || field.label.len() > 256 {
            return Err(AppError::Invalid(Msg::new("field_too_long").with("label", &field.label)));
        }
        if field.kind == FieldKind::Totp && !field.value.trim().is_empty() && Totp::parse(&field.value).is_err() {
            return Err(AppError::Invalid(Msg::new("totp_invalid")));
        }
    }
    Ok(())
}

/// Encrypts and stores a new version of an item (to be uploaded).
#[allow(clippy::too_many_arguments)]
fn write_local_item(
    state: &AppState,
    session: &mut Session,
    item_id: &str,
    vault_id: &str,
    revision: i64,
    version: u64,
    overview: &mut ItemOverview,
    details: &mut ItemDetails,
) -> AppResult<()> {
    if serde_json::to_vec(&*details).map(|j| j.len()).unwrap_or(usize::MAX) > MAX_DETAILS_JSON {
        return Err(AppError::Invalid(Msg::new("item_too_large")));
    }
    stamp_version(overview, details, version);
    let vault = session.vault(vault_id)?;
    let local = LocalItem {
        id: item_id.to_string(),
        vault_id: vault_id.to_string(),
        enc_overview: Some(vault.key.seal_overview(vault_id, item_id, overview)?),
        enc_details: Some(vault.key.seal_details(vault_id, item_id, details)?),
        revision,
        seq: 0,
        deleted: false,
        dirty: Dirty::Upsert,
        version,
        enc_tombstone: None,
    };
    state.store().upsert_item(&local)?;
    cache_item(session, &local);
    Ok(())
}

fn tombstone_local(state: &AppState, session: &mut Session, local: &LocalItem) -> AppResult<()> {
    let version = local.version + 1;
    let proof = session
        .vault(&local.vault_id)?
        .key
        .seal_tombstone(&local.vault_id, &local.id, &Tombstone { version, deleted_at: now_secs() })?;
    let tombstone = LocalItem {
        enc_overview: None,
        enc_details: None,
        deleted: true,
        dirty: Dirty::Delete,
        version,
        enc_tombstone: Some(proof),
        ..local.clone()
    };
    state.store().upsert_item(&tombstone)?;
    session.items.remove(&local.id);
    Ok(())
}

pub async fn save_item(app: &AppHandle, draft: ItemDraft) -> AppResult<ItemSummary> {
    save_item_with(app, draft, Extras::default()).await
}

/// Saves a draft; `passkeys` replaces the item's passkeys, which are kept
/// as they were otherwise (the editor never sees them).
/// What a save changes besides the draft; `None` keeps what the item has.
/// Passkeys and attachments are never part of the edit form.
#[derive(Default)]
pub struct Extras {
    pub passkeys: Option<Vec<keyless_core::passkey::Passkey>>,
    pub attachments: Option<Vec<keyless_core::attachment::Attachment>>,
}

pub async fn save_item_with(app: &AppHandle, mut draft: ItemDraft, extras: Extras) -> AppResult<ItemSummary> {
    let state = app.state::<AppState>();
    validate_draft(&draft)?;
    // Moving to another vault: its attachments are copied there first.
    let moved_from = match &draft.id {
        Some(id) => crate::attachments::copy_for_move(app, id, &draft.vault_id).await?,
        None => None,
    };
    let now = now_secs();
    let result = {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        if !session.vault(&draft.vault_id)?.can_write() {
            return Err(AppError::Invalid(Msg::new("vault_read_only")));
        }

        let existing = match &draft.id {
            Some(id) => {
                let (local, details) = load_details(&state, session, id)?;
                let overview = session.items.get(id).ok_or(AppError::NotFound)?.overview.clone();
                Some((local, details, overview))
            }
            None => None,
        };

        // Normalise the draft.
        for field in draft.fields.iter_mut().chain(draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut())) {
            if field.id.is_empty() {
                field.id = new_field_id();
            }
            if field.kind == FieldKind::Totp {
                field.value = field.value.trim().to_string();
            }
            // A private key whose line breaks were lost in a single-line field.
            if draft.category == Category::SshKey && field.kind == FieldKind::Concealed && field.value.contains("-----BEGIN ") {
                field.value = crate::ssh_keys::normalize_pem(&field.value).to_string();
            }
        }
        for section in draft.sections.iter_mut() {
            if section.id.is_empty() {
                section.id = new_field_id();
            }
        }
        draft.sections.retain(|s| !s.fields.is_empty() || !s.title.trim().is_empty());

        let mut details = ItemDetails::default();
        details.fields = std::mem::take(&mut draft.fields);
        details.sections = std::mem::take(&mut draft.sections);
        details.notes = std::mem::take(&mut draft.notes);

        let mut created_at = now;
        let mut archived = false;
        let sentinel_ignored = existing.as_ref().map(|(_, _, o)| o.sentinel_ignored.clone()).unwrap_or_default();
        // What a later version added to the item stays.
        let unknown = existing.as_ref().map(|(_, _, o)| o.unknown.clone()).unwrap_or_default();
        if let Some((_, old_details, _)) = &existing {
            details.passkeys = old_details.passkeys.clone();
            details.attachments = old_details.attachments.clone();
            details.unknown = old_details.unknown.clone();
        }
        if let Some(passkeys) = extras.passkeys {
            details.passkeys = passkeys;
        }
        if let Some(attachments) = extras.attachments {
            details.attachments = attachments;
        }
        if let Some((_, old_details, old_overview)) = &existing {
            created_at = old_overview.created_at;
            archived = old_overview.archived;
            details.password_history = old_details.password_history.clone();
            if let Some(old_password) = old_details.password()
                && !old_password.is_empty()
                && details.password() != Some(old_password)
            {
                details
                    .password_history
                    .push(PasswordHistoryEntry { value: old_password.to_string(), changed_at: now });
                let excess = details.password_history.len().saturating_sub(MAX_HISTORY);
                details.password_history.drain(..excess);
            }
        }

        let mut tags: Vec<String> = draft.tags.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
        tags.sort_by_key(|t| t.to_lowercase());
        tags.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

        let mut overview = ItemOverview {
            title: if draft.title.trim().is_empty() { "Untitled".into() } else { draft.title.trim().to_string() },
            subtitle: compute_subtitle(draft.category, &details),
            category: draft.category,
            urls: draft
                .urls
                .iter()
                .filter(|u| !u.href.trim().is_empty())
                .map(|u| ItemUrl { href: normalize_url(&u.href), label: u.label.trim().to_string(), fill: u.fill, unknown: u.unknown.clone() })
                .collect(),
            tags,
            favorite: draft.favorite,
            archived,
            trashed_at: None,
            created_at,
            updated_at: now,
            sentinel_ignored,
            unknown,
            ..Default::default()
        };

        let item_id = match existing {
            Some((local, _, old_overview)) if local.vault_id == draft.vault_id => {
                let version = local.version.max(old_overview.version) + 1;
                write_local_item(&state, session, &local.id, &draft.vault_id, local.revision, version, &mut overview, &mut details)?;
                local.id
            }
            Some((local, _, _)) => {
                // Moving between vaults: ciphertexts are bound to their vault,
                // so the item is re-created in the target vault.
                let new_id = uuid::Uuid::new_v4().to_string();
                write_local_item(&state, session, &new_id, &draft.vault_id, 0, 1, &mut overview, &mut details)?;
                tombstone_local(&state, session, &local)?;
                new_id
            }
            None => {
                let new_id = uuid::Uuid::new_v4().to_string();
                write_local_item(&state, session, &new_id, &draft.vault_id, 0, 1, &mut overview, &mut details)?;
                new_id
            }
        };
        let cached = session.items.get(&item_id).ok_or(AppError::NotFound)?;
        summary(&item_id, cached)
    };
    if let Some(moved) = moved_from {
        // The copies in the old vault are no longer needed.
        crate::attachments::forget(app, moved);
    }
    state.touch();
    sync::spawn_sync(app);
    Ok(result)
}

/// Changes overview flags (favorite, archive, trash) as a new version of the
/// whole item, so overview and details stay paired.
async fn update_overview(app: &AppHandle, item_id: &str, change: impl FnOnce(&mut ItemOverview)) -> AppResult<()> {
    let state = app.state::<AppState>();
    {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        let (local, mut details) = load_details(&state, session, item_id)?;
        if !session.vault(&local.vault_id)?.can_write() {
            return Err(AppError::Invalid(Msg::new("vault_read_only")));
        }
        let mut overview = session.items.get(item_id).ok_or(AppError::NotFound)?.overview.clone();
        change(&mut overview);
        let version = local.version.max(overview.version) + 1;
        write_local_item(&state, session, item_id, &local.vault_id, local.revision, version, &mut overview, &mut details)?;
    }
    sync::spawn_sync(app);
    Ok(())
}

/// Ignores (or watches again) a Sentinel alert for the item.
pub async fn set_sentinel_ignored(app: &AppHandle, item_id: &str, alert: &str, ignored: bool) -> AppResult<()> {
    const ALERTS: [&str; 7] = ["weak", "reused", "breached", "compromised", "unsecured", "expiring", "two_factor"];
    if !ALERTS.contains(&alert) {
        return Err(AppError::Invalid(Msg::new("invalid_request")));
    }
    update_overview(app, item_id, |o| {
        o.sentinel_ignored.retain(|a| a != alert);
        if ignored {
            o.sentinel_ignored.push(alert.to_string());
        }
    })
    .await
}

pub async fn set_favorite(app: &AppHandle, item_id: &str, favorite: bool) -> AppResult<()> {
    update_overview(app, item_id, |o| o.favorite = favorite).await
}

pub async fn set_archived(app: &AppHandle, item_id: &str, archived: bool) -> AppResult<()> {
    update_overview(app, item_id, |o| {
        o.archived = archived;
        o.updated_at = now_secs();
    })
    .await
}

pub async fn trash_item(app: &AppHandle, item_id: &str) -> AppResult<()> {
    update_overview(app, item_id, |o| {
        o.trashed_at = Some(now_secs());
        o.updated_at = now_secs();
    })
    .await
}

pub async fn restore_item(app: &AppHandle, item_id: &str) -> AppResult<()> {
    update_overview(app, item_id, |o| {
        o.trashed_at = None;
        o.updated_at = now_secs();
    })
    .await
}

pub async fn delete_items_permanently(app: &AppHandle, item_ids: &[String]) -> AppResult<()> {
    let state = app.state::<AppState>();
    let mut files = Vec::new();
    {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        for id in item_ids {
            let Some(local) = state.store().item(id)? else { continue };
            if !session.vault(&local.vault_id)?.can_write() {
                continue;
            }
            // Its attachments go too.
            if let Ok((_, details)) = load_details(&state, session, id) {
                files.extend(details.attachments.iter().map(|a| crate::attachments::Gone::of(&local.vault_id, a)));
            }
            tombstone_local(&state, session, &local)?;
        }
    }
    crate::attachments::forget(app, files);
    sync::spawn_sync(app);
    Ok(())
}

/// Moves items to another vault. The encryption context binds an item to its
/// vault and id, so each item is encrypted again with the destination vault's
/// key under a new id, then the original is deleted with a tombstone proof.
/// The copy is written first: an interruption leaves a duplicate, never a
/// lost item. Returns how many items moved.
pub async fn move_items(app: &AppHandle, item_ids: &[String], to_vault: &str) -> AppResult<usize> {
    let state = app.state::<AppState>();
    // Their attachments are copied to the destination first.
    let mut old_files = Vec::new();
    for id in item_ids {
        if let Some(files) = crate::attachments::copy_for_move(app, id, to_vault).await? {
            old_files.extend(files);
        }
    }
    let moved = {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        if !session.vault(to_vault)?.can_write() {
            return Err(AppError::Invalid(Msg::new("vault_read_only")));
        }
        let mut moved = 0;
        for id in item_ids {
            let Some(local) = state.store().item(id)? else { continue };
            if local.deleted || local.vault_id == to_vault {
                continue;
            }
            if !session.vault(&local.vault_id)?.can_write() {
                return Err(AppError::Invalid(Msg::new("vault_read_only")));
            }
            let mut overview = session.items.get(id).ok_or(AppError::NotFound)?.overview.clone();
            // Checks the item's integrity before copying it.
            let (_, mut details) = load_details(&state, session, id)?;
            let new_id = uuid::Uuid::new_v4().to_string();
            write_local_item(&state, session, &new_id, to_vault, 0, 1, &mut overview, &mut details)?;
            tombstone_local(&state, session, &local)?;
            let _ = state.store().move_item_usage(id, &new_id);
            moved += 1;
        }
        moved
    };
    crate::attachments::forget(app, old_files);
    sync::spawn_sync(app);
    Ok(moved)
}

/// Moves every item of a vault to another one and, if asked, deletes the
/// emptied vault once the move has reached the server.
pub async fn move_vault_items(app: &AppHandle, from_vault: &str, to_vault: &str, delete_source: bool) -> AppResult<usize> {
    let state = app.state::<AppState>();
    let ids: Vec<String> = {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        if from_vault == to_vault {
            return Err(AppError::Invalid(Msg::new("vault_same")));
        }
        if delete_source && session.vault(from_vault)?.role != "owner" {
            return Err(AppError::Invalid(Msg::new("vault_owner_only")));
        }
        session.items.iter().filter(|(_, i)| i.vault_id == from_vault).map(|(id, _)| id.clone()).collect()
    };
    let moved = move_items(app, &ids, to_vault).await?;
    if delete_source {
        // Upload the copies and the tombstones before the vault goes away.
        sync::sync_now(app).await.map_err(|_| AppError::Invalid(Msg::new("vault_moved_not_deleted")))?;
        delete_vault(app, from_vault).await.map_err(|_| AppError::Invalid(Msg::new("vault_moved_not_deleted")))?;
    }
    Ok(moved)
}

/// Permanently deletes items that have been in Recently Deleted for 30 days.
pub async fn purge_old_trash(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let cutoff = now_secs() - 30 * 86_400;
    let expired: Vec<String> = {
        let guard = state.session.lock().await;
        let Some(session) = guard.as_ref() else { return Ok(()) };
        session
            .items
            .iter()
            .filter(|(_, i)| i.overview.trashed_at.is_some_and(|t| t < cutoff))
            .map(|(id, _)| id.clone())
            .collect()
    };
    if !expired.is_empty() {
        delete_items_permanently(app, &expired).await?;
    }
    Ok(())
}

/// Creates items in bulk (imports). Does not upload; the caller syncs.
pub async fn insert_imported(state: &AppState, vault_id: &str, items: Vec<(ItemOverview, ItemDetails)>) -> AppResult<usize> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let now = now_secs();
    let mut count = 0;
    for (mut overview, details) in items {
        if overview.created_at == 0 {
            overview.created_at = now;
        }
        if overview.updated_at == 0 {
            overview.updated_at = now;
        }
        if overview.subtitle.is_empty() {
            overview.subtitle = compute_subtitle(overview.category, &details);
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut details = details;
        write_local_item(state, session, &id, vault_id, 0, 1, &mut overview, &mut details)?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtitles() {
        let mut details = ItemDetails::default();
        details.fields.push(Field {
            id: "n".into(),
            label: "number".into(),
            kind: FieldKind::CardNumber,
            value: "4111 1111 1111 1234".into(),
            purpose: None,
        });
        assert_eq!(compute_subtitle(Category::CreditCard, &details), "•••• 1234");

        let mut login = ItemDetails::default();
        login.fields.push(Field {
            id: "u".into(),
            label: "username".into(),
            kind: FieldKind::Text,
            value: "me".into(),
            purpose: Some(FieldPurpose::Username),
        });
        assert_eq!(compute_subtitle(Category::Login, &login), "me");
    }

    #[test]
    fn url_normalization() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(normalize_url("http://x.y"), "http://x.y");
        assert_eq!(normalize_url("  "), "");
    }

    #[test]
    fn secret_fields_are_redacted() {
        let password = Field {
            id: "p".into(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: "hunter2".into(),
            purpose: Some(FieldPurpose::Password),
        };
        let view = field_view(&password);
        assert!(view.value.is_none());
        assert!(view.has_value);
        let mut mislabeled = password.clone();
        mislabeled.kind = FieldKind::Text;
        assert!(field_view(&mislabeled).value.is_none());
    }
}
