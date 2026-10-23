//! Item and vault operations exposed to the UI.
//!
//! Secret field values are never included in item views: the UI gets them
//! only when the user explicitly reveals or edits a field, and copying
//! happens entirely in Rust.

use keyless_core::{
    item::{
        Address, Category, ExpiryAlert, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, PasswordHistoryEntry, Section,
        new_field_id, same_write, stamp_version,
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
    /// The item has its own icon (see `item_icon`).
    pub custom_icon: bool,
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
    /// Date fields: when to warn before the date (none: Keyless decides).
    pub alert: Option<ExpiryAlert>,
    /// Address fields: the parts.
    pub address: Option<Address>,
    /// Related item, or the login a "sign in with" account uses.
    pub link: String,
    /// Location fields: "latitude,longitude".
    pub geo: String,
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
#[derive(Default, Serialize, Deserialize)]
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
    /// The item's own icon (a PNG data URL), or empty.
    #[serde(default)]
    pub icon: String,
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
        custom_icon: o.custom_icon,
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
        alert: field.extra.alert,
        address: if secret { None } else { field.extra.address.clone() },
        link: field.extra.link.clone(),
        geo: if secret { String::new() } else { field.extra.geo.clone() },
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

/// A vault the user deleted that can still come back: the server keeps it
/// (and its items) for 30 days.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedVault {
    pub id: String,
    pub name: String,
    /// Unix seconds.
    pub deleted_at: i64,
}

/// The vaults the user deleted, still on the server. Only deletions with a
/// valid proof are listed (sync undoes the others).
pub async fn deleted_vaults(state: &AppState) -> AppResult<Vec<DeletedVault>> {
    let (user_id, token) = sync::ensure_token(state).await?;
    let memberships = state.api.memberships(&token, &user_id).await?;
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let mut deleted = Vec::new();
    for m in memberships.iter().filter(|m| m.role == "owner") {
        let Some(deleted_at) = m.vaults.deleted_at.as_deref() else { continue };
        let vault = LocalVault {
            id: m.vault_id.clone(),
            owner_id: m.vaults.owner_id.clone(),
            role: m.role.clone(),
            enc_meta: m.vaults.enc_meta.clone(),
            enc_vault_key: m.enc_vault_key.clone(),
            seq: m.vaults.seq,
        };
        let Some(opened) = sync::unlock_vault(session.account.user_key(), &vault) else { continue };
        let genuine = m
            .vaults
            .enc_tombstone
            .as_deref()
            .is_some_and(|t| opened.key.open_vault_tombstone(&vault.id, t).is_ok());
        if genuine {
            let deleted_at = keyless_core::time::parse_iso8601(deleted_at).unwrap_or_default();
            deleted.push(DeletedVault { id: vault.id, name: opened.meta.name.clone(), deleted_at });
        }
    }
    deleted.sort_by_key(|v| std::cmp::Reverse(v.deleted_at));
    Ok(deleted)
}

/// Brings back a deleted vault, with its items, and syncs them down.
pub async fn restore_vault(app: &AppHandle, vault_id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.restore_vault(&token, vault_id).await?;
    sync::sync_now(app).await
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
        icon: details.icon.clone(),
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

/// Adds the website of `url` (its origin) to a login, from the browser
/// extension, after the user filled it there on purpose.
pub async fn add_website(app: &AppHandle, item_id: &str, url: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let parsed = url::Url::parse(url).map_err(|_| AppError::Invalid(Msg::new("url_invalid")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::Invalid(Msg::new("url_scheme")));
    }
    let origin = parsed.origin().ascii_serialization();
    let mut draft = get_item_draft(&state, item_id).await?;
    if draft.urls.iter().any(|u| normalize_url(&u.href).trim_end_matches('/') == origin) {
        return Ok(());
    }
    draft.urls.push(ItemUrl { href: origin, ..Default::default() });
    save_item(app, draft).await.map(|_| ())
}

/// Sets a login's one-time password (an `otpauth://` address), replacing the
/// one it had; from the browser extension, for a login of the page whose
/// setup QR code it read.
pub async fn set_totp(app: &AppHandle, item_id: &str, uri: &str) -> AppResult<()> {
    Totp::parse(uri).map_err(|_| AppError::Invalid(Msg::new("totp_invalid")))?;
    let state = app.state::<AppState>();
    let mut draft = get_item_draft(&state, item_id).await?;
    let existing = draft
        .fields
        .iter_mut()
        .chain(draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()))
        .find(|f| f.kind == FieldKind::Totp);
    match existing {
        Some(field) => field.value = uri.to_string(),
        None => draft.fields.push(Field {
            id: new_field_id(),
            label: "one-time password".into(),
            kind: FieldKind::Totp,
            value: uri.to_string(),
            purpose: None,
            extra: Default::default(),
        }),
    }
    save_item(app, draft).await.map(|_| ())
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
        if field.extra.link.len() > 128 || field.extra.geo.len() > 64 {
            return Err(AppError::Invalid(Msg::new("field_too_long").with("label", &field.label)));
        }
    }
    if !draft.icon.is_empty() && (draft.icon.len() > MAX_ICON || !draft.icon.starts_with(ICON_PREFIX)) {
        return Err(AppError::Invalid(Msg::new("icon_invalid")));
    }
    Ok(())
}

/// Item icons: PNG data URLs made by `crate::item_icons`.
pub(crate) const ICON_PREFIX: &str = "data:image/png;base64,";
const MAX_ICON: usize = 96 * 1024;

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
            // An address is kept as its parts and as text (for search, the
            // list and versions that do not know addresses).
            if field.kind == FieldKind::Address
                && let Some(address) = &field.extra.address
            {
                field.value = address.formatted();
            }
            if !field.kind.is_date() {
                field.extra.alert = None;
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
        details.icon = std::mem::take(&mut draft.icon);

        let mut created_at = now;
        let mut archived = false;
        let sentinel_ignored = existing.as_ref().map(|(_, _, o)| o.sentinel_ignored.clone()).unwrap_or_default();
        let imported_from = existing.as_ref().map(|(_, _, o)| o.imported_from.clone()).unwrap_or_default();
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
                .map(|u| ItemUrl { href: normalize_url(&u.href), label: u.label.trim().to_string(), fill: u.fill, submit: u.submit, unknown: u.unknown.clone() })
                .collect(),
            tags,
            favorite: draft.favorite,
            archived,
            trashed_at: None,
            created_at,
            updated_at: now,
            sentinel_ignored,
            custom_icon: !details.icon.is_empty(),
            imported_from,
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

/// The item's own icon, if it has one.
pub async fn item_icon(state: &AppState, item_id: &str) -> AppResult<Option<String>> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let (_, details) = load_details(state, session, item_id)?;
    Ok(Some(details.icon.clone()).filter(|icon| !icon.is_empty()))
}

/// A copy of an item in the same vault, titled `title`. Its attachments and
/// passkeys stay with the original: attachments live on the server under
/// their id and vault, so two items of one vault cannot share them.
pub async fn duplicate_item(app: &AppHandle, item_id: &str, title: &str) -> AppResult<ItemSummary> {
    let state = app.state::<AppState>();
    let mut draft = get_item_draft(&state, item_id).await?;
    draft.id = None;
    draft.title = title.to_string();
    save_item_with(app, draft, Extras { passkeys: Some(Vec::new()), attachments: Some(Vec::new()) }).await
}

/// A copy of an item in another vault, with its passkeys and attachments
/// (whose encrypted chunks are copied on the server to the other vault).
pub async fn copy_item_to_vault(app: &AppHandle, item_id: &str, to_vault: &str) -> AppResult<ItemSummary> {
    let state = app.state::<AppState>();
    let mut draft = get_item_draft(&state, item_id).await?;
    if draft.vault_id == to_vault {
        let title = draft.title.clone();
        return duplicate_item(app, item_id, &title).await;
    }
    let (passkeys, attachments) = {
        let mut guard = state.session.lock().await;
        let session = unlocked(&mut guard)?;
        let (_, details) = load_details(&state, session, item_id)?;
        (details.passkeys.clone(), details.attachments.clone())
    };
    let copied = crate::attachments::copy_to_vault(app, item_id, to_vault).await?;
    draft.id = None;
    draft.vault_id = to_vault.to_string();
    match save_item_with(app, draft, Extras { passkeys: Some(passkeys), attachments: Some(attachments) }).await {
        Ok(summary) => Ok(summary),
        Err(err) => {
            // What was copied for it goes.
            crate::attachments::forget(app, copied);
            Err(err)
        }
    }
}

/// A field's value as a QR code (SVG), for showing it in large type.
pub async fn field_qr(state: &AppState, item_id: &str, field_id: &str) -> AppResult<String> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let (_, details) = load_details(state, session, item_id)?;
    let field = find_field(&details, field_id)?;
    qr_svg(&field.value)
}

/// The QR code phones scan to join a wireless router item's network
/// ("WIFI:S:<name>;T:<security>;P:<password>;;").
pub async fn wifi_qr(state: &AppState, item_id: &str) -> AppResult<String> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let (_, details) = load_details(state, session, item_id)?;
    qr_svg(&keyless_core::wifi::payload(&details).map_err(|_| AppError::Invalid(Msg::new("wifi_no_name")))?)
}

pub(crate) fn qr_svg(text: &str) -> AppResult<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|_| AppError::Invalid(Msg::new("qr_too_long")))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

/// A QR code in Keyless's look (see `keyless_core::qr`), for the codes one
/// Keyless app shows another: signing in and setup codes.
pub(crate) fn branded_qr_svg(text: &str) -> AppResult<String> {
    use std::fmt::Write;
    let art = keyless_core::qr::art(text).ok_or_else(|| AppError::Invalid(Msg::new("qr_too_long")))?;
    const QUIET: f32 = 4.0;
    // Near black: lighter colors stopped readers finding the code.
    const DARK: &str = "#061a18";
    let side = art.size as f32 + 2.0 * QUIET;
    let n = |v: f32| format!("{}", (v * 100.0).round() / 100.0);
    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}" width="320" height="320" shape-rendering="geometricPrecision"><rect width="{s}" height="{s}" fill="#fff"/>"##,
        s = n(side)
    );
    let rect = |svg: &mut String, x: f32, y: f32, w: f32, r: f32, fill: &str| {
        let _ = write!(svg, r#"<rect x="{}" y="{}" width="{}" height="{}" rx="{}" fill="{fill}"/>"#, n(x), n(y), n(w), n(w), n(r));
    };
    let [outer, hole, stone] = art.finder_corners;
    for &[x, y] in &art.finders {
        let (x, y) = (x as f32 + QUIET, y as f32 + QUIET);
        rect(&mut svg, x, y, 7.0, outer, DARK);
        rect(&mut svg, x + 1.0, y + 1.0, 5.0, hole, "#fff");
        rect(&mut svg, x + 2.0, y + 2.0, 3.0, stone, DARK);
    }
    let [outer, hole] = art.alignment_corners;
    let r = art.dot_radius;
    for &[x, y] in &art.alignments {
        let (cx, cy) = (x as f32 + QUIET + 0.5, y as f32 + QUIET + 0.5);
        rect(&mut svg, cx - 2.5, cy - 2.5, 5.0, outer, DARK);
        rect(&mut svg, cx - 1.5, cy - 1.5, 3.0, hole, "#fff");
        let _ = write!(svg, r#"<circle cx="{}" cy="{}" r="{}" fill="{DARK}"/>"#, n(cx), n(cy), n(r));
    }
    // Every module in one path: a dot is two half arcs, a square four lines.
    let _ = write!(svg, r#"<path fill="{DARK}" d=""#);
    for (y, row) in art.modules.iter().enumerate() {
        for (x, kind) in row.bytes().enumerate() {
            let (left, top) = (x as f32 + QUIET, y as f32 + QUIET);
            match kind {
                b'1' => {
                    let _ = write!(svg, "M{} {}a{r} {r} 0 1 0 {d} 0a{r} {r} 0 1 0 -{d} 0", n(left + 0.5 - r), n(top + 0.5), r = n(r), d = n(2.0 * r));
                }
                b'2' => {
                    let _ = write!(svg, "M{} {}h1v1h-1z", n(left), n(top));
                }
                _ => {}
            }
        }
    }
    svg.push_str(r#""/>"#);
    // The logo (as in the app's Logo component), inside a white margin.
    let center = side / 2.0;
    let scale = art.logo_radius * 0.82 / 452.0;
    let _ = write!(
        svg,
        concat!(
            r##"<g transform="translate({x:.4} {x:.4}) scale({s:.6})">"##,
            r##"<defs><linearGradient id="kq-r" x1="0.18" y1="0.08" x2="0.82" y2="0.96"><stop offset="0" stop-color="#7AF0DD"/><stop offset="0.45" stop-color="#14B8A6"/><stop offset="1" stop-color="#0B5F58"/></linearGradient>"##,
            r##"<radialGradient id="kq-c" cx="0.5" cy="0.32" r="0.75"><stop offset="0" stop-color="#16524D"/><stop offset="1" stop-color="#062523"/></radialGradient></defs>"##,
            r##"<circle cx="512" cy="512" r="452" fill="url(#kq-r)"/><circle cx="512" cy="512" r="318" fill="url(#kq-c)"/>"##,
            r##"<g fill="#F2FFFC"><circle cx="512" cy="438" r="94"/><path d="M470 486 H554 L586 676 Q590 702 564 702 H460 Q434 702 438 676 Z"/></g></g>"##,
        ),
        x = center - 512.0 * scale,
        s = scale,
    );
    svg.push_str("</svg>");
    Ok(svg)
}

/// Items whose details hold `query`: notes, labels, section titles, file
/// names and the values that are not secret (passwords, card numbers,
/// codes and answers are never searched). The details are decrypted for
/// the search and wiped right after.
pub async fn search_details(state: &AppState, query: &str) -> AppResult<Vec<String>> {
    let query = keyless_core::search::fold(query.trim());
    if query.chars().count() < 2 {
        return Ok(Vec::new());
    }
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let ids: Vec<String> = session.items.keys().cloned().collect();
    let mut found = Vec::new();
    for id in ids {
        let Ok((_, details)) = load_details(state, session, &id) else { continue };
        if details.matches(&query) {
            found.push(id);
        }
    }
    Ok(found)
}

/// Items that keep a passkey (their details are decrypted to tell, only
/// when the list is filtered by it).
pub async fn items_with_passkeys(state: &AppState) -> AppResult<Vec<String>> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let ids: Vec<String> = session.items.keys().cloned().collect();
    Ok(ids
        .into_iter()
        .filter(|id| load_details(state, session, id).is_ok_and(|(_, details)| !details.passkeys.is_empty()))
        .collect())
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
    if !keyless_core::health::ALERTS.contains(&alert) {
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

/// Watches again several ignored alerts, (item id, alert) pairs: one new
/// version per item. An item that cannot be changed (a read-only vault)
/// does not stop the others; the first error is returned at the end.
pub async fn unignore_sentinel(app: &AppHandle, pairs: &[(String, String)]) -> AppResult<()> {
    let mut by_item: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for (item_id, alert) in pairs {
        if !keyless_core::health::ALERTS.contains(&alert.as_str()) {
            return Err(AppError::Invalid(Msg::new("invalid_request")));
        }
        by_item.entry(item_id).or_default().push(alert);
    }
    let mut failed = None;
    for (item_id, alerts) in by_item {
        if let Err(err) = update_overview(app, item_id, |o| o.sentinel_ignored.retain(|a| !alerts.contains(&a.as_str()))).await {
            failed.get_or_insert(err);
        }
    }
    failed.map_or(Ok(()), Err)
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
    let mut renamed = Vec::new();
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
            renamed.push((id.clone(), new_id));
            moved += 1;
        }
        moved
    };
    if let Err(err) = crate::pinned::moved(app, &renamed).await {
        log::info!("pins: {err}");
    }
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
/// Saves imported items, with the ids the import gave them (their links to
/// one another use those).
/// The account's items outside Recently Deleted, decrypted, for an import to
/// compare its items with (see `keyless_core::import::reconcile`): id, vault,
/// overview and details. Items that do not open are left out.
pub fn existing_items(state: &AppState, session: &Session) -> Vec<(String, String, ItemOverview, ItemDetails)> {
    let mut out = Vec::with_capacity(session.items.len());
    for (id, cached) in &session.items {
        if cached.overview.trashed_at.is_some() {
            continue;
        }
        match load_details(state, session, id) {
            Ok((_, details)) => out.push((id.clone(), cached.vault_id.clone(), cached.overview.clone(), details)),
            Err(err) => log::warn!("import: an item to compare with did not open: {err}"),
        }
    }
    out
}

/// An import's update of item `item_id`: its next version, where it is.
pub async fn update_imported(state: &AppState, item_id: &str, mut overview: ItemOverview, mut details: ItemDetails) -> AppResult<()> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let local = state.store().item(item_id)?.ok_or(AppError::NotFound)?;
    if !session.vault(&local.vault_id)?.can_write() {
        return Err(AppError::Invalid(Msg::new("vault_read_only")));
    }
    if overview.subtitle.is_empty() {
        overview.subtitle = compute_subtitle(overview.category, &details);
    }
    write_local_item(state, session, item_id, &local.vault_id.clone(), local.revision, local.version + 1, &mut overview, &mut details)
}

/// Where an import's vault goes again, if this account can write to it:
/// `home` (the vault with most of the items the account has from it), or
/// a vault named `name` (any case), from an earlier import.
pub async fn import_home(state: &AppState, home: Option<&str>, name: &str) -> Option<String> {
    let guard = state.session.lock().await;
    let session = guard.as_ref()?;
    if let Some(id) = home.filter(|id| session.vaults.get(*id).is_some_and(|v| v.can_write())) {
        return Some(id.to_string());
    }
    let name = name.trim().to_lowercase();
    session.vaults.iter().find(|(_, v)| v.can_write() && v.meta.name.trim().to_lowercase() == name).map(|(id, _)| id.clone())
}

pub async fn insert_imported(state: &AppState, vault_id: &str, items: Vec<(String, ItemOverview, ItemDetails)>) -> AppResult<usize> {
    let mut guard = state.session.lock().await;
    let session = unlocked(&mut guard)?;
    let now = now_secs();
    let mut count = 0;
    for (id, mut overview, details) in items {
        if overview.created_at == 0 {
            overview.created_at = now;
        }
        if overview.updated_at == 0 {
            overview.updated_at = now;
        }
        if overview.subtitle.is_empty() {
            overview.subtitle = compute_subtitle(overview.category, &details);
        }
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
            extra: Default::default(),
        });
        assert_eq!(compute_subtitle(Category::CreditCard, &details), "•••• 1234");

        let mut login = ItemDetails::default();
        login.fields.push(Field {
            id: "u".into(),
            label: "username".into(),
            kind: FieldKind::Text,
            value: "me".into(),
            purpose: Some(FieldPurpose::Username),
            extra: Default::default(),
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
            extra: Default::default(),
        };
        let view = field_view(&password);
        assert!(view.value.is_none());
        assert!(view.has_value);
        let mut mislabeled = password.clone();
        mislabeled.kind = FieldKind::Text;
        assert!(field_view(&mislabeled).value.is_none());
    }
}
