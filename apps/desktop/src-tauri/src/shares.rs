//! Share links (see `keyless_core::share` and the `shares` migration): a
//! snapshot of an item that someone without Keyless opens in their browser.
//! The key exists only in the link; the server keeps ciphertext, and for the
//! owner a label (the item, its title and who may open it) encrypted with
//! their own key, to list and revoke their links.
//!
//! A link can be only for some email addresses (the `share_recipients`
//! migration): the server keeps their SHA-256 and gives the ciphertext only
//! to a visitor who proved one of them with a code sent by email.

use keyless_core::{
    share::{DURATIONS_HOURS, MAX_RECIPIENTS, ShareKey, ShareLabel as Label, SharedItem, label_context, recipient_hash},
    time::{iso8601, parse_iso8601},
};
use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    api::now_secs,
    config,
    error::{AppError, AppResult, Msg},
    items,
    state::AppState,
    sync,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedShare {
    pub id: String,
    /// The link, with its key: shown once, never stored.
    pub link: Zeroizing<String>,
    pub expires_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareView {
    pub id: String,
    pub item_id: String,
    pub title: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub max_views: Option<i64>,
    pub views: i64,
    /// "active", "expired", "revoked" or "used" (a one-view link opened).
    pub status: &'static str,
    /// Only these emails may open it (empty: anyone with the link).
    pub recipients: Vec<String>,
}

/// Creates a link for item `item_id` that lasts `hours` (one of the offered
/// durations), for one view or for any number, and when `recipients` are
/// given only for those emails.
pub async fn create(app: &AppHandle, item_id: &str, hours: u32, view_once: bool, recipients: &[String]) -> AppResult<CreatedShare> {
    if !DURATIONS_HOURS.contains(&hours) {
        return Err(AppError::Invalid(Msg::new("share_duration")));
    }
    let mut emails: Vec<String> = Vec::new();
    for email in recipients.iter().filter(|e| !e.trim().is_empty()) {
        let email = crate::auth::normalize_email(email)?;
        if !emails.contains(&email) {
            emails.push(email);
        }
    }
    if emails.len() > MAX_RECIPIENTS {
        return Err(AppError::Invalid(Msg::new("share_too_many_recipients").with("max", MAX_RECIPIENTS)));
    }
    let state = app.state::<AppState>();
    let key = ShareKey::generate()?;
    let now = now_secs();
    let (payload, label) = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        let cached = session.items.get(item_id).ok_or(AppError::NotFound)?;
        if cached.overview.trashed_at.is_some() {
            return Err(AppError::Invalid(Msg::new("share_trashed")));
        }
        let (_, details) = items::load_details(&state, session, item_id)?;
        let payload = key.seal(&SharedItem::of(&cached.overview, &details, now))?;
        let label = serde_json::to_vec(&Label { item_id: item_id.to_string(), title: cached.overview.title.clone(), recipients: emails.clone() })?;
        let label = session.account.user_key().seal(&label, &label_context(&key.id, &session.user_id))?;
        (payload, label)
    };
    let expires_at = now + hours as i64 * 3600;
    let (_, token) = sync::ensure_token(&state).await?;
    let mut row = json!({
        "id": key.id,
        "enc_payload": payload,
        "enc_label": label,
        "expires_at": iso8601(expires_at),
        "max_views": if view_once { Some(1) } else { None },
    });
    if !emails.is_empty() {
        // bytea values, as PostgREST reads them.
        row["recipients"] = json!(emails.iter().map(|e| recipient_hash(e)).collect::<Vec<_>>());
    }
    state.api.insert_share(&token, &row).await.map_err(|err| match err {
        // The server does not know the column yet (migration not applied).
        AppError::Server(message) if message.contains("PGRST204") => AppError::Invalid(Msg::new("share_recipients_unavailable")),
        other => other,
    })?;
    Ok(CreatedShare { id: key.id.clone(), link: key.link(config::SHARE_PAGE_URL), expires_at })
}

/// The account's links, newest first: those that can still be opened, or
/// with `all` also those that ended (the server keeps them for a day); only
/// those of item `item_id` when given.
pub async fn list(app: &AppHandle, item_id: Option<&str>, all: bool) -> AppResult<Vec<ShareView>> {
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    let remote = state.api.shares(&token).await?;
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let now = now_secs();
    Ok(remote
        .into_iter()
        .filter_map(|s| {
            let expires_at = parse_iso8601(&s.expires_at)?;
            let status = if s.revoked_at.is_some() {
                "revoked"
            } else if s.max_views.is_some_and(|max| s.views >= max) {
                "used"
            } else if expires_at <= now {
                "expired"
            } else {
                "active"
            };
            if !all && status != "active" {
                return None;
            }
            // A label that does not open is not this account's.
            let plain = session.account.user_key().open(&s.enc_label, &label_context(&s.id, &session.user_id)).ok()?;
            let label: Label = serde_json::from_slice(&plain).ok()?;
            if item_id.is_some_and(|id| id != label.item_id) {
                return None;
            }
            Some(ShareView {
                id: s.id,
                item_id: label.item_id,
                title: label.title,
                created_at: parse_iso8601(&s.created_at).unwrap_or(0),
                expires_at,
                max_views: s.max_views,
                views: s.views,
                status,
                recipients: label.recipients,
            })
        })
        .collect())
}

pub async fn revoke(app: &AppHandle, share_id: &str) -> AppResult<()> {
    let id = uuid::Uuid::parse_str(share_id).map_err(|_| AppError::NotFound)?.to_string();
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.revoke_share(&token, &id, &iso8601(now_secs())).await
}
