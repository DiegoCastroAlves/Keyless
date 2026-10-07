//! Share links (see `keyless_core::share` and the `shares` migration): a
//! snapshot of an item that someone without Keyless opens in their browser.
//! The key exists only in the link; the server keeps ciphertext, and for the
//! owner a label (the item and its title) encrypted with their own key, to
//! list and revoke their links.

use keyless_core::{
    crypto::context,
    share::{ShareKey, SharedItem},
};
use serde::{Deserialize, Serialize};
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

/// How long a link may last, as offered in the app.
const DURATIONS_HOURS: [u32; 5] = [1, 24, 7 * 24, 14 * 24, 30 * 24];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Label {
    item_id: String,
    title: String,
}

fn label_context(share_id: &str, user_id: &str) -> Vec<u8> {
    context("keyless/share-label", &[share_id, user_id])
}

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
    pub expires_at: i64,
    pub max_views: Option<i64>,
    pub views: i64,
}

/// Creates a link for item `item_id` that lasts `hours` (one of the offered
/// durations), for one view or for any number.
pub async fn create(app: &AppHandle, item_id: &str, hours: u32, view_once: bool) -> AppResult<CreatedShare> {
    if !DURATIONS_HOURS.contains(&hours) {
        return Err(AppError::Invalid(Msg::new("share_duration")));
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
        let label = serde_json::to_vec(&Label { item_id: item_id.to_string(), title: cached.overview.title.clone() })?;
        let label = session.account.user_key().seal(&label, &label_context(&key.id, &session.user_id))?;
        (payload, label)
    };
    let expires_at = now + hours as i64 * 3600;
    let (_, token) = sync::ensure_token(&state).await?;
    let row = json!({
        "id": key.id,
        "enc_payload": payload,
        "enc_label": label,
        "expires_at": iso8601(expires_at),
        "max_views": if view_once { Some(1) } else { None },
    });
    state.api.insert_share(&token, &row).await?;
    Ok(CreatedShare { id: key.id.clone(), link: key.link(config::SHARE_PAGE_URL), expires_at })
}

/// The account's links that can still be opened, newest first; only those
/// of item `item_id` when given.
pub async fn list(app: &AppHandle, item_id: Option<&str>) -> AppResult<Vec<ShareView>> {
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    let remote = state.api.shares(&token).await?;
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let now = now_secs();
    Ok(remote
        .into_iter()
        .filter(|s| s.revoked_at.is_none() && s.max_views.is_none_or(|max| s.views < max))
        .filter_map(|s| {
            let expires_at = parse_iso8601(&s.expires_at)?;
            if expires_at <= now {
                return None;
            }
            // A label that does not open is not this account's.
            let plain = session.account.user_key().open(&s.enc_label, &label_context(&s.id, &session.user_id)).ok()?;
            let label: Label = serde_json::from_slice(&plain).ok()?;
            if item_id.is_some_and(|id| id != label.item_id) {
                return None;
            }
            Some(ShareView { id: s.id, item_id: label.item_id, title: label.title, expires_at, max_views: s.max_views, views: s.views })
        })
        .collect())
}

pub async fn revoke(app: &AppHandle, share_id: &str) -> AppResult<()> {
    let id = uuid::Uuid::parse_str(share_id).map_err(|_| AppError::NotFound)?.to_string();
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.revoke_share(&token, &id, &iso8601(now_secs())).await
}

/// Unix seconds as `2026-10-07T19:15:06Z`.
fn iso8601(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// Unix seconds from a timestamp as Postgres writes it
/// (`2026-10-07T19:15:06.623+00:00`).
fn parse_iso8601(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once(['T', ' '])?;
    let mut parts = date.split('-');
    let (year, month, day) = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
    let zone_at = rest.find(['Z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(zone_at);
    let mut clock = clock.split(':');
    let hours: i64 = clock.next()?.parse().ok()?;
    let minutes: i64 = clock.next()?.parse().ok()?;
    let seconds: i64 = clock.next().unwrap_or("0").split('.').next()?.parse().ok()?;
    let offset = match zone {
        "" | "Z" => 0,
        _ => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let mut z = zone[1..].split(':');
            let (h, m): (i64, i64) = (z.next()?.parse().ok()?, z.next().unwrap_or("0").parse().ok()?);
            sign * (h * 3600 + m * 60)
        }
    };
    Some(crate::health::unix_day(year, month, day) + hours * 3600 + minutes * 60 + seconds - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_791_400_506), "2026-10-07T19:15:06Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(parse_iso8601("2026-10-07T19:15:06.623+00:00"), Some(1_791_400_506));
        assert_eq!(parse_iso8601("2026-10-07T16:15:06-03:00"), Some(1_791_400_506));
        assert_eq!(parse_iso8601("2026-10-07 19:15:06Z"), Some(1_791_400_506));
        assert_eq!(parse_iso8601(&iso8601(1_700_000_123)), Some(1_700_000_123));
        assert_eq!(parse_iso8601("garbage"), None);
    }
}
