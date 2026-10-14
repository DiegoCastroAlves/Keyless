//! Share links, made and listed as the desktop does (see its `shares`): a
//! snapshot of an item encrypted with a key that exists only in the link;
//! for the owner, a label encrypted with their own key; and, for a link only
//! some emails may open, their hashes.

use keyless_core::{
    share::{DURATIONS_HOURS, MAX_RECIPIENTS, ShareKey, ShareLabel, SharedItem, label_context, recipient_hash},
    time::{iso8601, parse_iso8601},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Client, Failure, Outcome, args};

/// A row of `shares`, as the owner reads it.
#[derive(Deserialize)]
struct RemoteShare {
    id: String,
    enc_label: String,
    created_at: String,
    expires_at: String,
    #[serde(default)]
    revoked_at: Option<String>,
    #[serde(default)]
    max_views: Option<i64>,
    #[serde(default)]
    views: i64,
}

impl Client {
    /// A link for item `itemId` lasting `hours` (one of the offered
    /// durations), for one view or any number, and only for `recipients`
    /// when given: the row to insert into `shares`, and the link (with its
    /// key, for the page at `base`) to show once.
    pub(crate) fn share_create(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            item_id: String,
            hours: u32,
            #[serde(default)]
            view_once: bool,
            #[serde(default)]
            recipients: Vec<String>,
            base: String,
            now: i64,
        }
        let a: A = args(json)?;
        if !DURATIONS_HOURS.contains(&a.hours) {
            return Err(Failure::new("share_duration"));
        }
        let mut emails: Vec<String> = Vec::new();
        for email in a.recipients.iter().map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()) {
            if !email.contains('@') || email.len() > 254 {
                return Err(Failure::new("email_invalid"));
            }
            if !emails.contains(&email) {
                emails.push(email);
            }
        }
        if emails.len() > MAX_RECIPIENTS {
            return Err(Failure::new("share_too_many_recipients"));
        }
        let (_, overview, details) = self.open_item(&a.item_id)?;
        if overview.trashed_at.is_some() {
            return Err(Failure::new("share_trashed"));
        }
        let unlocked = self.unlocked()?;
        let key = ShareKey::generate()?;
        let payload = key.seal(&SharedItem::of(&overview, &details, a.now))?;
        let label = serde_json::to_vec(&ShareLabel { item_id: a.item_id.clone(), title: overview.title.clone(), recipients: emails.clone() })?;
        let label = unlocked.account.user_key().seal(&label, &label_context(&key.id, &self.store.user_id))?;
        let expires_at = a.now + a.hours as i64 * 3600;
        let mut row = json!({
            "id": key.id,
            "enc_payload": payload,
            "enc_label": label,
            "expires_at": iso8601(expires_at),
            "max_views": if a.view_once { Some(1) } else { None },
        });
        if !emails.is_empty() {
            row["recipients"] = json!(emails.iter().map(|e| recipient_hash(e)).collect::<Vec<_>>());
        }
        Ok(json!({ "row": row, "id": key.id, "link": key.link(&a.base).as_str(), "expiresAt": expires_at }))
    }

    /// The account's links (`rows` from `shares`), newest first: those that
    /// can still be opened, or with `all` also those that ended; only item
    /// `itemId`'s when given. A label that does not open is not this
    /// account's.
    pub(crate) fn share_list(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            rows: Vec<RemoteShare>,
            #[serde(default)]
            item_id: Option<String>,
            #[serde(default)]
            all: bool,
            now: i64,
        }
        let a: A = args(json)?;
        let unlocked = self.unlocked()?;
        let mut out: Vec<(i64, Value)> = Vec::new();
        for s in a.rows {
            let Some(expires_at) = parse_iso8601(&s.expires_at) else { continue };
            let status = if s.revoked_at.is_some() {
                "revoked"
            } else if s.max_views.is_some_and(|max| s.views >= max) {
                "used"
            } else if expires_at <= a.now {
                "expired"
            } else {
                "active"
            };
            if !a.all && status != "active" {
                continue;
            }
            let Ok(plain) = unlocked.account.user_key().open(&s.enc_label, &label_context(&s.id, &self.store.user_id)) else { continue };
            let Ok(label) = serde_json::from_slice::<ShareLabel>(&plain) else { continue };
            if a.item_id.as_deref().is_some_and(|id| id != label.item_id) {
                continue;
            }
            let created_at = parse_iso8601(&s.created_at).unwrap_or(0);
            out.push((
                created_at,
                json!({
                    "id": s.id,
                    "itemId": label.item_id,
                    "title": label.title,
                    "createdAt": created_at,
                    "expiresAt": expires_at,
                    "maxViews": s.max_views,
                    "views": s.views,
                    "status": status,
                    "recipients": label.recipients,
                }),
            ));
        }
        out.sort_by_key(|(created, _)| std::cmp::Reverse(*created));
        Ok(Value::Array(out.into_iter().map(|(_, v)| v).collect()))
    }

    /// The timestamp to write in `revoked_at`.
    pub(crate) fn share_revoked_at(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            now: i64,
        }
        let a: A = args(json)?;
        Ok(json!(iso8601(a.now)))
    }
}
