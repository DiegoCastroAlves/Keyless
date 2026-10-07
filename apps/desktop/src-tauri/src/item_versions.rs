//! Earlier versions of an item ("item history", like 1Password's). The server
//! keeps the ciphertext each write replaced (see the `item_versions`
//! migration); here they are decrypted and checked like synced items: both
//! documents must open with the vault key, bound to this vault and item, and
//! come from the same write, and be older than the current item. Restoring a
//! version saves its content as a new write, so it never brings back an old
//! version number.

use keyless_core::item::{Field, ItemDetails, ItemOverview, ItemUrl, same_write};
use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    error::{AppError, AppResult},
    items::{self, FieldView, ItemDraft, ItemSummary, SectionView},
    state::AppState,
    sync,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemVersionView {
    pub revision: i64,
    /// When this version was saved (from the encrypted item).
    pub updated_at: i64,
    pub title: String,
    pub url_entries: Vec<ItemUrl>,
    pub fields: Vec<FieldView>,
    pub sections: Vec<SectionView>,
    pub notes: String,
    /// What the next version changed: field labels, or ":title",
    /// ":websites", ":notes", ":tags".
    pub changed: Vec<String>,
}

struct Version {
    revision: i64,
    overview: ItemOverview,
    details: ItemDetails,
}

/// The item's earlier versions that check out, newest first.
async fn fetch(state: &AppState, item_id: &str) -> AppResult<(Vec<Version>, ItemOverview, ItemDetails)> {
    let (_, token) = sync::ensure_token(state).await?;
    let remote = state.api.item_versions(&token, item_id).await?;
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let cached = session.items.get(item_id).ok_or(AppError::NotFound)?;
    let (_, current_details) = items::load_details(state, session, item_id)?;
    let current = cached.overview.clone();
    let vault = session.vault(&cached.vault_id)?;
    let mut versions: Vec<Version> = remote
        .into_iter()
        .filter_map(|v| {
            let overview = vault.key.open_overview(&cached.vault_id, item_id, &v.enc_overview).ok()?;
            let details = vault.key.open_details(&cached.vault_id, item_id, &v.enc_details).ok()?;
            (same_write(&overview, &details) && overview.version < current.version).then_some(Version { revision: v.revision, overview, details })
        })
        .collect();
    versions.sort_by_key(|v| std::cmp::Reverse(v.overview.version));
    versions.dedup_by_key(|v| v.overview.version);
    Ok((versions, current, current_details))
}

fn all_fields(details: &ItemDetails) -> impl Iterator<Item = &Field> {
    details.fields.iter().chain(details.sections.iter().flat_map(|s| s.fields.iter()))
}

/// What changed from `old` to `new`, by name.
fn changes(old: (&ItemOverview, &ItemDetails), new: (&ItemOverview, &ItemDetails)) -> Vec<String> {
    let mut changed = Vec::new();
    if old.0.title != new.0.title {
        changed.push(":title".to_string());
    }
    if old.0.urls != new.0.urls {
        changed.push(":websites".to_string());
    }
    if old.0.tags != new.0.tags {
        changed.push(":tags".to_string());
    }
    for field in all_fields(old.1) {
        let after = all_fields(new.1).find(|f| f.id == field.id);
        if after.is_none_or(|f| f.value != field.value || f.label != field.label) && !changed.contains(&field.label) {
            changed.push(field.label.clone());
        }
    }
    for field in all_fields(new.1) {
        if !all_fields(old.1).any(|f| f.id == field.id) && !changed.contains(&field.label) {
            changed.push(field.label.clone());
        }
    }
    if old.1.notes != new.1.notes {
        changed.push(":notes".to_string());
    }
    changed
}

pub async fn list(state: &AppState, item_id: &str) -> AppResult<Vec<ItemVersionView>> {
    let (versions, current, current_details) = fetch(state, item_id).await?;
    let mut views = Vec::with_capacity(versions.len());
    for (i, v) in versions.iter().enumerate() {
        let newer = match i {
            0 => (&current, &current_details),
            _ => (&versions[i - 1].overview, &versions[i - 1].details),
        };
        let mut details = v.details.clone();
        details.sort_main_fields();
        views.push(ItemVersionView {
            revision: v.revision,
            updated_at: v.overview.updated_at,
            title: v.overview.title.clone(),
            url_entries: v.overview.urls.clone(),
            fields: details.fields.iter().map(items::field_view).collect(),
            sections: details
                .sections
                .iter()
                .map(|s| SectionView { id: s.id.clone(), title: s.title.clone(), fields: s.fields.iter().map(items::field_view).collect() })
                .collect(),
            notes: details.notes.clone(),
            changed: changes((&v.overview, &v.details), newer),
        });
    }
    Ok(views)
}

async fn version(state: &AppState, item_id: &str, revision: i64) -> AppResult<Version> {
    let (versions, _, _) = fetch(state, item_id).await?;
    versions.into_iter().find(|v| v.revision == revision).ok_or(AppError::NotFound)
}

/// A secret field of an earlier version, shown when the user asks.
pub async fn reveal(state: &AppState, item_id: &str, revision: i64, field_id: &str) -> AppResult<Zeroizing<String>> {
    let v = version(state, item_id, revision).await?;
    let field = all_fields(&v.details).find(|f| f.id == field_id).ok_or(AppError::NotFound)?;
    Ok(Zeroizing::new(field.value.clone()))
}

/// Saves an earlier version's content as the item's newest version. The
/// password it replaces goes to the password history as on any edit; the
/// item stays where it is (vault, favorite, archive).
pub async fn restore(app: &AppHandle, item_id: &str, revision: i64) -> AppResult<ItemSummary> {
    let state = app.state::<AppState>();
    let mut v = version(&state, item_id, revision).await?;
    let (vault_id, favorite) = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        let current = session.items.get(item_id).ok_or(AppError::NotFound)?;
        (current.vault_id.clone(), current.overview.favorite)
    };
    let draft = ItemDraft {
        id: Some(item_id.to_string()),
        vault_id,
        title: v.overview.title,
        category: v.overview.category,
        urls: v.overview.urls,
        tags: v.overview.tags,
        favorite,
        fields: std::mem::take(&mut v.details.fields),
        sections: std::mem::take(&mut v.details.sections),
        notes: std::mem::take(&mut v.details.notes),
    };
    items::save_item(app, draft).await
}

#[cfg(test)]
mod tests {
    use keyless_core::item::{FieldKind, FieldPurpose};

    use super::*;

    fn field(id: &str, label: &str, value: &str) -> Field {
        Field { id: id.into(), label: label.into(), kind: FieldKind::Text, value: value.into(), purpose: Some(FieldPurpose::Username) }
    }

    #[test]
    fn names_what_changed() {
        let old_o = ItemOverview { title: "GitHub".into(), ..Default::default() };
        let mut old_d = ItemDetails::default();
        old_d.fields = vec![field("u", "username", "ana"), field("p", "password", "one")];
        let mut new_o = old_o.clone();
        let mut new_d = ItemDetails::default();
        new_d.fields = vec![field("u", "username", "ana"), field("p", "password", "two"), field("x", "pin", "1234")];
        assert_eq!(changes((&old_o, &old_d), (&new_o, &new_d)), vec!["password", "pin"]);
        new_o.title = "GitHub work".into();
        new_d.notes = "hello".into();
        new_d.fields.truncate(1);
        assert_eq!(changes((&old_o, &old_d), (&new_o, &new_d)), vec![":title", "password", ":notes"]);
    }
}
