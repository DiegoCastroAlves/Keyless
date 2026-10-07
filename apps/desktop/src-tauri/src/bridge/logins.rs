//! Saving logins from the browser (the "Save login?" prompt) and suggesting
//! passwords for sign-up and change-password forms.
//!
//! The extension only calls these from its own pages (the prompt and the
//! menus, never a web page), after the user chose to save. The app checks
//! the vault can be written and keeps the old password in the item's
//! history when updating.

use keyless_core::{
    generator::{GeneratorOptions, generate},
    item::{Category, Field, FieldKind, FieldPurpose, ItemUrl, new_field_id},
};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use super::handlers::{Page, match_score, site_of};
use crate::{
    items::{self, ItemDraft},
    state::AppState,
    sync::EVENT_ITEMS_CHANGED,
};

/// Default length of a suggested password.
const SUGGESTED_LENGTH: usize = 20;

fn is_login(category: Category) -> bool {
    matches!(category, Category::Login | Category::Password)
}

/// Vaults a login can be saved to; the personal one first.
pub async fn vaults(app: &AppHandle) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let vaults = items::list_vaults(&state).await.map_err(|_| "locked")?;
    Ok(Value::Array(
        vaults
            .into_iter()
            .filter(|v| v.can_write && !v.orphaned)
            .map(|v| json!({ "id": v.id, "name": v.name }))
            .collect(),
    ))
}

/// Compares what the user typed with the logins saved for the page:
/// - "same": nothing to save;
/// - "update": a login with this username has another password;
/// - "new": no login with this username.
///
/// `candidates` are the page's logins: the one whose password is `current`
/// (the current password typed in a change-password form) first, then
/// those with this username. `current` marks the login being changed.
pub async fn check(app: &AppHandle, url: &str, username: &str, password: &str, current: &str) -> Result<Value, &'static str> {
    let page = Page::parse(url).ok_or("bad_request")?;
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;

    let mut state_name = "new";
    let mut candidates: Vec<((bool, bool), Value)> = Vec::new();
    for (id, item) in &session.items {
        let o = &item.overview;
        if o.trashed_at.is_some() || o.archived || !is_login(o.category) {
            continue;
        }
        if !o.urls.iter().any(|u| match_score(&page, u) > 0) {
            continue;
        }
        let Ok((_, details)) = items::load_details(&state, session, id) else { continue };
        let saved_user = details.username().unwrap_or("");
        // A form may ask only for the password (second step of a login).
        let same_user = username.is_empty() || saved_user.eq_ignore_ascii_case(username);
        let is_current = !current.is_empty() && details.password() == Some(current);
        if same_user || is_current {
            if same_user && details.password() == Some(password) {
                return Ok(json!({ "state": "same", "candidates": [] }));
            }
            state_name = "update";
        }
        let vault = session.vaults.get(&item.vault_id).map(|v| v.meta.name.clone()).unwrap_or_default();
        candidates.push((
            (is_current, same_user),
            json!({ "id": id, "title": o.title, "username": saved_user, "vault": vault, "sameUser": same_user, "current": is_current }),
        ));
    }
    candidates.sort_by_key(|((is_current, same_user), _)| (!is_current, !same_user));
    Ok(json!({
        "state": state_name,
        "candidates": candidates.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
        "title": suggested_title(&page_host(url)),
    }))
}

fn page_host(url: &str) -> String {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default()
}

/// "accounts.google.com" -> "Google".
fn suggested_title(host: &str) -> String {
    let site = site_of(host.trim_start_matches("www."));
    let name = site.split('.').next().unwrap_or(&site);
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => host.to_string(),
    }
}

/// The page's address without path, query or fragment.
fn origin(url: &str) -> Result<String, &'static str> {
    let parsed = url::Url::parse(url).map_err(|_| "bad_request")?;
    Ok(parsed.origin().ascii_serialization())
}

fn login_field(purpose: FieldPurpose, value: &str) -> Field {
    let (label, kind) = match purpose {
        FieldPurpose::Password => ("password", FieldKind::Concealed),
        _ => ("username", FieldKind::Text),
    };
    Field { id: new_field_id(), label: label.into(), kind, value: value.into(), purpose: Some(purpose) }
}

/// Saves a new login for the page.
pub async fn save_new(
    app: &AppHandle,
    url: &str,
    title: &str,
    username: &str,
    password: Zeroizing<String>,
    vault_id: Option<&str>,
) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let vault_id = match vault_id {
        Some(id) => id.to_string(),
        None => {
            let vaults = vaults(app).await?;
            vaults[0]["id"].as_str().ok_or("no_vault")?.to_string()
        }
    };
    let title = match title.trim() {
        "" => suggested_title(&page_host(url)),
        title => title.to_string(),
    };
    let draft = ItemDraft {
        id: None,
        vault_id,
        title,
        category: Category::Login,
        urls: vec![ItemUrl { href: origin(url)?, ..Default::default() }],
        tags: Vec::new(),
        favorite: false,
        fields: vec![login_field(FieldPurpose::Username, username), login_field(FieldPurpose::Password, &password)],
        sections: Vec::new(),
        notes: String::new(),
    };
    let saved = items::save_item(app, draft).await.map_err(save_error)?;
    let _ = app.emit(EVENT_ITEMS_CHANGED, ());
    crate::commands::record_use(&state, &saved.id);
    Ok(json!({ "id": saved.id }))
}

/// Updates the password (and username) of a saved login for the page; the
/// old password goes to the item's history. Only a login saved for the page
/// can be changed from it.
pub async fn update(app: &AppHandle, id: &str, url: &str, username: &str, password: Zeroizing<String>) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let mut draft = items::get_item_draft(&state, id).await.map_err(save_error)?;
    if !is_login(draft.category) {
        return Err("bad_request");
    }
    let page = Page::parse(url).ok_or("bad_request")?;
    let mut set = |purpose: FieldPurpose, value: &str| match draft.fields.iter_mut().find(|f| f.purpose == Some(purpose)) {
        Some(field) => field.value = value.to_string(),
        None => draft.fields.push(login_field(purpose, value)),
    };
    if !username.is_empty() {
        set(FieldPurpose::Username, username);
    }
    if !draft.urls.iter().any(|u| match_score(&page, u) > 0) {
        return Err("bad_request");
    }
    set(FieldPurpose::Password, &password);
    let saved = items::save_item(app, draft).await.map_err(save_error)?;
    let _ = app.emit(EVENT_ITEMS_CHANGED, ());
    crate::commands::record_use(&state, &saved.id);
    Ok(json!({ "id": saved.id }))
}

fn save_error(err: crate::error::AppError) -> &'static str {
    use crate::error::AppError;
    match err {
        AppError::Locked => "locked",
        AppError::NotFound => "not_found",
        AppError::Invalid(msg) if msg.key == "vault_read_only" => "read_only",
        _ => "error",
    }
}

/// A strong random password; `max_length` and `symbols` follow the form.
pub fn suggest(max_length: Option<u64>, symbols: bool) -> Result<Value, &'static str> {
    let length = max_length.map_or(SUGGESTED_LENGTH, |max| (max as usize).clamp(8, SUGGESTED_LENGTH));
    let options = GeneratorOptions::Random { length, uppercase: true, lowercase: true, digits: true, symbols, avoid_ambiguous: true };
    let generated = generate(&options).map_err(|_| "error")?;
    Ok(json!({ "password": generated.password.as_str() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_and_origins() {
        assert_eq!(suggested_title("accounts.google.com"), "Google");
        assert_eq!(suggested_title("www.instagram.com"), "Instagram");
        assert_eq!(suggested_title("nubank.com.br"), "Nubank");
        assert_eq!(origin("https://www.instagram.com/accounts/login/?next=%2F#x").unwrap(), "https://www.instagram.com");
    }

    #[test]
    fn suggestions_follow_the_form() {
        let password = |max, symbols| suggest(max, symbols).unwrap()["password"].as_str().unwrap().to_string();
        assert_eq!(password(None, true).len(), SUGGESTED_LENGTH);
        assert_eq!(password(Some(12), true).len(), 12);
        assert!(password(None, false).chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
