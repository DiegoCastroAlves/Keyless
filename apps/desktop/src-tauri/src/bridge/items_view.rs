//! Any item in the popup, not only logins: its fields, notes, files and
//! password history, and what the popup can do with items (favorite,
//! archive, move to the trash, save a file, edit in Keyless). Secret values
//! stay out of the view until the user asks to see one (`reveal`); copies are
//! made by the app (see the `copy` command).

use keyless_core::{
    item::{Field, FieldKind},
    totp::Totp,
};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::{api::now_secs, error::AppError, items, state::AppState, sync::EVENT_ITEMS_CHANGED};

fn not_found(err: AppError) -> &'static str {
    match err {
        AppError::Locked => "locked",
        _ => "not_found",
    }
}

/// What the popup shows of a field: its value unless it is secret (a
/// one-time password shows its current code instead).
fn field_view(session_items: &std::collections::HashMap<String, crate::state::CachedItem>, field: &Field, now: u64) -> Value {
    let secret = field.kind.is_secret();
    let mut view = json!({
        "id": field.id,
        "label": field.label,
        "kind": field.kind,
        "purpose": field.purpose,
        "secret": secret,
        "empty": field.value.trim().is_empty(),
    });
    if field.kind == FieldKind::Totp {
        if let Ok(totp) = Totp::parse(&field.value) {
            let period = totp.period.max(1);
            view["totp"] = json!({ "code": totp.code_at(now).as_str(), "period": period, "expiresIn": period - now % period });
        }
    } else if !secret {
        view["value"] = json!(field.value);
    }
    if let Some(address) = &field.extra.address {
        view["address"] = json!(address);
    }
    if !field.extra.geo.is_empty() {
        view["geo"] = json!(field.extra.geo);
    }
    // A related item, or the login a "sign in with" account uses.
    let linked = if field.kind == FieldKind::Reference { field.value.as_str() } else { field.extra.link.as_str() };
    if let Some(item) = session_items.get(linked).filter(|i| i.overview.trashed_at.is_none()) {
        view["link"] = json!({ "id": linked, "title": item.overview.title, "subtitle": item.overview.subtitle });
    }
    view
}

/// The item as the popup shows it.
pub async fn view(app: &AppHandle, id: &str) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let cached = session.items.get(id).ok_or("not_found")?;
    let o = &cached.overview;
    if o.trashed_at.is_some() {
        return Err("not_found");
    }
    let (local, details) = items::load_details(&state, session, id).map_err(not_found)?;
    let can_edit = session.vault(&local.vault_id).is_ok_and(|v| v.can_write());
    let now = now_secs().max(0) as u64;
    let mut sections = vec![json!({ "title": "", "fields": details.fields.iter().map(|f| field_view(&session.items, f, now)).collect::<Vec<_>>() })];
    for section in &details.sections {
        sections.push(json!({ "title": section.title, "fields": section.fields.iter().map(|f| field_view(&session.items, f, now)).collect::<Vec<_>>() }));
    }
    let vault = session.vaults.get(&cached.vault_id).map(|v| v.meta.name.clone()).unwrap_or_default();
    Ok(json!({
        "id": id,
        "title": o.title,
        "subtitle": o.subtitle,
        "category": o.category,
        "vault": vault,
        "vaultId": cached.vault_id,
        "favorite": o.favorite,
        "archived": o.archived,
        "canEdit": can_edit,
        "tags": o.tags,
        "urls": o.urls.iter().filter(|u| !u.href.trim().is_empty()).map(|u| json!({ "href": u.href, "label": u.label })).collect::<Vec<_>>(),
        "sections": sections,
        "notes": details.notes,
        "attachments": details.attachments.iter().map(|a| json!({ "id": a.id, "name": a.name, "size": a.size })).collect::<Vec<_>>(),
        "history": details.password_history.iter().enumerate().map(|(i, h)| json!({ "index": i, "changedAt": h.changed_at })).collect::<Vec<_>>(),
        "passkeys": details.passkeys.len(),
        "createdAt": o.created_at,
        "updatedAt": o.updated_at,
    }))
}

/// A secret value the user asked to see: field `field` (its id), or entry
/// `history` of the password history.
pub async fn secret(app: &AppHandle, id: &str, field: Option<&str>, history: Option<usize>) -> Result<Zeroizing<String>, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    if session.items.get(id).is_none_or(|i| i.overview.trashed_at.is_some()) {
        return Err("not_found");
    }
    let (_, details) = items::load_details(&state, session, id).map_err(not_found)?;
    match (field, history) {
        (Some(field), _) => {
            let field = details.all_fields().find(|f| f.id == field).ok_or("not_found")?;
            if field.kind == FieldKind::Totp {
                // The code, never the seed.
                let totp = Totp::parse(&field.value).map_err(|_| "not_found")?;
                return Ok(totp.code_at(now_secs().max(0) as u64));
            }
            if let Some(a) = field.extra.address.as_ref().filter(|_| field.value.trim().is_empty()) {
                // An address kept in parts: as it is written on an envelope.
                let town = [a.zip.as_str(), a.city.as_str()].iter().filter(|p| !p.is_empty()).copied().collect::<Vec<_>>().join(" ");
                let lines = [a.street.as_str(), a.line2.as_str(), town.as_str(), a.state.as_str(), a.country.as_str()];
                return Ok(Zeroizing::new(lines.iter().filter(|l| !l.is_empty()).copied().collect::<Vec<_>>().join("\n")));
            }
            Ok(Zeroizing::new(field.value.clone()))
        }
        (None, Some(index)) => details.password_history.get(index).map(|h| Zeroizing::new(h.value.clone())).ok_or("not_found"),
        _ => Err("bad_request"),
    }
}

/// Favorite, archive or move to the trash several items at once. Stops at
/// the first that cannot change (a vault the user may only read).
pub async fn change(app: &AppHandle, ids: &[String], action: &str, on: bool) -> Result<Value, &'static str> {
    let mut changed = 0;
    for id in ids {
        let result = match action {
            "favorite" => items::set_favorite(app, id, on).await,
            "archive" => items::set_archived(app, id, on).await,
            "trash" => items::trash_item(app, id).await,
            _ => return Err("bad_request"),
        };
        match result {
            Ok(()) => changed += 1,
            Err(AppError::Locked) => return Err("locked"),
            Err(AppError::Invalid(_)) => return Err("read_only"),
            Err(_) => return Err("not_found"),
        }
    }
    let _ = app.emit(EVENT_ITEMS_CHANGED, ());
    Ok(json!({ "changed": changed }))
}

/// Saves a file of the item where the user chooses, from the app's own save
/// dialog (`title` is its title, in the extension's language).
pub async fn save_attachment(app: &AppHandle, id: &str, attachment: &str, title: &str) -> Result<Value, &'static str> {
    let text = crate::dialog_text::DialogText { title: title.chars().take(120).collect(), filter: String::new() };
    match crate::attachments::save(app, id, attachment, &text).await {
        Ok(()) => Ok(Value::Null),
        Err(AppError::Locked) => Err("locked"),
        Err(_) => Err("not_found"),
    }
}
