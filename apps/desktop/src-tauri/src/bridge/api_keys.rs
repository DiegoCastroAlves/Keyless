//! API keys the user copies on a page (a service's dashboard, mostly):
//! recognized by their format (see `secret_patterns`), and offered to be
//! saved as an API credential for the site.

use keyless_core::item::{Category, Field, FieldKind, FieldPurpose, new_field_id};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};

use super::logins::{origin, page_host, suggested_title, target_vault};
use crate::{
    items::{self, ItemDraft},
    secret_patterns,
    state::AppState,
};

/// Kinds not offered: a private key is not copied as one word, and
/// passwords inside addresses or tokens of any service are not API keys.
const SKIPPED: [&str; 4] = ["private_key", "url_password", "database_password", "jwt"];

/// The secret `text` is, when it is one secret of a known format and
/// nothing else.
fn recognize(text: &str) -> Option<secret_patterns::Found<'_>> {
    let text = text.trim();
    if text.len() > 600 || secret_patterns::placeholder(text) {
        return None;
    }
    let mut found = secret_patterns::find(text);
    let secret = found.pop().filter(|_| found.is_empty())?;
    (secret.value == text && !SKIPPED.contains(&secret.kind)).then_some(secret)
}

/// Whether an item (not in the trash) has the secret already.
async fn saved(app: &AppHandle, secret: &str) -> bool {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let Some(session) = guard.as_ref() else { return false };
    session.items.iter().filter(|(_, item)| item.overview.trashed_at.is_none()).any(|(id, _)| {
        items::load_details(&state, session, id).is_ok_and(|(_, details)| details.all_fields().any(|f| f.value.trim() == secret))
    })
}

/// What the copied text is: its service and kind, or null for anything
/// else. `exists`: Keyless has it already (only known when unlocked).
pub async fn check(app: &AppHandle, text: &str) -> Value {
    let Some(secret) = recognize(text) else { return Value::Null };
    let exists = saved(app, secret.value).await;
    json!({ "format": secret.id, "service": secret.service, "kind": secret.kind, "exists": exists })
}

/// Saves the copied secret as an API credential, noting the page's site.
/// `label`: what the extension calls it ("Stripe key"), kept as its type.
pub async fn save(app: &AppHandle, url: &str, text: &str, title: &str, label: &str, vault_id: Option<&str>) -> Result<Value, &'static str> {
    let secret = recognize(text).ok_or("bad_request")?;
    if saved(app, secret.value).await {
        return Ok(json!({ "existed": true }));
    }
    let vault_id = target_vault(app, vault_id).await?;
    let title = match title.trim() {
        "" if !secret.service.is_empty() => format!("{} ({})", secret.service, page_host(url)),
        "" => suggested_title(&page_host(url)),
        title => title.to_string(),
    };
    let field = |label: &str, kind: FieldKind, value: &str, purpose: Option<FieldPurpose>| Field {
        id: new_field_id(),
        label: label.into(),
        kind,
        value: value.into(),
        purpose,
        extra: Default::default(),
    };
    let mut fields = vec![field("credential", FieldKind::Concealed, secret.value, Some(FieldPurpose::Password))];
    if !label.trim().is_empty() {
        fields.push(field("type", FieldKind::Text, label.trim(), None));
    }
    // Where it came from, but not a website to fill it in: the site's sign-in
    // menus would offer the key as a login.
    fields.push(field("website", FieldKind::Url, &origin(url)?, None));
    let draft = ItemDraft { vault_id, title, category: Category::ApiCredential, fields, ..Default::default() };
    let summary = items::save_item(app, draft).await.map_err(|_| "error")?;
    Ok(json!({ "id": summary.id }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Put together at run time, so the source never holds something that
    /// looks like a real secret.
    fn token(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn recognizes_one_secret_alone() {
        let github = token(&["ghp_", &"a1B2".repeat(9)]);
        assert_eq!(recognize(&format!("  {github}\n")).map(|s| s.id), Some("github_token"));
        // Not alone, or not a secret.
        assert!(recognize(&format!("token: {github}")).is_none());
        assert!(recognize("correct-horse-battery-staple").is_none());
        assert!(recognize(&token(&["ghp_", "your_token_here_xxxxxxxxxxxxxxxxxxxxxxxx"])).is_none());
    }
}
