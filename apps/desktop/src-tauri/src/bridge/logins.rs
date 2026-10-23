//! Saving logins from the browser (the "Save login?" prompt) and suggesting
//! passwords for sign-up and change-password forms.
//!
//! The extension only calls these from its own pages (the prompt and the
//! menus, never a web page), after the user chose to save. The app checks
//! the vault can be written and keeps the old password in the item's
//! history when updating.

use keyless_core::{
    generator::{GeneratorOptions, generate},
    password_rules,
    item::{Category, Field, FieldExtra, FieldKind, FieldPurpose, ItemUrl, new_field_id},
};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use super::handlers::{Page, match_score, site_of};
use crate::{
    error::AppResult,
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
            json!({ "id": id, "title": o.title, "username": saved_user, "vault": vault, "vaultId": item.vault_id, "sameUser": same_user, "current": is_current }),
        ));
    }
    candidates.sort_by_key(|((is_current, same_user), _)| (!is_current, !same_user));
    Ok(json!({
        "state": state_name,
        "candidates": candidates.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
        "title": suggested_title(&page_host(url)),
    }))
}

pub(crate) fn page_host(url: &str) -> String {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default()
}

/// Names written their own way.
const BRANDS: &[(&str, &str)] = &[
    ("icloud", "iCloud"),
    ("github", "GitHub"),
    ("gitlab", "GitLab"),
    ("youtube", "YouTube"),
    ("linkedin", "LinkedIn"),
    ("paypal", "PayPal"),
    ("whatsapp", "WhatsApp"),
    ("tiktok", "TikTok"),
    ("ifood", "iFood"),
    ("openai", "OpenAI"),
    ("chatgpt", "ChatGPT"),
    ("playstation", "PlayStation"),
    ("digitalocean", "DigitalOcean"),
    ("ebay", "eBay"),
    ("mercadolivre", "Mercado Livre"),
    ("mercadopago", "Mercado Pago"),
    ("mercadolibre", "Mercado Libre"),
    ("itau", "Itaú"),
];

/// "accounts.google.com" -> "Google".
pub(crate) fn suggested_title(host: &str) -> String {
    let site = site_of(host.trim_start_matches("www."));
    let name = site.split('.').next().unwrap_or(&site);
    if let Some((_, brand)) = BRANDS.iter().find(|(key, _)| *key == name) {
        return brand.to_string();
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => host.to_string(),
    }
}

/// The page's address without path, query or fragment.
pub(crate) fn origin(url: &str) -> Result<String, &'static str> {
    let parsed = url::Url::parse(url).map_err(|_| "bad_request")?;
    Ok(parsed.origin().ascii_serialization())
}

fn login_field(purpose: FieldPurpose, value: &str) -> Field {
    let (label, kind) = match purpose {
        FieldPurpose::Password => ("password", FieldKind::Concealed),
        _ => ("username", FieldKind::Text),
    };
    Field { id: new_field_id(), label: label.into(), kind, value: value.into(), purpose: Some(purpose), extra: Default::default() }
}

/// The vault a new item from the browser goes into: the one chosen, or the
/// first the user can write to.
pub(crate) async fn target_vault(app: &AppHandle, vault_id: Option<&str>) -> Result<String, &'static str> {
    match vault_id {
        Some(id) => Ok(id.to_string()),
        None => {
            let vaults = vaults(app).await?;
            Ok(vaults.as_array().and_then(|list| list.first()).and_then(|v| v["id"].as_str()).ok_or("no_vault")?.to_string())
        }
    }
}

/// Providers a login can sign in through (the desktop's list).
const PROVIDERS: [&str; 12] = ["google", "apple", "microsoft", "github", "facebook", "x", "amazon", "discord", "slack", "linkedin", "gitlab", "okta"];

/// Saves a login for the page that signs in through `provider`, unless the
/// page has one already. `account`: the provider's login the user signed
/// in with, when the extension knows it.
pub async fn save_sign_in_with(
    app: &AppHandle,
    url: &str,
    provider: &str,
    title: &str,
    account: Option<&str>,
    vault_id: Option<&str>,
) -> Result<Value, &'static str> {
    if !PROVIDERS.contains(&provider) {
        return Err("bad_request");
    }
    let page = Page::parse(url).ok_or("bad_request")?;
    let link = {
        let state = app.state::<AppState>();
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or("locked")?;
        // Only a login the user has (not in the trash).
        let link = account
            .and_then(|id| session.items.get(id).filter(|i| i.overview.category == Category::Login && i.overview.trashed_at.is_none()).map(|_| id.to_string()))
            .unwrap_or_default();
        for (id, item) in &session.items {
            if item.overview.trashed_at.is_some() || !item.overview.urls.iter().any(|u| match_score(&page, u) > 0) {
                continue;
            }
            let Ok((_, details)) = items::load_details(&state, session, id) else { continue };
            if details.all_fields().any(|f| f.kind == FieldKind::SignInWith && f.value == provider) {
                return Ok(json!({ "id": id, "existed": true }));
            }
        }
        link
    };
    let vault_id = target_vault(app, vault_id).await?;
    let draft = ItemDraft {
        vault_id,
        title: match title.trim() {
            "" => suggested_title(&page_host(url)),
            title => title.to_string(),
        },
        category: Category::Login,
        urls: vec![ItemUrl { href: origin(url)?, ..Default::default() }],
        fields: vec![Field {
            id: new_field_id(),
            label: "sign in with".into(),
            kind: FieldKind::SignInWith,
            value: provider.to_string(),
            purpose: None,
            extra: FieldExtra { link, ..Default::default() },
        }],
        ..Default::default()
    };
    let summary = items::save_item(app, draft).await.map_err(|_| "error")?;
    Ok(json!({ "id": summary.id }))
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
    let vault_id = target_vault(app, vault_id).await?;
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
        icon: String::new(),
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

/// The account setting with the user's defaults for suggested passwords.
const SUGGESTION: &str = "suggestion";

/// What a suggested password is made of until the user picks otherwise.
pub fn standard_suggestion() -> GeneratorOptions {
    GeneratorOptions::Random { length: SUGGESTED_LENGTH, uppercase: true, lowercase: true, digits: true, symbols: true, avoid_ambiguous: true }
}

/// The defaults the user chose for suggested passwords, if any (a setting
/// that follows the account).
pub fn suggestion_default(state: &AppState) -> Option<GeneratorOptions> {
    serde_json::from_value(crate::account_settings::get(state, SUGGESTION)?).ok()
}

/// Makes `options` the defaults for suggested passwords (None: back to the
/// standard ones).
pub async fn set_suggestion_default(app: &AppHandle, options: Option<GeneratorOptions>) -> AppResult<()> {
    if let Some(options) = &options {
        generate(options)?;
    }
    crate::account_settings::set(app, SUGGESTION, options.map(|options| json!(options))).await
}

/// A password for a sign-up or change-password form, made as `options` say
/// when the form and the site take that: within the field's maximum length,
/// and following the website's password rules, those the page states (its
/// `passwordrules` attribute) or the known ones for its site (see
/// `keyless_core::password_rules`). Otherwise the closest one they take,
/// with why in `adjusted` ("length" or "rules").
pub fn suggest(options: &GeneratorOptions, max_length: Option<u64>, page_rules: &str, url: &str) -> Result<Value, &'static str> {
    generate(options).map_err(|_| "bad_request")?;
    let max = max_length.map(|max| max as usize);
    let rules = password_rules::parse(page_rules).or_else(|| password_rules::rules_for(&page_host(url))).map(|mut rules| {
        // The field itself may allow less than the site says.
        if let Some(max) = max {
            rules.max_length = Some(rules.max_length.map_or(max, |m| m.min(max)));
        }
        rules
    });
    let made = |password: Zeroizing<String>, adjusted: Option<&str>| json!({ "password": password.as_str(), "options": options, "adjusted": adjusted });

    // A random password or PIN longer than the field takes: as long as it does.
    let mut asked = options.clone();
    let mut adjusted = None;
    if let (Some(max), GeneratorOptions::Random { length, .. } | GeneratorOptions::Pin { length }) = (max, &mut asked)
        && *length > max
    {
        *length = max;
        adjusted = Some("length");
    }
    let fits = |password: &str| max.is_none_or(|max| password.chars().count() <= max) && rules.as_ref().is_none_or(|rules| password_rules::follows(rules, password));
    for _ in 0..20 {
        if let Ok(generated) = generate(&asked)
            && fits(&generated.password)
        {
            return Ok(made(generated.password, adjusted));
        }
    }

    // Not what the site takes: what it does, as close as can be.
    let (length, symbols) = match options {
        GeneratorOptions::Random { length, symbols, .. } => (*length, *symbols),
        _ => (SUGGESTED_LENGTH, true),
    };
    if let Some(rules) = &rules
        && let Ok(generated) = password_rules::generate(rules, length, symbols)
    {
        return Ok(made(generated.password, Some("rules")));
    }
    let length = max.map_or(length, |max| length.min(max)).max(8);
    let generated = generate(&GeneratorOptions::Random { length, uppercase: true, lowercase: true, digits: true, symbols, avoid_ambiguous: true }).map_err(|_| "error")?;
    Ok(made(generated.password, Some("length")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_and_origins() {
        assert_eq!(suggested_title("accounts.google.com"), "Google");
        assert_eq!(suggested_title("www.instagram.com"), "Instagram");
        assert_eq!(suggested_title("nubank.com.br"), "Nubank");
        assert_eq!(suggested_title("www.icloud.com"), "iCloud");
        assert_eq!(suggested_title("mercadolivre.com.br"), "Mercado Livre");
        assert_eq!(origin("https://www.instagram.com/accounts/login/?next=%2F#x").unwrap(), "https://www.instagram.com");
    }

    #[test]
    fn suggestions_follow_the_site() {
        let password = |rules: &str, url: &str, max| suggest(&standard_suggestion(), max, rules, url).unwrap()["password"].as_str().unwrap().to_string();
        // The page's own rules.
        let digits = password("minlength: 6; maxlength: 6; allowed: digit;", "https://bank.example", None);
        assert!(digits.len() == 6 && digits.chars().all(|c| c.is_ascii_digit()));
        // Known rules for the site (Apple: at most 32 characters, no more
        // than 3 alike in a row).
        let apple = password("", "https://appleid.apple.com/account", None);
        assert!(apple.len() <= 32 && !apple.is_empty());
        // The field's limit wins over a longer one.
        assert_eq!(password("maxlength: 30;", "https://x.example", Some(10)).len(), 10);
    }

    #[test]
    fn suggestions_follow_the_form() {
        let random = |symbols| GeneratorOptions::Random { length: SUGGESTED_LENGTH, uppercase: true, lowercase: true, digits: true, symbols, avoid_ambiguous: true };
        let password = |max, symbols| suggest(&random(symbols), max, "", "").unwrap()["password"].as_str().unwrap().to_string();
        assert_eq!(password(None, true).len(), SUGGESTED_LENGTH);
        assert_eq!(password(Some(12), true).len(), 12);
        assert!(password(None, false).chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn suggestions_follow_the_options() {
        let made = |options: &GeneratorOptions, max, rules: &str| suggest(options, max, rules, "https://x.example").unwrap();
        let text = |reply: &Value| reply["password"].as_str().unwrap().to_string();
        // As asked, when the site takes it.
        let memorable = GeneratorOptions::Memorable { words: 4, separator: "-".into(), capitalize: false, include_number: false, style: Default::default(), separators: Default::default() };
        let reply = made(&memorable, None, "");
        assert_eq!(text(&reply).split('-').count(), 4);
        assert!(reply["adjusted"].is_null());
        assert_eq!(reply["options"]["kind"], "memorable");
        let pin = GeneratorOptions::Pin { length: 6 };
        assert!(text(&made(&pin, None, "")).chars().all(|c| c.is_ascii_digit()));
        // Shorter, for a field that takes fewer characters.
        let long = GeneratorOptions::Random { length: 40, uppercase: true, lowercase: true, digits: true, symbols: false, avoid_ambiguous: true };
        let reply = made(&long, Some(16), "");
        assert_eq!(text(&reply).len(), 16);
        assert_eq!(reply["adjusted"], "length");
        // The site's rules, when the options do not meet them.
        let reply = made(&pin, None, "required: upper; required: lower; minlength: 10;");
        assert!(text(&reply).len() >= 10 && text(&reply).chars().any(|c| c.is_ascii_uppercase()));
        assert_eq!(reply["adjusted"], "rules");
        // Options that make no password are refused.
        assert_eq!(suggest(&GeneratorOptions::Pin { length: 2 }, None, "", ""), Err("bad_request"));
    }
}
