//! Commands the browser extension can run (after pairing, over the
//! encrypted channel). Deliberately small: status, unlocking, finding logins
//! for a page and returning the credentials the user chose to fill.

use keyless_core::{
    item::{Category, FieldKind, FieldPurpose, ItemUrl, UrlMatch},
    totp::Totp,
};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{api::now_secs, error::AppError, state::AppState};

const MAX_RESULTS: usize = 50;
/// How long `wait_status` waits for Keyless to lock or unlock.
const WAIT_STATUS: std::time::Duration = std::time::Duration::from_secs(50);

pub async fn dispatch(app: &AppHandle, cmd: &str, args: &mut Value) -> Result<Value, &'static str> {
    match cmd {
        "status" => status(app).await,
        "wait_status" => {
            // Long poll: answers as soon as Keyless locks or unlocks (or after
            // a while), so the extension's icon follows the app.
            let known = args.get("locked").and_then(Value::as_bool);
            let mut changes = app.state::<AppState>().lock_state.subscribe();
            if known == Some(*changes.borrow_and_update()) {
                let _ = tokio::time::timeout(WAIT_STATUS, changes.changed()).await;
            }
            status(app).await
        }
        "unlock" => {
            // Keyless asks the user itself (system prompt or its own
            // window): the extension never sees the master password.
            crate::unlock_prompt::request(app, crate::unlock_prompt::Reason::Browser).await.map_err(|err| {
                log::info!("unlock for the browser extension: {err}");
                unlock_error(err)
            })?;
            Ok(Value::Null)
        }
        "show_app" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
            Ok(Value::Null)
        }
        "match" => {
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?;
            find(app, Query::Url(url)).await
        }
        "search" => {
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            find(app, Query::Text(query)).await
        }
        "sites" => {
            // Each host's registrable domain (Public Suffix List), so the
            // extension can tell whether two pages are the same site.
            let hosts = args.get("hosts").and_then(Value::as_array).ok_or("bad_request")?;
            if hosts.len() > 64 {
                return Err("bad_request");
            }
            Ok(hosts.iter().map(|host| Value::String(host.as_str().map(|h| site_of(&h.to_ascii_lowercase())).unwrap_or_default())).collect())
        }
        "vaults" => super::logins::vaults(app).await,
        "form_items" => super::forms::list(app).await,
        "form_details" => {
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            super::forms::details(app, &id).await
        }
        "check_login" => {
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let username = args.get("username").and_then(Value::as_str).unwrap_or("").to_string();
            let password = take_secret(args, "password")?;
            // The current password of a change-password form, if any.
            let current = take_secret(args, "current").unwrap_or_default();
            super::logins::check(app, &url, &username, &password, &current).await
        }
        "save_login" => {
            let password = take_secret(args, "password")?;
            let text = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or("").to_string();
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let vault = args.get("vaultId").and_then(Value::as_str).map(str::to_string);
            super::logins::save_new(app, &url, &text("title"), &text("username"), password, vault.as_deref()).await
        }
        "update_login" => {
            let password = take_secret(args, "password")?;
            let text = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or("").to_string();
            let (id, url) = (text("id"), text("url"));
            if id.is_empty() || url.is_empty() {
                return Err("bad_request");
            }
            super::logins::update(app, &id, &url, &text("username"), password).await
        }
        "suggest_password" => {
            let max_length = args.get("maxLength").and_then(Value::as_u64).filter(|&n| n > 0);
            let symbols = args.get("symbols").and_then(Value::as_bool).unwrap_or(true);
            super::logins::suggest(max_length, symbols)
        }
        // Passkeys, after the user chose in the extension's window.
        "passkey_check" => super::passkeys::check(args),
        "passkey_list" => super::passkeys::list(app, args).await,
        "passkey_create" => super::passkeys::create(app, args).await,
        "passkey_get" => super::passkeys::get(app, args).await,
        "remember_generated" => {
            // A suggested password was filled into a page: kept in the
            // generator history, with the page's site.
            let password = take_secret(args, "password")?;
            let site = args.get("url").and_then(Value::as_str).and_then(Page::parse).map(|page| page.host);
            let state = app.state::<AppState>();
            let guard = state.session.lock().await;
            let session = guard.as_ref().ok_or("locked")?;
            crate::generator_history::remember(&state, session, &password, site.as_deref()).map_err(|_| "error")?;
            Ok(json!(true))
        }
        "credentials" => {
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?;
            let url = args.get("url").and_then(Value::as_str);
            let any_site = args.get("anySite").and_then(Value::as_bool).unwrap_or(false);
            credentials(app, id, url, any_site).await
        }
        "copy" => {
            // Copied by the app: kept out of clipboard history and cleared
            // automatically, unlike a copy made by the browser.
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?;
            let field = args.get("field").and_then(Value::as_str).ok_or("bad_request")?;
            if !matches!(field, "username" | "password" | "totp") {
                return Err("bad_request");
            }
            let state = app.state::<AppState>();
            let value = crate::items::copy_value(&state, id, None, Some(field)).await.map_err(|err| match err {
                crate::error::AppError::Locked => "locked",
                _ => "not_found",
            })?;
            crate::commands::record_use(&state, id);
            let seconds = state.settings().clipboard_clear_seconds;
            let generation = state.clipboard.copy(value, true).map_err(|_| "clipboard")?;
            crate::clipboard::schedule_clear(app.clone(), generation, std::time::Duration::from_secs(seconds as u64));
            Ok(json!({ "clearAfterSeconds": seconds }))
        }
        _ => Err("unknown_command"),
    }
}

async fn status(app: &AppHandle) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    Ok(match guard.as_ref() {
        Some(session) => json!({ "locked": false, "email": session.email }),
        None => json!({ "locked": true }),
    })
}

/// Takes a secret out of the request, so it is wiped after use.
fn take_secret(args: &mut Value, key: &str) -> Result<Zeroizing<String>, &'static str> {
    match args.get_mut(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Zeroizing::new(std::mem::take(value))),
        _ => Err("bad_request"),
    }
}

fn unlock_error(err: AppError) -> &'static str {
    match err {
        AppError::Cancelled => "cancelled",
        AppError::NoAccount => "no_account",
        AppError::Invalid(msg) if msg.key == "busy" => "busy",
        _ => "error",
    }
}

/// Host part of a URL, accepting bare domains.
pub fn url_host(url: &str) -> Option<String> {
    url_parts(url).map(|(host, _)| host)
}

/// Host and port (when not the scheme's default) of a URL, accepting bare
/// domains.
fn url_parts(url: &str) -> Option<(String, Option<u16>)> {
    let url = url.trim();
    let normalized = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    let parsed = url::Url::parse(&normalized).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_start_matches("www.").to_ascii_lowercase();
    Some((host, parsed.port()))
}

/// Registrable domain ("eTLD+1"), e.g. accounts.google.com -> google.com.
/// Addresses by number (192.168.1.1, [::1]) are whole hosts.
pub fn site_of(host: &str) -> String {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    psl::domain_str(host).map(str::to_string).unwrap_or_else(|| host.to_string())
}

/// Hosts where anyone can publish pages under a big site's domain: logins
/// for the rest of that site are not offered there (nor theirs elsewhere).
const USER_CONTENT_HOSTS: &[&str] = &["script.google.com"];

/// The page a request comes from, as reported by the browser.
pub struct Page {
    host: String,
    port: Option<u16>,
    secure: bool,
}

impl Page {
    pub fn parse(url: &str) -> Option<Page> {
        let parsed = url::Url::parse(url.trim()).ok()?;
        let secure = match parsed.scheme() {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let host = parsed.host_str()?.trim_start_matches("www.").to_ascii_lowercase();
        Some(Page { host, port: parsed.port(), secure })
    }
}

fn is_https(url: &str) -> bool {
    url.trim().get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://"))
}

/// 2 = same host, 1 = same site, 0 = no match. A login saved for an https
/// address is never offered to a plain http page, where anyone on the network
/// could read it. The address's fill rule narrows this: only its exact host
/// (and port, when it has one), or nowhere.
pub fn match_score(page: &Page, item_url: &ItemUrl) -> u8 {
    if item_url.fill == UrlMatch::Never {
        return 0;
    }
    let Some((item_host, item_port)) = url_parts(&item_url.href) else { return 0 };
    let exact = item_url.fill == UrlMatch::Host;
    if is_https(&item_url.href) && !page.secure {
        0
    } else if item_host == page.host {
        if exact && item_port.is_some() && item_port != page.port { 0 } else { 2 }
    } else if exact || USER_CONTENT_HOSTS.contains(&page.host.as_str()) || USER_CONTENT_HOSTS.contains(&item_host.as_str()) {
        0
    } else if site_of(&item_host) == site_of(&page.host) {
        1
    } else {
        0
    }
}

enum Query<'a> {
    Url(&'a str),
    Text(&'a str),
}

fn is_fillable(category: Category) -> bool {
    matches!(
        category,
        Category::Login | Category::Password | Category::EmailAccount | Category::Server | Category::Database | Category::ApiCredential
    )
}

async fn find(app: &AppHandle, query: Query<'_>) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;

    let page = match &query {
        Query::Url(url) => Some(Page::parse(url).ok_or("bad_request")?),
        Query::Text(_) => None,
    };
    let needle = match &query {
        Query::Text(text) => text.trim().to_lowercase(),
        Query::Url(_) => String::new(),
    };

    // Logins used most recently come first, like the last one used here.
    let usage = state.store().item_usage().unwrap_or_default();
    let mut results: Vec<(u8, i64, Value)> = Vec::new();
    for (id, item) in &session.items {
        let o = &item.overview;
        if o.trashed_at.is_some() || o.archived || !is_fillable(o.category) {
            continue;
        }
        let score = match &page {
            Some(page) => o.urls.iter().map(|u| match_score(page, u)).max().unwrap_or(0),
            None => {
                let hit = needle.is_empty()
                    || o.title.to_lowercase().contains(&needle)
                    || o.subtitle.to_lowercase().contains(&needle)
                    || o.urls.iter().any(|u| u.href.to_lowercase().contains(&needle));
                u8::from(hit)
            }
        };
        if score == 0 {
            continue;
        }
        let vault = session.vaults.get(&item.vault_id).map(|v| v.meta.name.clone()).unwrap_or_default();
        results.push((
            score,
            usage.get(id).map(|&(_, last_used)| last_used).unwrap_or(0),
            json!({
                "id": id,
                "title": o.title,
                "username": o.subtitle,
                "url": o.urls.first().map(|u| u.href.clone()).unwrap_or_default(),
                "vault": vault,
                "favorite": o.favorite,
            }),
        ));
    }
    results.sort_by(|a, b| {
        b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then_with(|| {
            a.2["title"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&b.2["title"].as_str().unwrap_or("").to_lowercase())
        })
    });
    let mut logins: Vec<Value> = results.into_iter().take(MAX_RESULTS).map(|(_, _, v)| v).collect();
    // Which have a one-time code (for the code's own fill and shortcut).
    for login in &mut logins {
        let id = login["id"].as_str().unwrap_or_default().to_string();
        let totp = crate::items::load_details(&state, session, &id)
            .is_ok_and(|(_, details)| details.all_fields().any(|f| f.kind == FieldKind::Totp && !f.value.trim().is_empty()));
        login["totp"] = json!(totp);
    }
    // Website icons the app has (see `site_icons`).
    let sites: Vec<String> = logins.iter().filter_map(|l| l["url"].as_str().filter(|u| !u.is_empty()).map(str::to_string)).collect();
    let icons = crate::site_icons::lookup(&state, session, &sites);
    for login in &mut logins {
        if let Some(icon) = login["url"].as_str().and_then(|url| icons.get(url)) {
            login["icon"] = json!(icon);
        }
    }
    Ok(Value::Array(logins))
}

/// `any_site` is set when the user explicitly confirmed, in the extension's
/// own UI, filling a login saved for another site. A login saved for an https
/// address still never goes to a plain http page.
async fn credentials(app: &AppHandle, id: &str, url: Option<&str>, any_site: bool) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let cached = session.items.get(id).ok_or("not_found")?;

    // Requests that come from a page must match that page's site.
    if let Some(url) = url {
        let page = Page::parse(url).ok_or("bad_request")?;
        if !cached.overview.urls.iter().any(|u| match_score(&page, u) > 0) {
            if !any_site {
                return Err("url_mismatch");
            }
            if !page.secure && cached.overview.urls.iter().any(|u| is_https(&u.href)) {
                return Err("insecure_page");
            }
        }
    }

    let local = state.store().item(id).map_err(|_| "internal")?.ok_or("not_found")?;
    let enc = local.enc_details.as_deref().ok_or("not_found")?;
    let vault = session.vault(&local.vault_id).map_err(|_| "not_found")?;
    let details = vault.key.open_details(&local.vault_id, id, enc).map_err(|_| "internal")?;

    let totp = details
        .all_fields()
        .find(|f| f.kind == FieldKind::Totp && !f.value.is_empty())
        .and_then(|f| Totp::parse(&f.value).ok())
        .map(|t| t.code_at(now_secs().max(0) as u64).to_string());

    crate::commands::record_use(&state, id);
    Ok(json!({
        "username": details.field_by_purpose(FieldPurpose::Username).map(|f| f.value.clone()).unwrap_or_default(),
        "password": details.field_by_purpose(FieldPurpose::Password).map(|f| f.value.clone()).unwrap_or_default(),
        "totp": totp,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> Page {
        Page::parse(url).unwrap()
    }

    fn url(href: &str) -> ItemUrl {
        ItemUrl { href: href.into(), ..Default::default() }
    }

    #[test]
    fn url_matching() {
        assert_eq!(url_host("https://www.GitHub.com/login"), Some("github.com".into()));
        assert_eq!(url_host("github.com"), Some("github.com".into()));
        assert_eq!(url_host("javascript:alert(1)"), None);
        assert_eq!(url_host("file:///etc/passwd"), None);
        assert!(Page::parse("javascript:alert(1)").is_none());
        assert!(Page::parse("github.com").is_none());

        assert_eq!(match_score(&page("https://github.com/login"), &url("https://github.com")), 2);
        assert_eq!(match_score(&page("https://gist.github.com"), &url("https://github.com")), 1);
        assert_eq!(match_score(&page("https://accounts.google.com"), &url("google.com")), 1);
        assert_eq!(match_score(&page("https://evilgithub.com"), &url("https://github.com")), 0);
        assert_eq!(match_score(&page("https://github.com.evil.io"), &url("https://github.com")), 0);
        // Different sites under a public suffix must not match.
        assert_eq!(match_score(&page("https://alice.github.io"), &url("https://bob.github.io")), 0);
        assert_eq!(match_score(&page("https://foo.co.uk"), &url("https://bar.co.uk")), 0);
        // The sites the extension compares pages by.
        assert_eq!(site_of("accounts.google.com"), "google.com");
        assert_eq!(site_of("alice.github.io"), "alice.github.io");
        assert_ne!(site_of("victim.vercel.app"), site_of("attacker.vercel.app"));
        assert_eq!(site_of("[::1]"), "[::1]");
        // Addresses by number are whole hosts, not domains.
        assert_eq!(match_score(&page("http://192.168.1.1"), &url("http://10.0.1.1")), 0);
        assert_eq!(match_score(&page("http://192.168.1.1/admin"), &url("http://192.168.1.1")), 2);
        assert_eq!(match_score(&page("http://[::1]:8080"), &url("http://[fe80::1]")), 0);
        // Pages anyone can publish under a big site's domain.
        assert_eq!(match_score(&page("https://script.google.com/macros/s/x"), &url("https://accounts.google.com")), 0);
        assert_eq!(match_score(&page("https://script.google.com"), &url("https://script.google.com")), 2);
    }

    #[test]
    fn https_logins_stay_off_http_pages() {
        assert_eq!(match_score(&page("http://github.com"), &url("https://github.com")), 0);
        assert_eq!(match_score(&page("http://github.com"), &url("HTTPS://github.com")), 0);
        // Upgrading is fine, and so are addresses saved without a scheme or
        // for plain http (routers, local services).
        assert_eq!(match_score(&page("https://github.com"), &url("http://github.com")), 2);
        assert_eq!(match_score(&page("http://router.lan"), &url("router.lan")), 2);
        assert_eq!(match_score(&page("http://localhost:8765/login"), &url("http://localhost:8765")), 2);
    }

    #[test]
    fn fill_rules() {
        let host = |href: &str| ItemUrl { href: href.into(), fill: UrlMatch::Host, ..Default::default() };
        let never = |href: &str| ItemUrl { href: href.into(), fill: UrlMatch::Never, ..Default::default() };
        // Only this host: not the rest of the site.
        assert_eq!(match_score(&page("https://accounts.google.com"), &host("https://accounts.google.com")), 2);
        assert_eq!(match_score(&page("https://mail.google.com"), &host("https://accounts.google.com")), 0);
        // With a port, only that port; without one, any.
        assert_eq!(match_score(&page("http://localhost:3000"), &host("http://localhost:8765")), 0);
        assert_eq!(match_score(&page("http://localhost:8765/x"), &host("http://localhost:8765")), 2);
        assert_eq!(match_score(&page("https://nas.lan:5001"), &host("nas.lan")), 2);
        assert_eq!(match_score(&page("https://github.com"), &never("https://github.com")), 0);
        // Saved without a rule: anywhere on the site, as before.
        let saved: ItemUrl = serde_json::from_str(r#"{"href":"https://github.com"}"#).unwrap();
        assert_eq!(saved.fill, UrlMatch::Domain);
        assert_eq!(serde_json::to_string(&saved).unwrap(), r#"{"href":"https://github.com"}"#);
    }
}
