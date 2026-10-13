//! Commands the browser extension can run (after pairing, over the
//! encrypted channel). Deliberately small: status, unlocking, finding logins
//! for a page and returning the credentials the user chose to fill.

use keyless_core::{
    generator::{GeneratorOptions, generate},
    item::{Category, FieldKind, FieldPurpose, ItemUrl, UrlMatch},
    totp::Totp,
};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::{api::now_secs, error::AppError, state::AppState};

const MAX_RESULTS: usize = 50;
/// The most a list in the popup asks for at once.
const MAX_LIST: usize = 1000;
/// Sent to the main window to start a new item (from the popup).
pub const EVENT_NEW_ITEM: &str = "keyless://new-item";
/// How long `wait_status` waits for Keyless to lock or unlock.
const WAIT_STATUS: std::time::Duration = std::time::Duration::from_secs(50);

/// The vaults this browser may use, chosen in its extension (`vaults` in
/// each request); none chosen means all of them.
struct Scope(Option<std::collections::HashSet<String>>);

impl Scope {
    fn of(args: &Value) -> Scope {
        let ids: std::collections::HashSet<String> =
            args.get("vaults").and_then(Value::as_array).map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        Scope((!ids.is_empty()).then_some(ids))
    }

    fn allows(&self, vault_id: &str) -> bool {
        self.0.as_ref().is_none_or(|ids| ids.contains(vault_id))
    }

    /// The vault of item `id`, if this browser may use it.
    async fn allows_item(&self, app: &AppHandle, id: &str) -> bool {
        if self.0.is_none() {
            return true;
        }
        let state = app.state::<AppState>();
        let guard = state.session.lock().await;
        guard.as_ref().and_then(|s| s.items.get(id)).is_some_and(|item| self.allows(&item.vault_id))
    }

    /// Keeps the entries (objects with `vaultId`, or `itemId`) this browser
    /// may use.
    async fn filter(&self, app: &AppHandle, list: &mut Vec<Value>) {
        if self.0.is_none() {
            return;
        }
        let mut kept = Vec::with_capacity(list.len());
        for entry in list.drain(..) {
            let allowed = match (entry.get("vaultId").and_then(Value::as_str), entry.get("itemId").and_then(Value::as_str)) {
                (Some(vault), _) => self.allows(vault),
                (None, Some(item)) => self.allows_item(app, item).await,
                _ => true,
            };
            if allowed {
                kept.push(entry);
            }
        }
        *list = kept;
    }
}

/// Handles a request from the browser extension, within the vaults this
/// browser may use.
pub async fn dispatch(app: &AppHandle, cmd: &str, args: &mut Value) -> Result<Value, &'static str> {
    let scope = Scope::of(args);
    const BY_ID: [&str; 7] = ["item_details", "credentials", "add_site", "copy", "form_details", "update_login", "set_totp"];
    if BY_ID.contains(&cmd) {
        let id = args.get("id").and_then(Value::as_str).unwrap_or("");
        if !scope.allows_item(app, id).await {
            return Err("not_found");
        }
    }
    let mut result = dispatch_all(app, cmd, args).await?;
    match cmd {
        "match" | "search" | "passkey_list" | "vaults" | "ssh_public_keys" => {
            if let Value::Array(list) = &mut result {
                if cmd == "vaults" {
                    list.retain(|v| v.get("id").and_then(Value::as_str).is_some_and(|id| scope.allows(id)));
                } else {
                    scope.filter(app, list).await;
                }
            }
        }
        "form_items" => {
            for key in ["cards", "identities"] {
                if let Some(Value::Array(list)) = result.get_mut(key) {
                    scope.filter(app, list).await;
                }
            }
        }
        "check_login" | "password_owner" => {
            let key = if cmd == "check_login" { "candidates" } else { "logins" };
            if let Some(Value::Array(list)) = result.get_mut(key) {
                scope.filter(app, list).await;
            }
        }
        _ => {}
    }
    Ok(result)
}

async fn dispatch_all(app: &AppHandle, cmd: &str, args: &mut Value) -> Result<Value, &'static str> {
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
            // With an item: shows it in the main window.
            match args.get("id").and_then(Value::as_str) {
                Some(id) => crate::quick_access::show_item(app, id),
                None => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.unminimize();
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
            Ok(Value::Null)
        }
        "new_item" => {
            // The popup's "+": the editor opens in the main window (the
            // extension never writes items itself), with the tab's address
            // for a login.
            let category: Category = args.get("category").cloned().and_then(|c| serde_json::from_value(c).ok()).ok_or("bad_request")?;
            // The site's address, like "Save login?" keeps (no path).
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .filter(|u| Page::parse(u).is_some())
                .and_then(|u| super::logins::origin(u).ok())
                .unwrap_or_default();
            let url = url.as_str();
            let host = super::logins::page_host(url);
            let title = if host.is_empty() { String::new() } else { super::logins::suggested_title(&host) };
            crate::tray::show_main(app);
            let _ = app.emit_to("main", EVENT_NEW_ITEM, json!({ "category": category, "url": url, "title": title }));
            Ok(Value::Null)
        }
        "lock" => {
            crate::auth::lock(app).await;
            Ok(Value::Null)
        }
        "item_details" => {
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?;
            let reveal = args.get("reveal").and_then(Value::as_bool).unwrap_or(false);
            item_details(app, id, reveal).await
        }
        "generate" => {
            // The popup's password generator (no site rules: it is not
            // filling a field).
            let options: GeneratorOptions = args.get("options").cloned().and_then(|o| serde_json::from_value(o).ok()).ok_or("bad_request")?;
            let generated = generate(&options).map_err(|_| "bad_request")?;
            Ok(json!({ "password": generated.password.as_str(), "entropyBits": generated.entropy_bits }))
        }
        "copy_generated" => {
            // A password from the popup's generator: copied by the app (kept
            // out of clipboard history, cleared after a while) and kept in
            // the generator history.
            let password = take_secret(args, "password")?;
            let site = args.get("url").and_then(Value::as_str).and_then(Page::parse).map(|page| page.host);
            let state = app.state::<AppState>();
            {
                let guard = state.session.lock().await;
                let session = guard.as_ref().ok_or("locked")?;
                crate::generator_history::remember(&state, session, &password, site.as_deref()).map_err(|_| "error")?;
            }
            let seconds = state.settings().clipboard_clear_seconds;
            let generation = state.clipboard.copy(password, true).map_err(|_| "clipboard")?;
            crate::clipboard::schedule_clear(app.clone(), generation, std::time::Duration::from_secs(seconds as u64));
            Ok(json!({ "clearAfterSeconds": seconds }))
        }
        "match" => {
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?;
            find(app, Query::Url(url), false, MAX_RESULTS).await
        }
        "search" => {
            // An empty query lists logins, most recently used first:
            // `favorites` keeps only favorites, `limit` asks for more than
            // the default (the popup's lists).
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            let favorites = args.get("favorites").and_then(Value::as_bool).unwrap_or(false);
            let limit = args.get("limit").and_then(Value::as_u64).map_or(MAX_RESULTS, |n| (n as usize).clamp(1, MAX_LIST));
            find(app, Query::Text(query), favorites, limit).await
        }
        "site_alerts" => {
            // The serious Sentinel alerts of this website's logins, for the
            // warning on the page.
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?;
            let site = url_host(url).map(|h| site_of(&h)).ok_or("bad_request")?;
            let alerts = crate::health::site_alerts(app, &site).await.map_err(|err| match err {
                AppError::Locked => "locked",
                _ => "error",
            })?;
            serde_json::to_value(alerts).map_err(|_| "error")
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
        "same_owner" => {
            // Whether two pages are of one service (the same site, or sites
            // that share one account), for frames of one inside the other.
            let site = |key: &str| args.get(key).and_then(Value::as_str).and_then(|u| url::Url::parse(u).ok()).and_then(|u| u.host_str().map(|h| site_of(&h.to_ascii_lowercase()))).unwrap_or_default();
            Ok(Value::Bool(super::shared_sites::same_owner(&site("a"), &site("b"))))
        }
        "vaults" => super::logins::vaults(app).await,
        "all_vaults" => {
            // Every vault, for choosing the ones this browser uses.
            let state = app.state::<AppState>();
            let vaults = crate::items::list_vaults(&state).await.map_err(|_| "locked")?;
            Ok(Value::Array(vaults.into_iter().filter(|v| !v.orphaned).map(|v| json!({ "id": v.id, "name": v.name })).collect()))
        }
        "form_items" => super::forms::list(app).await,
        "form_details" => {
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            super::forms::details(app, &id).await
        }
        "save_sign_in_with" => {
            // A site the user signed in to through a provider ("Sign in
            // with Google"): a login that says so.
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let provider = args.get("provider").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let title = args.get("title").and_then(Value::as_str).unwrap_or("").to_string();
            let account = args.get("account").and_then(Value::as_str).filter(|a| !a.is_empty()).map(str::to_string);
            let vault = args.get("vaultId").and_then(Value::as_str).map(str::to_string);
            super::logins::save_sign_in_with(app, &url, &provider, &title, account.as_deref(), vault.as_deref()).await
        }
        "check_secret" => {
            // Text the user copied on a page: an API key worth saving?
            let text = args.get("text").and_then(Value::as_str).ok_or("bad_request")?;
            Ok(super::api_keys::check(app, text).await)
        }
        "save_secret" => {
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let text = args.get("text").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let title = args.get("title").and_then(Value::as_str).unwrap_or("").to_string();
            let label = args.get("label").and_then(Value::as_str).unwrap_or("").to_string();
            let vault = args.get("vaultId").and_then(Value::as_str).map(str::to_string);
            super::api_keys::save(app, &url, &text, &title, &label, vault.as_deref()).await
        }
        "check_form" => {
            let kind = args.get("kind").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let values = args.get("values").cloned().ok_or("bad_request")?;
            super::forms::check_typed(app, &kind, &values).await
        }
        "save_form" => {
            let kind = args.get("kind").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let values = args.get("values").cloned().ok_or("bad_request")?;
            let title = args.get("title").and_then(Value::as_str).unwrap_or("").to_string();
            let vault = args.get("vaultId").and_then(Value::as_str).map(str::to_string);
            super::forms::save_typed(app, &kind, &values, &title, vault.as_deref()).await
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
            let rules = args.get("rules").and_then(Value::as_str).unwrap_or("");
            let url = args.get("url").and_then(Value::as_str).unwrap_or("");
            super::logins::suggest(max_length, symbols, rules, url)
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
        "scan_qr_image" => {
            // A picture of the page (the extension took it, for a site's
            // two-factor setup): the one-time password QR code in it.
            use base64::Engine;
            let image = args.get("image").and_then(Value::as_str).ok_or("bad_request")?;
            let data = image.split_once("base64,").map_or(image, |(_, data)| data);
            let bytes = base64::engine::general_purpose::STANDARD.decode(data).map_err(|_| "bad_request")?;
            let uri = crate::qr::scan_image(bytes).await.map_err(|_| "not_found")?;
            let totp = Totp::parse(&uri).map_err(|_| "not_found")?;
            Ok(json!({ "uri": uri, "issuer": totp.issuer, "account": totp.account }))
        }
        "set_totp" => {
            // Only a login for the page the code was read on.
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?;
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?;
            let uri = args.get("uri").and_then(Value::as_str).ok_or("bad_request")?;
            let page = Page::parse(url).ok_or("bad_request")?;
            {
                let state = app.state::<AppState>();
                let guard = state.session.lock().await;
                let session = guard.as_ref().ok_or("locked")?;
                let item = session.items.get(id).ok_or("not_found")?;
                if !item.overview.urls.iter().any(|u| match_score(&page, u) > 0) {
                    return Err("url_mismatch");
                }
            }
            crate::items::set_totp(app, id, uri).await.map_err(|err| match err {
                AppError::Locked => "locked",
                _ => "error",
            })?;
            Ok(json!({}))
        }
        "ssh_public_keys" => ssh_public_keys(app).await,
        "password_owner" => {
            // A password pasted into a page: whether it belongs to a login
            // for this page, or to logins for other sites (a page that may
            // be pretending to be one of them).
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?.to_string();
            let password = take_secret(args, "password")?;
            password_owner(app, &url, &password).await
        }
        "add_site" => {
            // The page's site, added to a login the user just filled there
            // on purpose (the extension asked first).
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?;
            let url = args.get("url").and_then(Value::as_str).ok_or("bad_request")?;
            crate::items::add_website(app, id, url).await.map_err(|err| match err {
                AppError::Locked => "locked",
                AppError::NotFound => "not_found",
                AppError::Invalid(msg) if msg.key == "vault_read_only" => "read_only",
                _ => "error",
            })?;
            Ok(json!({}))
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

/// 2 = same host, 1 = same site (or one sharing its accounts), 0 = no match. A login saved for an https
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
    } else {
        let (item_site, page_site) = (site_of(&item_host), site_of(&page.host));
        // The same site, or sites that share one account (see shared_sites).
        u8::from(item_site == page_site || super::shared_sites::shares_account(&item_site, &page_site))
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

async fn find(app: &AppHandle, query: Query<'_>, favorites: bool, limit: usize) -> Result<Value, &'static str> {
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
        if o.trashed_at.is_some() || o.archived || !is_fillable(o.category) || (favorites && !o.favorite) {
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
                "vaultId": item.vault_id,
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
    let mut logins: Vec<Value> = results.into_iter().take(limit).map(|(_, _, v)| v).collect();
    // Which have a one-time code (for the code's own fill and shortcut).
    // Not for the popup's long lists: it would decrypt every login's details.
    if limit <= MAX_RESULTS {
        for login in &mut logins {
            let id = login["id"].as_str().unwrap_or_default().to_string();
            let totp = crate::items::load_details(&state, session, &id)
                .is_ok_and(|(_, details)| details.all_fields().any(|f| f.kind == FieldKind::Totp && !f.value.trim().is_empty()));
            login["totp"] = json!(totp);
        }
    }
    // Website icons the app has (see `site_icons`), for the first ones only:
    // a reply must stay under the browser's 1 MiB message limit.
    let sites: Vec<String> =
        logins.iter().take(MAX_RESULTS).filter_map(|l| l["url"].as_str().filter(|u| !u.is_empty()).map(str::to_string)).collect();
    let icons = crate::site_icons::lookup(&state, session, &sites);
    for login in logins.iter_mut().take(MAX_RESULTS) {
        if let Some(icon) = login["url"].as_str().and_then(|url| icons.get(url)) {
            login["icon"] = json!(icon);
        }
    }
    // Logins that sign in through another provider ("Sign in with
    // Google"): which provider, and the account there (the first ones only,
    // as for icons).
    for login in logins.iter_mut().take(MAX_RESULTS) {
        let Some(id) = login["id"].as_str().map(str::to_string) else { continue };
        let Ok((_, details)) = crate::items::load_details(&state, session, &id) else { continue };
        let Some(field) = details.all_fields().find(|f| f.kind == FieldKind::SignInWith && !f.value.is_empty()) else { continue };
        login["signInWith"] = json!(field.value);
        let account = session.items.get(&field.extra.link).map(|linked| linked.overview.subtitle.clone()).unwrap_or_default();
        if !account.is_empty() {
            login["providerAccount"] = json!(account);
        }
    }
    Ok(Value::Array(logins))
}

/// What the popup shows for a login. Not counted as a use (only filling and
/// copying are), and the password only when the user asked to see it.
async fn item_details(app: &AppHandle, id: &str, reveal: bool) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let cached = session.items.get(id).ok_or("not_found")?;
    let o = &cached.overview;
    if o.trashed_at.is_some() || !is_fillable(o.category) {
        return Err("not_found");
    }
    let (_, details) = crate::items::load_details(&state, session, id).map_err(|_| "not_found")?;
    let password = details.field_by_purpose(FieldPurpose::Password).map(|f| f.value.as_str()).unwrap_or("");
    let now = now_secs().max(0) as u64;
    let totp = details
        .all_fields()
        .find(|f| f.kind == FieldKind::Totp && !f.value.is_empty())
        .and_then(|f| Totp::parse(&f.value).ok())
        .map(|t| {
            let period = t.period.max(1);
            json!({ "code": t.code_at(now).as_str(), "period": period, "expiresIn": period - now % period })
        });
    let vault = session.vaults.get(&cached.vault_id).map(|v| v.meta.name.clone()).unwrap_or_default();
    let urls: Vec<Value> = o.urls.iter().filter(|u| !u.href.trim().is_empty()).map(|u| json!({ "href": u.href, "label": u.label })).collect();
    let mut result = json!({
        "id": id,
        "title": o.title,
        "username": details.field_by_purpose(FieldPurpose::Username).map(|f| f.value.as_str()).unwrap_or(&o.subtitle),
        "urls": urls,
        "vault": vault,
        "favorite": o.favorite,
        "hasPassword": !password.is_empty(),
        "totp": totp,
        "updatedAt": o.updated_at,
    });
    if reveal {
        result["password"] = json!(password);
    }
    Ok(result)
}

/// `any_site` is set when the user explicitly confirmed, in the extension's
/// own UI, filling a login saved for another site. A login saved for an https
/// address still never goes to a plain http page.
/// SSH key items' public keys (nothing secret), for the forms where a
/// developer site asks for one.
async fn ssh_public_keys(app: &AppHandle) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let mut keys = Vec::new();
    for (id, item) in &session.items {
        let o = &item.overview;
        if o.category != Category::SshKey || o.trashed_at.is_some() || o.archived {
            continue;
        }
        let Ok((_, details)) = crate::items::load_details(&state, session, id) else { continue };
        let from_private = details
            .all_fields()
            .find(|f| f.kind == FieldKind::Concealed && f.value.contains("-----BEGIN "))
            .and_then(|f| crate::ssh_keys::parse_private(&f.value, None).ok())
            .and_then(|key| Some((key.public_key().to_openssh().ok()?, key.fingerprint(ssh_key::HashAlg::Sha256).to_string())));
        let from_field = || {
            details
                .all_fields()
                .map(|f| f.value.trim())
                .find(|v| v.starts_with("ssh-") || v.starts_with("ecdsa-sha2-") || v.starts_with("sk-"))
                .and_then(|v| ssh_key::PublicKey::from_openssh(v).ok())
                .map(|key| (key.to_openssh().unwrap_or_default(), key.fingerprint(ssh_key::HashAlg::Sha256).to_string()))
        };
        let Some((public_key, fingerprint)) = from_private.or_else(from_field) else { continue };
        keys.push(json!({ "id": id, "title": o.title, "publicKey": public_key, "fingerprint": fingerprint, "vaultId": item.vault_id }));
    }
    keys.sort_by_key(|k| k["title"].as_str().unwrap_or("").to_lowercase());
    Ok(Value::Array(keys))
}

/// The logins whose password is `password`: none matched for this page
/// (`matched` false) means it is another site's password.
async fn password_owner(app: &AppHandle, url: &str, password: &str) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let page = Page::parse(url).ok_or("bad_request")?;
    let mut matched = false;
    let mut logins = Vec::new();
    for (id, item) in &session.items {
        let o = &item.overview;
        if o.trashed_at.is_some() || !is_fillable(o.category) {
            continue;
        }
        let Ok((_, details)) = crate::items::load_details(&state, session, id) else { continue };
        if details.password() != Some(password) {
            continue;
        }
        if o.urls.iter().any(|u| match_score(&page, u) > 0) {
            matched = true;
            break;
        }
        if logins.len() < 5 {
            logins.push(json!({
                "itemId": id,
                "title": o.title,
                "site": o.urls.first().and_then(|u| url_host(&u.href)).unwrap_or_default(),
                "vaultId": item.vault_id,
            }));
        }
    }
    Ok(json!({ "matched": matched, "logins": if matched { Vec::new() } else { logins } }))
}

async fn credentials(app: &AppHandle, id: &str, url: Option<&str>, any_site: bool) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let cached = session.items.get(id).ok_or("not_found")?;

    // Requests that come from a page must match that page's site.
    let mut submit = None;
    if let Some(url) = url {
        let page = Page::parse(url).ok_or("bad_request")?;
        // What the website that matches best says about signing in.
        submit = cached.overview.urls.iter().filter(|u| match_score(&page, u) > 0).max_by_key(|u| match_score(&page, u)).and_then(|u| u.submit);
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
        "submit": submit,
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
        // Sites that share one account: iCloud signs in in a frame of
        // apple.com; not for an exact-host rule, nor onto plain http.
        assert_eq!(match_score(&page("https://idmsa.apple.com/appleauth"), &url("https://www.icloud.com")), 1);
        let exact = ItemUrl { href: "https://www.icloud.com".into(), fill: UrlMatch::Host, ..Default::default() };
        assert_eq!(match_score(&page("https://idmsa.apple.com"), &exact), 0);
        assert_eq!(match_score(&page("http://apple.com"), &url("https://icloud.com")), 0);
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
