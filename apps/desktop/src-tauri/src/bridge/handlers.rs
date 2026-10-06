//! Commands the browser extension can run (after pairing, over the
//! encrypted channel). Deliberately small: status, finding logins for a page
//! and returning the credentials the user chose to fill.

use keyless_core::{
    item::{Category, FieldKind, FieldPurpose},
    totp::Totp,
};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};

use crate::{api::now_secs, state::AppState};

const MAX_RESULTS: usize = 50;

pub async fn dispatch(app: &AppHandle, cmd: &str, args: &Value) -> Result<Value, &'static str> {
    match cmd {
        "status" => status(app).await,
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
        "credentials" => {
            let id = args.get("id").and_then(Value::as_str).ok_or("bad_request")?;
            let url = args.get("url").and_then(Value::as_str);
            credentials(app, id, url).await
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

/// Host part of a URL, accepting bare domains.
pub fn url_host(url: &str) -> Option<String> {
    let url = url.trim();
    let normalized = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    let parsed = url::Url::parse(&normalized).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    parsed.host_str().map(|h| h.trim_start_matches("www.").to_ascii_lowercase())
}

/// Registrable domain ("eTLD+1"), e.g. accounts.google.com -> google.com.
pub fn site_of(host: &str) -> String {
    psl::domain_str(host).map(str::to_string).unwrap_or_else(|| host.to_string())
}

/// The page a request comes from, as reported by the browser.
pub struct Page {
    host: String,
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
        Some(Page { host, secure })
    }
}

/// 2 = same host, 1 = same site, 0 = no match. A login saved for an https
/// address is never offered to a plain http page, where anyone on the network
/// could read it.
pub fn match_score(page: &Page, item_url: &str) -> u8 {
    let Some(item_host) = url_host(item_url) else { return 0 };
    let item_secure = item_url.trim().get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://"));
    if item_secure && !page.secure {
        0
    } else if item_host == page.host {
        2
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

    let mut results: Vec<(u8, Value)> = Vec::new();
    for (id, item) in &session.items {
        let o = &item.overview;
        if o.trashed_at.is_some() || o.archived || !is_fillable(o.category) {
            continue;
        }
        let score = match &page {
            Some(page) => o.urls.iter().map(|u| match_score(page, &u.href)).max().unwrap_or(0),
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
        b.0.cmp(&a.0).then_with(|| {
            a.1["title"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&b.1["title"].as_str().unwrap_or("").to_lowercase())
        })
    });
    Ok(Value::Array(results.into_iter().take(MAX_RESULTS).map(|(_, v)| v).collect()))
}

async fn credentials(app: &AppHandle, id: &str, url: Option<&str>) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let cached = session.items.get(id).ok_or("not_found")?;

    // Requests that come from a page must match that page's site.
    if let Some(url) = url {
        let page = Page::parse(url).ok_or("bad_request")?;
        if !cached.overview.urls.iter().any(|u| match_score(&page, &u.href) > 0) {
            return Err("url_mismatch");
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

    #[test]
    fn url_matching() {
        assert_eq!(url_host("https://www.GitHub.com/login"), Some("github.com".into()));
        assert_eq!(url_host("github.com"), Some("github.com".into()));
        assert_eq!(url_host("javascript:alert(1)"), None);
        assert_eq!(url_host("file:///etc/passwd"), None);
        assert!(Page::parse("javascript:alert(1)").is_none());
        assert!(Page::parse("github.com").is_none());

        assert_eq!(match_score(&page("https://github.com/login"), "https://github.com"), 2);
        assert_eq!(match_score(&page("https://gist.github.com"), "https://github.com"), 1);
        assert_eq!(match_score(&page("https://accounts.google.com"), "google.com"), 1);
        assert_eq!(match_score(&page("https://evilgithub.com"), "https://github.com"), 0);
        assert_eq!(match_score(&page("https://github.com.evil.io"), "https://github.com"), 0);
        // Different sites under a public suffix must not match.
        assert_eq!(match_score(&page("https://alice.github.io"), "https://bob.github.io"), 0);
        assert_eq!(match_score(&page("https://foo.co.uk"), "https://bar.co.uk"), 0);
    }

    #[test]
    fn https_logins_stay_off_http_pages() {
        assert_eq!(match_score(&page("http://github.com"), "https://github.com"), 0);
        assert_eq!(match_score(&page("http://github.com"), "HTTPS://github.com"), 0);
        // Upgrading is fine, and so are addresses saved without a scheme or
        // for plain http (routers, local services).
        assert_eq!(match_score(&page("https://github.com"), "http://github.com"), 2);
        assert_eq!(match_score(&page("http://router.lan"), "router.lan"), 2);
        assert_eq!(match_score(&page("http://localhost:8765/login"), "http://localhost:8765"), 2);
    }
}
