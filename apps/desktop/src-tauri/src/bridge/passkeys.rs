//! Passkeys for the browser extension: creating one when a site asks, and
//! signing in with one. The extension shows the request to the user in its
//! own window and calls these only after the user chose; the origin comes
//! from the browser, never from the page.
//!
//! Checks, as WebAuthn requires: the page is https (or localhost), the
//! relying party id is the page's host or a parent domain of it, never a
//! public suffix (so `example.github.io` cannot claim `github.io`), an IP
//! address or a single label. Only ES256 keys.
//!
//! A request from a frame of another origin inside the page (which the
//! extension lets through only where the page allows passkeys in it) is
//! checked against the frame's origin, and `clientDataJSON` names the page
//! too (`crossOrigin`, `topOrigin`), as the browser would.
//!
//! The `prf` extension is answered (see `passkey::prf`); the others are
//! left to the extension (`credProps`) or not supported.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keyless_core::{
    item::{Category, FieldKind, FieldPurpose, ItemUrl},
    passkey::{self, Passkey},
};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};

use super::handlers::site_of;
use crate::{
    api::now_secs,
    items::{self, ItemDraft},
    state::AppState,
};

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>, &'static str> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).map_err(|_| "bad_request")
}

/// The page's origin and host, if a passkey may be used there at all.
fn page(origin: &str) -> Result<(String, String), &'static str> {
    let url = url::Url::parse(origin).map_err(|_| "bad_request")?;
    let host = url.host_str().ok_or("bad_request")?.to_ascii_lowercase();
    match url.scheme() {
        "https" => {}
        "http" if host == "localhost" => {}
        _ => return Err("insecure_page"),
    }
    Ok((url.origin().ascii_serialization(), host))
}

/// `rp_id` may be used by a page on `host`.
pub fn rp_id_allowed(host: &str, rp_id: &str) -> bool {
    let rp_id = rp_id.to_ascii_lowercase();
    if host == "localhost" || rp_id == "localhost" {
        return host == rp_id;
    }
    if rp_id.parse::<std::net::IpAddr>().is_ok() || !rp_id.contains('.') {
        return false;
    }
    // A registrable domain, or a host under one (not a public suffix).
    let Some(site) = psl::domain_str(&rp_id) else { return false };
    if site_of(host) != site {
        return false;
    }
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

/// The rp id a request names (or the page's host), checked against the page.
fn rp_id(args: &Value, host: &str) -> Result<String, &'static str> {
    let rp_id = args.get("rpId").and_then(Value::as_str).map(str::to_ascii_lowercase).unwrap_or_else(|| host.to_string());
    if rp_id_allowed(host, &rp_id) { Ok(rp_id) } else { Err("rp_id_mismatch") }
}

/// The page around the frame that asks, for a frame of another origin.
fn top_origin(args: &Value) -> Result<Option<String>, &'static str> {
    match args.get("topOrigin").and_then(Value::as_str) {
        Some(top) => Ok(Some(page(top)?.0)),
        None => Ok(None),
    }
}

/// Largest PRF input taken from a site.
const MAX_PRF_INPUT: usize = 1024;

/// The PRF results for `key`: `{first, second?}` from the inputs the site
/// gave (`evalByCredential` for this passkey, else `eval`), or none.
fn prf_results(key: &Passkey, prf: Option<&Value>) -> Result<Option<Value>, &'static str> {
    let Some(prf) = prf else { return Ok(None) };
    let inputs = prf.get("evalByCredential").and_then(|by| by.get(&key.credential_id)).or_else(|| prf.get("eval"));
    let Some(inputs) = inputs else { return Ok(None) };
    let one = |name: &str| -> Result<Option<String>, &'static str> {
        let Some(text) = inputs.get(name).and_then(Value::as_str) else { return Ok(None) };
        let input = unb64(text)?;
        if input.len() > MAX_PRF_INPUT {
            return Err("bad_request");
        }
        Ok(Some(b64(&passkey::prf(key, &input).map_err(|_| "error")?)))
    };
    let Some(first) = one("first")? else { return Ok(None) };
    let mut results = json!({ "first": first });
    if let Some(second) = one("second")? {
        results["second"] = json!(second);
    }
    Ok(Some(results))
}

fn ids(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).filter_map(|id| unb64(id).ok()).map(|id| b64(&id)).collect())
        .unwrap_or_default()
}

/// Whether the page may use passkeys for the relying party it names (needs
/// no unlocked vault: checked before asking the user anything).
pub fn check(args: &Value) -> Result<Value, &'static str> {
    let origin = args.get("origin").and_then(Value::as_str).ok_or("bad_request")?;
    let (_, host) = page(origin)?;
    Ok(json!({ "rpId": rp_id(args, &host)? }))
}

/// Passkeys for the page: `{itemId, credentialId, title, userName}`, only
/// those in `allowCredentials` when the site lists some.
pub async fn list(app: &AppHandle, args: &Value) -> Result<Value, &'static str> {
    let origin = args.get("origin").and_then(Value::as_str).ok_or("bad_request")?;
    let (_, host) = page(origin)?;
    let rp_id = rp_id(args, &host)?;
    let allowed = ids(args, "allowCredentials");
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let mut found = Vec::new();
    for (id, cached) in &session.items {
        let o = &cached.overview;
        if o.trashed_at.is_some() || o.archived {
            continue;
        }
        let Ok((_, details)) = items::load_details(&state, session, id) else { continue };
        for key in details.passkeys.iter().filter(|p| p.rp_id == rp_id) {
            if allowed.is_empty() || allowed.contains(&key.credential_id) {
                found.push(json!({
                    "itemId": id,
                    "credentialId": key.credential_id,
                    "title": o.title,
                    "userName": if key.user_name.is_empty() { &key.user_display_name } else { &key.user_name },
                }));
            }
        }
    }
    Ok(Value::Array(found))
}

/// Creates a passkey, in item `itemId` (a login for the site) or in a new
/// login. Refused when the site already has one of `excludeCredentials`.
pub async fn create(app: &AppHandle, args: &Value) -> Result<Value, &'static str> {
    let origin = args.get("origin").and_then(Value::as_str).ok_or("bad_request")?;
    let (origin, host) = page(origin)?;
    let rp_id = rp_id(args, &host)?;
    let top_origin = top_origin(args)?;
    let text = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let challenge = unb64(&text("challenge"))?;
    let user_handle = unb64(&text("userId"))?;
    if challenge.len() < 16 || user_handle.is_empty() || user_handle.len() > 64 {
        return Err("bad_request");
    }
    let algorithms: Vec<i64> = args.get("algorithms").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
    if !algorithms.is_empty() && !algorithms.contains(&passkey::ES256) {
        return Err("unsupported");
    }

    // Existing passkeys the site excludes, and the item to save into.
    let excluded = ids(args, "excludeCredentials");
    if !excluded.is_empty() {
        let existing = list(app, &json!({ "origin": origin, "rpId": rp_id })).await?;
        if existing.as_array().is_some_and(|l| l.iter().any(|p| p["credentialId"].as_str().is_some_and(|id| excluded.iter().any(|e| e == id)))) {
            return Err("exists");
        }
    }

    let user_name = text("userName");
    let created = passkey::create(&rp_id, &text("rpName"), &user_handle, &user_name, &text("userDisplayName"), true, now_secs())
        .map_err(|_| "error")?;
    let state = app.state::<AppState>();
    let item_id = text("itemId");
    if item_id.is_empty() {
        // A new login for the site.
        let vaults = super::logins::vaults(app).await?;
        let vault_id = vaults[0]["id"].as_str().ok_or("no_vault")?.to_string();
        let title = if text("rpName").trim().is_empty() { rp_id.clone() } else { text("rpName") };
        let draft = ItemDraft {
            id: None,
            vault_id,
            title,
            category: Category::Login,
            urls: vec![ItemUrl { href: origin.clone(), ..Default::default() }],
            tags: Vec::new(),
            favorite: false,
            fields: vec![keyless_core::item::Field {
                id: keyless_core::item::new_field_id(),
                label: "username".into(),
                kind: FieldKind::Text,
                value: user_name,
                purpose: Some(FieldPurpose::Username),
            }],
            sections: Vec::new(),
            notes: String::new(),
        };
        items::save_item_with(app, draft, items::Extras { passkeys: Some(vec![created.passkey.clone()]), ..Default::default() })
            .await
            .map_err(|_| "error")?;
    } else {
        // A login saved for this site; a passkey for the same account is
        // replaced.
        let draft = items::get_item_draft(&state, &item_id).await.map_err(|_| "not_found")?;
        let mut passkeys = {
            let guard = state.session.lock().await;
            let session = guard.as_ref().ok_or("locked")?;
            let cached = session.items.get(&item_id).ok_or("not_found")?;
            let page_url = super::handlers::Page::parse(&origin).ok_or("bad_request")?;
            if !cached.overview.urls.iter().any(|u| super::handlers::match_score(&page_url, u) > 0) {
                return Err("url_mismatch");
            }
            items::load_details(&state, session, &item_id).map_err(|_| "not_found")?.1.passkeys.clone()
        };
        passkeys.retain(|p| !(p.rp_id == rp_id && p.user_handle == created.passkey.user_handle));
        passkeys.push(created.passkey.clone());
        items::save_item_with(app, draft, items::Extras { passkeys: Some(passkeys), ..Default::default() }).await.map_err(|_| "error")?;
    }

    let client_data = passkey::client_data_json("webauthn.create", &challenge, &origin, top_origin.as_deref());
    let mut answer = json!({
        "credentialId": b64(&created.credential_id),
        "clientDataJSON": b64(client_data.as_bytes()),
        "attestationObject": b64(&created.attestation_object),
        "authenticatorData": b64(&created.authenticator_data),
        "publicKey": b64(&created.public_key),
        "publicKeyAlgorithm": passkey::ES256,
    });
    // Asked for at all: every Keyless passkey has it.
    if let Some(prf) = args.get("prf").filter(|p| p.is_object()) {
        answer["prf"] = json!({ "enabled": true });
        if let Some(results) = prf_results(&created.passkey, Some(prf))? {
            answer["prf"]["results"] = results;
        }
    }
    Ok(answer)
}

/// Signs in with the passkey `credentialId`.
pub async fn get(app: &AppHandle, args: &Value) -> Result<Value, &'static str> {
    let origin = args.get("origin").and_then(Value::as_str).ok_or("bad_request")?;
    let (origin, host) = page(origin)?;
    let rp_id = rp_id(args, &host)?;
    let top_origin = top_origin(args)?;
    let challenge = unb64(args.get("challenge").and_then(Value::as_str).unwrap_or(""))?;
    if challenge.len() < 16 {
        return Err("bad_request");
    }
    let wanted = args.get("credentialId").and_then(Value::as_str).ok_or("bad_request")?;
    let state = app.state::<AppState>();
    let (item_id, key): (String, Passkey) = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or("locked")?;
        let mut found = None;
        for (id, cached) in &session.items {
            if cached.overview.trashed_at.is_some() || cached.overview.archived {
                continue;
            }
            let Ok((_, details)) = items::load_details(&state, session, id) else { continue };
            if let Some(key) = details.passkeys.iter().find(|p| p.credential_id == wanted && p.rp_id == rp_id) {
                found = Some((id.clone(), key.clone()));
                break;
            }
        }
        found.ok_or("not_found")?
    };
    let client_data = passkey::client_data_json("webauthn.get", &challenge, &origin, top_origin.as_deref());
    let assertion = passkey::assert(&key, &client_data, true).map_err(|_| "error")?;
    let prf = prf_results(&key, args.get("prf"))?;
    crate::commands::record_use(&state, &item_id);
    let mut answer = json!({
        "credentialId": b64(&assertion.credential_id),
        "clientDataJSON": b64(client_data.as_bytes()),
        "authenticatorData": b64(&assertion.authenticator_data),
        "signature": b64(&assertion.signature),
        "userHandle": b64(&assertion.user_handle),
    });
    if let Some(results) = prf {
        answer["prf"] = json!({ "results": results });
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relying_party_ids() {
        assert!(rp_id_allowed("login.example.com", "example.com"));
        assert!(rp_id_allowed("example.com", "example.com"));
        assert!(rp_id_allowed("localhost", "localhost"));
        assert!(!rp_id_allowed("example.com", "login.example.com"));
        assert!(!rp_id_allowed("evilexample.com", "example.com"));
        assert!(!rp_id_allowed("example.com.evil.io", "example.com"));
        // Public suffixes, including private ones, cannot be claimed.
        assert!(!rp_id_allowed("alice.github.io", "github.io"));
        assert!(rp_id_allowed("alice.github.io", "alice.github.io"));
        assert!(!rp_id_allowed("www.example.co.uk", "co.uk"));
        assert!(!rp_id_allowed("127.0.0.1", "127.0.0.1"));
        assert!(!rp_id_allowed("intranet", "intranet"));
        assert!(!rp_id_allowed("localhost", "example.com"));
        assert_eq!(page("http://example.com"), Err("insecure_page"));
        assert_eq!(page("http://localhost:8765/x").unwrap().0, "http://localhost:8765");
    }

    #[test]
    fn prf_inputs() {
        let key = passkey::create("example.com", "", b"user", "", "", true, 0).unwrap().passkey;
        let first = b64(b"salt one");
        let other = b64(b"salt two");
        // This passkey's own inputs win over the general ones.
        let by_credential = json!({ "eval": { "first": other }, "evalByCredential": { key.credential_id.clone(): { "first": first } } });
        let general = json!({ "eval": { "first": first } });
        let a = prf_results(&key, Some(&by_credential)).unwrap().unwrap();
        let b = prf_results(&key, Some(&general)).unwrap().unwrap();
        assert_eq!(a, b);
        assert!(a.get("second").is_none());
        assert_eq!(prf_results(&key, None).unwrap(), None);
        assert_eq!(prf_results(&key, Some(&json!({}))).unwrap(), None);
        let huge = json!({ "eval": { "first": b64(&[0u8; MAX_PRF_INPUT + 1]) } });
        assert_eq!(prf_results(&key, Some(&huge)), Err("bad_request"));
        assert_eq!(top_origin(&json!({ "topOrigin": "http://shop.example" })), Err("insecure_page"));
        assert_eq!(top_origin(&json!({ "topOrigin": "https://shop.example/x" })).unwrap().as_deref(), Some("https://shop.example"));
    }
}
