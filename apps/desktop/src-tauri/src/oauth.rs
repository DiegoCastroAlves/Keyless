//! "Continue with Google": OAuth 2.0 authorization code flow with PKCE, in the
//! system browser, with a loopback redirect (RFC 8252).
//!
//! Google only identifies the account. The session it yields can read
//! nothing (the database requires a session proven with the secret derived
//! from the master password and Secret Key), and the server only issues it
//! for accounts that are not set up yet. The app uses it once, to set that
//! derived secret when creating the account.

use std::{collections::HashMap, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use tauri_plugin_opener::OpenerExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use zeroize::Zeroizing;

use crate::{
    api::{AuthSession, CodeExchange},
    error::{AppError, AppResult, Msg},
    state::AppState,
};

const CALLBACK_PATH: &str = "/auth/callback";
/// How long the browser step may take.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// Texts for the page the browser shows after the redirect, translated by the
/// UI.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPage {
    pub done_title: String,
    pub done_body: String,
    pub error_title: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum GoogleResult {
    /// No Keyless account yet: the user chooses a master password next.
    New { email: String },
    /// The account exists: it opens with the Secret Key and master password.
    Existing { email: String },
}

/// The Google session kept between the browser step and the master password
/// step of a new account.
pub struct PendingGoogle {
    pub session: AuthSession,
    pub email: String,
}

/// Runs the browser step. Only one at a time; `cancel` stops it.
pub async fn sign_in_with_google(app: &AppHandle, page: BrowserPage) -> AppResult<GoogleResult> {
    let state = app.state::<AppState>();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    {
        let mut slot = state.google_cancel.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|tx| !tx.is_closed()) {
            return Err(AppError::Invalid(Msg::new("busy")));
        }
        *slot = Some(cancel_tx);
    }
    discard_pending(&state).await;

    let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(*keyless_core::crypto::random_array::<32>()?));
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(google_failed)?;
    let port = listener.local_addr().map_err(google_failed)?.port();
    let redirect = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
    let url = state.api.authorize_url("google", &redirect, &challenge);
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|e| AppError::Invalid(Msg::new("open_url_failed").with("detail", e)))?;

    let callback = tokio::select! {
        result = wait_for_callback(&listener, &page) => result?,
        _ = tokio::time::sleep(SIGN_IN_TIMEOUT) => return Err(AppError::Invalid(Msg::new("google_timeout"))),
        _ = cancel_rx => return Err(AppError::Cancelled),
    };
    drop(listener);
    let code = match callback {
        Callback::Code(code) => code,
        Callback::Error(detail) => return Err(AppError::Auth(Msg::new("google_failed").with("detail", detail))),
    };

    match state.api.exchange_code(&code, &verifier).await? {
        CodeExchange::AccountExists(email) => Ok(GoogleResult::Existing { email }),
        CodeExchange::Session(session, email) => {
            // A second check besides the server: never touch the password of
            // an account that is already set up.
            if state.api.account_exists(&session.access_token).await? {
                let _ = state.api.sign_out(&session.access_token).await;
                return Ok(GoogleResult::Existing { email });
            }
            if email.is_empty() {
                let _ = state.api.sign_out(&session.access_token).await;
                return Err(AppError::Auth(Msg::new("google_failed").with("detail", "no email")));
            }
            *state.pending_google.lock().await = Some(PendingGoogle { session, email: email.clone() });
            Ok(GoogleResult::New { email })
        }
    }
}

/// Stops a running browser step and forgets any Google session.
pub async fn cancel(state: &AppState) {
    if let Some(tx) = state.google_cancel.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = tx.send(());
    }
    discard_pending(state).await;
}

async fn discard_pending(state: &AppState) {
    if let Some(pending) = state.pending_google.lock().await.take() {
        let _ = state.api.sign_out(&pending.session.access_token).await;
    }
}

fn google_failed(err: impl std::fmt::Display) -> AppError {
    AppError::Auth(Msg::new("google_failed").with("detail", err))
}

enum Callback {
    Code(Zeroizing<String>),
    Error(String),
}

async fn wait_for_callback(listener: &TcpListener, page: &BrowserPage) -> AppResult<Callback> {
    loop {
        let (stream, _) = listener.accept().await.map_err(google_failed)?;
        if let Ok(Some(callback)) = tokio::time::timeout(REQUEST_TIMEOUT, handle_request(stream, page)).await {
            return Ok(callback);
        }
    }
}

async fn handle_request(mut stream: TcpStream, page: &BrowserPage) -> Option<Callback> {
    let head = read_head(&mut stream).await?;
    let target = head.lines().next()?.strip_prefix("GET ")?.split(' ').next()?;
    let url = url::Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != CALLBACK_PATH {
        respond(&mut stream, "404 Not Found", "", "").await;
        return None;
    }
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if let Some(code) = params.get("code").filter(|c| !c.is_empty()) {
        respond(&mut stream, "200 OK", PAGE_CSP, &result_page(&page.done_title, &page.done_body)).await;
        return Some(Callback::Code(Zeroizing::new(code.clone())));
    }
    if let Some(detail) = params.get("error_description").or_else(|| params.get("error")) {
        respond(&mut stream, "200 OK", PAGE_CSP, &result_page(&page.error_title, detail)).await;
        return Some(Callback::Error(detail.clone()));
    }
    // Errors can also arrive in the URL fragment, which browsers never send:
    // move it to the query string.
    respond(&mut stream, "200 OK", FORWARDER_CSP, FORWARDER).await;
    None
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() + n > MAX_REQUEST_HEAD {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(buf).ok()
}

async fn respond(stream: &mut TcpStream, status: &str, csp: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Content-Security-Policy: {csp}\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'";
const FORWARDER_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'";
const FORWARDER: &str = "<!doctype html><meta charset=\"utf-8\"><script>\
if (location.hash.length > 1) location.replace(location.pathname + \"?\" + location.hash.slice(1));\
</script>";

fn escape_html(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn result_page(title: &str, body: &str) -> String {
    format!(
        r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Keyless</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--text:#121820;--muted:#5d6877;--accent:#0d9488}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1216;--card:#161a20;--text:#e7eaee;--muted:#9aa3ae;--accent:#2dd4bf}}}}
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:380px;margin:16px;padding:32px;border-radius:16px;background:var(--card);text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.08)}}
.logo{{width:48px;height:48px}}h1{{margin:16px 0 8px;font-size:20px}}p{{margin:0;color:var(--muted)}}
</style></head><body><main><svg class="logo" viewBox="0 0 1024 1024" aria-hidden="true"><circle cx="512" cy="512" r="452" fill="var(--accent)"/><circle cx="512" cy="512" r="318" fill="#073b37"/><circle cx="512" cy="438" r="94" fill="#fff"/><path d="M470 486H554L586 676Q590 702 564 702H460Q434 702 438 676Z" fill="#fff"/></svg><h1>{}</h1><p>{}</p></main></body></html>"##,
        escape_html(title),
        escape_html(body)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_page_text() {
        assert_eq!(escape_html(r#"<script>"&'"#), "&lt;script&gt;&quot;&amp;&#39;");
        assert!(result_page("<b>", "x").contains("&lt;b&gt;"));
    }

    #[tokio::test]
    async fn callback_server_extracts_code_and_errors() {
        let page = BrowserPage { done_title: "Done".into(), done_body: "Close".into(), error_title: "Error".into() };
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let get = |path: &'static str| async move {
                let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
                let mut out = String::new();
                s.read_to_string(&mut out).await.unwrap();
                out
            };
            let not_found = get("/favicon.ico").await;
            let forwarder = get("/auth/callback").await;
            let done = get("/auth/callback?code=abc123").await;
            (not_found, forwarder, done)
        });
        let callback = wait_for_callback(&listener, &page).await.unwrap();
        assert!(matches!(callback, Callback::Code(ref c) if c.as_str() == "abc123"));
        let (not_found, forwarder, done) = client.await.unwrap();
        assert!(not_found.starts_with("HTTP/1.1 404"));
        assert!(forwarder.contains("location.hash"));
        assert!(done.contains("<h1>Done</h1>"));

        let client = tokio::spawn(async move {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(b"GET /auth/callback?error=access_denied&error_description=%3Cno%3E HTTP/1.1\r\n\r\n").await.unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        });
        let callback = wait_for_callback(&listener, &page).await.unwrap();
        assert!(matches!(callback, Callback::Error(ref d) if d == "<no>"));
        assert!(client.await.unwrap().contains("&lt;no&gt;"));
    }
}
