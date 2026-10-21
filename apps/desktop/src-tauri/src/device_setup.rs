//! Getting the account onto a new device without typing the Secret Key:
//!
//! - **With another device** (see `keyless_core::device_setup`): the new
//!   device leaves a request for the account; a signed-in device shows it,
//!   the user types there the code the new device shows, and the email and
//!   Secret Key come back encrypted for the new device.
//! - **With a QR code** (see `keyless_core::qr_sign_in`): the new device
//!   shows one, a signed-in phone reads it and sends the email and Secret
//!   Key back, encrypted for the new device.
//! - **With a setup code** (see `keyless_core::setup_code`): the QR code a
//!   signed-in device shows ("Set up another device") or the Emergency Kit
//!   prints, read from the screen, a picture or the Kit's PDF; or the
//!   `keyless://setup` link itself, opened or pasted.
//!
//! Either way the email and Secret Key wait here, in memory, for the sign-in
//! form; the master password is still typed on the new device.

use std::{collections::HashMap, sync::Mutex};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keyless_core::{
    crypto::random_array,
    device_setup::{SetupApproval, SetupPayload, SetupRequest},
    keys::SecretKey,
    qr_sign_in::SignInRequest,
    setup_code,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::{
    api::Api,
    auth::normalize_email,
    devices,
    dialog_text::DialogText,
    error::{AppError, AppResult, Msg},
    kit_pdf::{self, KitLabels},
    qr::{self, Wanted},
    state::AppState,
    sync,
};

/// A signed-in device: another device asks to sign in to the account.
pub const EVENT_SETUP_REQUESTED: &str = "keyless://device-setup-requested";
/// A setup code arrived (a `keyless://setup` link was opened): the sign-in
/// form can show its email.
pub const EVENT_SETUP_RECEIVED: &str = "keyless://setup-received";
/// Wrong codes typed before a request is refused.
const MAX_CODE_ATTEMPTS: u32 = 3;

/// The email and Secret Key received for the sign-in form.
struct Received {
    email: String,
    secret_key: SecretKey,
}

/// This device's request to another one.
struct Outgoing {
    id: String,
    secret: String,
    email: String,
    request: SetupRequest,
    code: Option<String>,
}

#[derive(Default)]
pub struct SetupState {
    received: Mutex<Option<Received>>,
    outgoing: tokio::sync::Mutex<Option<Outgoing>>,
    qr: QrSignIns,
    /// Requests this device answered: its key, and the wrong codes typed.
    approvals: Mutex<HashMap<String, (SetupApproval, u32)>>,
    /// Requests already announced with a notification.
    announced: Mutex<std::collections::HashSet<String>>,
}

fn invalid(key: &'static str) -> AppError {
    AppError::Invalid(Msg::new(key))
}

// ----- received setup -------------------------------------------------------

fn receive(state: &AppState, email: String, secret_key: SecretKey) -> String {
    *state.setup.received.lock().unwrap_or_else(|e| e.into_inner()) = Some(Received { email: email.clone(), secret_key });
    email
}

/// The email of the setup received, if any.
pub fn received_email(state: &AppState) -> Option<String> {
    state.setup.received.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|r| r.email.clone())
}

/// The Secret Key received for `email` (a sign-in with it is about to run).
pub fn received_key(state: &AppState, email: &str) -> Option<SecretKey> {
    let received = state.setup.received.lock().unwrap_or_else(|e| e.into_inner());
    received
        .as_ref()
        .filter(|r| r.email.eq_ignore_ascii_case(email))
        .and_then(|r| SecretKey::from_bytes(r.secret_key.as_bytes()).ok())
}

pub fn clear_received(state: &AppState) {
    *state.setup.received.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Takes a setup link (pasted, or opened) for the sign-in form; returns its
/// email.
pub fn use_link(state: &AppState, link: &str) -> AppResult<String> {
    let (email, secret_key) = setup_code::parse_setup_link(link).map_err(|_| invalid("setup_code_invalid"))?;
    let email = normalize_email(&email)?;
    Ok(receive(state, email, secret_key))
}

/// Reads a setup code from the screen, the clipboard or a file (a picture,
/// or the Emergency Kit's PDF); returns its email.
pub async fn scan(app: &AppHandle, source: &str, text: &DialogText) -> AppResult<String> {
    let link = Zeroizing::new(qr::scan_for(app, source, text, Wanted::Setup).await?);
    use_link(&app.state::<AppState>(), &link)
}

/// Keyless was started (or started again) with a `keyless://setup` link:
/// the sign-in form gets it. Returns whether there was one.
pub fn handle_args(app: &AppHandle, args: &[String]) -> bool {
    let Some(link) = args.iter().find(|a| setup_code::is_setup_link(a)) else { return false };
    let state = app.state::<AppState>();
    match use_link(&state, link) {
        Ok(email) => {
            crate::main_window::deliver(app, EVENT_SETUP_RECEIVED, serde_json::Value::String(email));
        }
        Err(err) => log::info!("setup link: {err}"),
    }
    true
}

#[derive(Serialize)]
pub struct SetupQr {
    pub svg: String,
    pub link: String,
}

fn qr_for(email: &str, secret_key: &SecretKey) -> AppResult<SetupQr> {
    let link = setup_code::setup_link(email, secret_key);
    Ok(SetupQr { svg: crate::items::branded_qr_svg(&link)?, link: link.to_string() })
}

/// The signed-in account's setup code, after the master password.
pub async fn account_qr(state: &AppState, master_password: Zeroizing<String>) -> AppResult<SetupQr> {
    let display = Zeroizing::new(crate::auth::reveal_secret_key(state, master_password).await?);
    let email = state.session.lock().await.as_ref().map(|s| s.email.clone()).ok_or(AppError::Locked)?;
    qr_for(&email, &SecretKey::parse(&display)?)
}

/// The setup code printed on an Emergency Kit (whose Secret Key the window
/// already shows).
pub fn kit_qr(email: &str, secret_key: &str) -> AppResult<SetupQr> {
    let key = SecretKey::parse(secret_key).map_err(|_| invalid("secret_key_invalid"))?;
    qr_for(email, &key)
}

/// Saves the Emergency Kit as a PDF the user picks.
pub async fn save_kit(app: &AppHandle, labels: KitLabels, email: String, secret_key: String, text: &DialogText) -> AppResult<()> {
    use tauri_plugin_dialog::DialogExt;
    let secret_key = Zeroizing::new(secret_key);
    let key = SecretKey::parse(&secret_key).map_err(|_| invalid("secret_key_invalid"))?;
    let link = setup_code::setup_link(&email, &key);
    let pdf = Zeroizing::new(kit_pdf::emergency_kit(&labels, &email, &key.to_display(), &link).map_err(AppError::Store)?);
    // Named like the Kit's title, without characters file names cannot hold.
    let name: String = labels.title.chars().filter(|c| !"/\\:*?\"<>|".contains(*c) && !c.is_control()).collect();
    let name = if name.trim().is_empty() { "Keyless Emergency Kit".to_string() } else { name.trim().to_string() };
    let dialog = text.apply(app.dialog().file(), &[]).add_filter("PDF", &["pdf"]).set_file_name(format!("{name}.pdf"));
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| invalid("file_unwritable"))?;
    tauri::async_runtime::spawn_blocking(move || crate::import::write_private(&path, &pdf))
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
}

// ----- the new device ---------------------------------------------------------

#[derive(Deserialize)]
struct RequestStatus {
    status: String,
    approver_key: Option<String>,
    approver_nonce: Option<String>,
    payload: Option<String>,
}

#[derive(Serialize)]
pub struct SetupProgress {
    /// "waiting", "code" (show `code`), "approved" (the email and Secret
    /// Key arrived), "denied" or "expired".
    pub status: &'static str,
    pub code: Option<String>,
    pub email: Option<String>,
}

fn answer_error(answer: &Value) -> Option<AppError> {
    match answer.get("error").and_then(Value::as_str) {
        None => None,
        Some("device_setup_throttled") => Some(invalid("device_setup_throttled")),
        Some("qr_sign_in_throttled") => Some(invalid("qr_sign_in_throttled")),
        Some(_) => Some(invalid("invalid_request")),
    }
}

/// Asks the account's signed-in devices to let this one in.
pub async fn request(app: &AppHandle, email: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let email = normalize_email(email)?;
    if let Some(existing) = state.store().account()?
        && !existing.email.eq_ignore_ascii_case(&email)
    {
        return Err(AppError::Invalid(Msg::new("device_other_account").with("email", &existing.email)));
    }
    cancel(app).await;
    let request = SetupRequest::new()?;
    let id = uuid::Uuid::new_v4().to_string();
    let secret = URL_SAFE_NO_PAD.encode(random_array::<32>()?.as_ref());
    let answer: Value = state
        .api
        .rpc(
            None,
            "request_device_setup",
            json!({
                "p_email": email,
                "p_id": id,
                "p_secret": secret,
                "p_public_key": request.public_key(),
                "p_commitment": request.commitment(),
                "p_platform": devices::platform(),
            }),
        )
        .await
        .map_err(|err| if devices::is_missing_function(&err) { invalid("device_setup_unavailable") } else { err })?;
    if let Some(err) = answer_error(&answer) {
        return Err(err);
    }
    *state.setup.outgoing.lock().await = Some(Outgoing { id, secret, email, request, code: None });
    Ok(())
}

/// Where this device's request is; shows the code once another device
/// answered, and keeps the email and Secret Key once it approved.
pub async fn poll(app: &AppHandle) -> AppResult<SetupProgress> {
    let state = app.state::<AppState>();
    let mut slot = state.setup.outgoing.lock().await;
    let outgoing = slot.as_mut().ok_or_else(|| invalid("device_setup_expired"))?;
    let status: RequestStatus = state.api.rpc(None, "device_setup_status", json!({ "p_id": outgoing.id, "p_secret": outgoing.secret })).await?;
    let progress = |status: &'static str, code: Option<String>, email: Option<String>| SetupProgress { status, code, email };
    match status.status.as_str() {
        "pending" => Ok(progress("waiting", None, None)),
        "answered" | "revealed" => {
            let (Some(key), Some(nonce)) = (status.approver_key.as_deref(), status.approver_nonce.as_deref()) else {
                return Ok(progress("waiting", None, None));
            };
            let code = outgoing.request.code(key, nonce).map_err(|_| invalid("device_setup_failed"))?;
            if status.status == "answered" {
                let _: bool = state
                    .api
                    .rpc(None, "reveal_device_setup", json!({ "p_id": outgoing.id, "p_secret": outgoing.secret, "p_nonce": outgoing.request.nonce() }))
                    .await?;
            }
            outgoing.code = Some(code.clone());
            Ok(progress("code", Some(code), None))
        }
        "approved" => {
            let outgoing = slot.take().ok_or_else(|| invalid("device_setup_expired"))?;
            let (Some(key), Some(nonce), Some(payload)) = (status.approver_key, status.approver_nonce, status.payload) else {
                return Err(invalid("device_setup_failed"));
            };
            let SetupPayload { email, secret_key } =
                outgoing.request.open(&outgoing.id, &key, &nonce, &payload).map_err(|_| invalid("device_setup_failed"))?;
            if !email.eq_ignore_ascii_case(&outgoing.email) {
                return Err(invalid("device_setup_failed"));
            }
            let secret_key = SecretKey::parse(&secret_key).map_err(|_| invalid("device_setup_failed"))?;
            let email = receive(&state, outgoing.email, secret_key);
            Ok(progress("approved", None, Some(email)))
        }
        "denied" => {
            *slot = None;
            Ok(progress("denied", None, None))
        }
        _ => {
            *slot = None;
            Ok(progress("expired", None, None))
        }
    }
}

/// Gives up this device's request.
pub async fn cancel(app: &AppHandle) {
    let state = app.state::<AppState>();
    let Some(outgoing) = state.setup.outgoing.lock().await.take() else { return };
    let result: AppResult<Value> = state.api.rpc(None, "cancel_device_setup", json!({ "p_id": outgoing.id, "p_secret": outgoing.secret })).await;
    if let Err(err) = result {
        log::info!("could not cancel the device setup request: {err}");
    }
}

// ----- the new device, with a QR code ---------------------------------------

#[derive(Deserialize)]
struct QrStatus {
    status: String,
    approver_key: Option<String>,
    payload: Option<String>,
}

#[derive(Serialize)]
pub struct SignInQr {
    /// The request, for polling and cancelling it.
    pub id: String,
    pub svg: String,
}

/// Where a QR code sign-in is.
enum QrProgress {
    Waiting,
    /// A phone sent the account's email and Secret Key.
    Approved { email: String, secret_key: SecretKey },
    Denied,
    Expired,
}

/// This device's QR codes waiting for a phone, by request id: each sign-in
/// screen polls and cancels its own (a screen shown twice starts twice).
#[derive(Default)]
struct QrSignIns(tokio::sync::Mutex<HashMap<String, SignInRequest>>);

impl QrSignIns {
    async fn start(&self, api: &Api, platform: &str) -> AppResult<SignInQr> {
        let request = SignInRequest::new()?;
        let answer: Value = api
            .rpc(None, "start_qr_sign_in", json!({ "p_id": request.id(), "p_secret": request.poll_secret(), "p_platform": platform }))
            .await
            .map_err(|err| if devices::is_missing_function(&err) { invalid("device_setup_unavailable") } else { err })?;
        if let Some(err) = answer_error(&answer) {
            return Err(err);
        }
        let qr = SignInQr { id: request.id().to_string(), svg: crate::items::branded_qr_svg(&request.link())? };
        self.0.lock().await.insert(qr.id.clone(), request);
        Ok(qr)
    }

    async fn poll(&self, api: &Api, id: &str) -> AppResult<QrProgress> {
        let mut requests = self.0.lock().await;
        let request = requests.get(id).ok_or_else(|| invalid("device_setup_expired"))?;
        let status: QrStatus = api.rpc(None, "qr_sign_in_status", json!({ "p_id": request.id(), "p_secret": request.poll_secret() })).await?;
        match status.status.as_str() {
            "waiting" => Ok(QrProgress::Waiting),
            "approved" => {
                let request = requests.remove(id).ok_or_else(|| invalid("device_setup_expired"))?;
                let (Some(key), Some(payload)) = (status.approver_key, status.payload) else {
                    return Err(invalid("device_setup_failed"));
                };
                let SetupPayload { email, secret_key } = request.open(&key, &payload).map_err(|_| invalid("device_setup_failed"))?;
                let email = normalize_email(&email).map_err(|_| invalid("device_setup_failed"))?;
                let secret_key = SecretKey::parse(&secret_key).map_err(|_| invalid("device_setup_failed"))?;
                Ok(QrProgress::Approved { email, secret_key })
            }
            "denied" => {
                requests.remove(id);
                Ok(QrProgress::Denied)
            }
            _ => {
                requests.remove(id);
                Ok(QrProgress::Expired)
            }
        }
    }

    async fn cancel(&self, api: &Api, id: &str) {
        let Some(request) = self.0.lock().await.remove(id) else { return };
        let result: AppResult<Value> = api.rpc(None, "cancel_qr_sign_in", json!({ "p_id": request.id(), "p_secret": request.poll_secret() })).await;
        if let Err(err) = result {
            log::info!("could not cancel the QR code sign-in: {err}");
        }
    }
}

/// Leaves a request on the server and returns the QR code (SVG) a signed-in
/// phone reads to answer it, with the request's id for polling and
/// cancelling it.
pub async fn qr_start(app: &AppHandle) -> AppResult<SignInQr> {
    let state = app.state::<AppState>();
    state.setup.qr.start(&state.api, devices::platform()).await
}

/// Whether a phone answered QR code `id`; keeps the email and Secret Key it
/// sent for the sign-in form.
pub async fn qr_poll(app: &AppHandle, id: &str) -> AppResult<SetupProgress> {
    let state = app.state::<AppState>();
    let progress = |status: &'static str, email: Option<String>| SetupProgress { status, code: None, email };
    match state.setup.qr.poll(&state.api, id).await? {
        QrProgress::Waiting => Ok(progress("waiting", None)),
        QrProgress::Approved { email, secret_key } => {
            if let Some(existing) = state.store().account()?
                && !existing.email.eq_ignore_ascii_case(&email)
            {
                return Err(AppError::Invalid(Msg::new("device_other_account").with("email", &existing.email)));
            }
            Ok(progress("approved", Some(receive(&state, email, secret_key))))
        }
        QrProgress::Denied => Ok(progress("denied", None)),
        QrProgress::Expired => Ok(progress("expired", None)),
    }
}

/// Takes QR code `id` off the server.
pub async fn qr_cancel(app: &AppHandle, id: &str) {
    let state = app.state::<AppState>();
    state.setup.qr.cancel(&state.api, id).await;
}

// ----- a signed-in device -----------------------------------------------------

#[derive(Clone, Deserialize)]
struct RemoteRequest {
    id: String,
    public_key: String,
    commitment: String,
    platform: String,
    ip: Option<String>,
    country: Option<String>,
    created_at: String,
    expires_at: String,
    status: String,
    nonce: Option<String>,
    mine: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupRequestView {
    pub id: String,
    pub platform: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    /// "pending" (nobody answered), "answering" (this device answered and
    /// waits for the new device's code), "code" (type the code here), or
    /// "elsewhere" (another device of the account is handling it).
    pub status: &'static str,
}

async fn remote_requests(app: &AppHandle) -> AppResult<Vec<RemoteRequest>> {
    let state = app.state::<AppState>();
    let (_, token) = sync::ensure_token(&state).await?;
    let list: Value = state.api.rpc(Some(&token), "pending_device_setups", json!({})).await?;
    Ok(serde_json::from_value(list)?)
}

/// Requests from new devices waiting for this account.
pub async fn pending(app: &AppHandle) -> AppResult<Vec<SetupRequestView>> {
    let state = app.state::<AppState>();
    if !state.devices.supported() {
        return Ok(Vec::new());
    }
    let requests = remote_requests(app).await.inspect_err(|err| state.devices.note_error(err))?;
    let approvals = state.setup.approvals.lock().unwrap_or_else(|e| e.into_inner());
    Ok(requests
        .into_iter()
        .map(|r| {
            let status = match r.status.as_str() {
                "pending" => "pending",
                _ if !r.mine || !approvals.contains_key(&r.id) => "elsewhere",
                "revealed" => "code",
                _ => "answering",
            };
            SetupRequestView { id: r.id, platform: r.platform, ip: r.ip, country: r.country, created_at: r.created_at, expires_at: r.expires_at, status }
        })
        .collect())
}

async fn find(app: &AppHandle, id: &str) -> AppResult<RemoteRequest> {
    remote_requests(app).await?.into_iter().find(|r| r.id == id).ok_or_else(|| invalid("device_setup_expired"))
}

/// Starts handling request `id` on this device.
pub async fn answer(app: &AppHandle, id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let request = find(app, id).await?;
    if request.status != "pending" {
        return Err(invalid("device_setup_taken"));
    }
    let approval = SetupApproval::new(&request.public_key, &request.commitment).map_err(|_| invalid("device_setup_failed"))?;
    let (_, token) = sync::ensure_token(&state).await?;
    let taken: bool = state
        .api
        .rpc(Some(&token), "answer_device_setup", json!({ "p_id": id, "p_public_key": approval.public_key(), "p_nonce": approval.nonce() }))
        .await?;
    if !taken {
        return Err(invalid("device_setup_taken"));
    }
    state.setup.approvals.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), (approval, 0));
    Ok(())
}

/// Approves request `id` when `code` is the one the new device shows: sends
/// it the email and Secret Key.
pub async fn approve(app: &AppHandle, id: &str, code: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let request = find(app, id).await?;
    let nonce = request.nonce.as_deref().filter(|_| request.status == "revealed" && request.mine).ok_or_else(|| invalid("device_setup_expired"))?;
    let email = state.store().account()?.map(|a| a.email).ok_or(AppError::NoAccount)?;
    let secret_key = state.secrets.load_secret_key(&email)?.ok_or(AppError::NoAccount)?;
    let sealed = {
        let mut approvals = state.setup.approvals.lock().unwrap_or_else(|e| e.into_inner());
        let (approval, attempts) = approvals.get_mut(id).ok_or_else(|| invalid("device_setup_expired"))?;
        if approval.code_matches(nonce, code).map_err(|_| invalid("device_setup_failed"))? {
            let payload = SetupPayload { email, secret_key: secret_key.to_display() };
            Some(approval.seal(id, nonce, &payload).map_err(|_| invalid("device_setup_failed"))?)
        } else {
            *attempts += 1;
            if *attempts < MAX_CODE_ATTEMPTS {
                return Err(invalid("device_setup_code_wrong"));
            }
            None
        }
    };
    let Some(envelope) = sealed else {
        // Too many wrong codes: whoever asked is not in front of this screen.
        deny(app, id).await?;
        return Err(invalid("device_setup_code_denied"));
    };
    let (_, token) = sync::ensure_token(&state).await?;
    let approved: bool = state.api.rpc(Some(&token), "approve_device_setup", json!({ "p_id": id, "p_enc_payload": envelope })).await?;
    state.setup.approvals.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
    if approved { Ok(()) } else { Err(invalid("device_setup_expired")) }
}

/// Refuses request `id`.
pub async fn deny(app: &AppHandle, id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    state.setup.approvals.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
    let (_, token) = sync::ensure_token(&state).await?;
    let _: Value = state.api.rpc(Some(&token), "deny_device_setup", json!({ "p_id": id })).await?;
    Ok(())
}

/// After each sync: announces requests that just arrived (a notification and
/// an event the main window shows a dialog for).
pub async fn check_requests(app: &AppHandle) {
    let state = app.state::<AppState>();
    if !state.devices.supported() {
        return;
    }
    let requests = match remote_requests(app).await {
        Ok(requests) => requests,
        Err(err) => {
            state.devices.note_error(&err);
            return;
        }
    };
    let fresh = {
        let mut announced = state.setup.announced.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = requests.iter().filter(|r| r.status == "pending" && announced.insert(r.id.clone())).count();
        announced.retain(|id| requests.iter().any(|r| &r.id == id));
        fresh
    };
    if fresh > 0 {
        let _ = app.emit(EVENT_SETUP_REQUESTED, ());
        crate::notify::device_setup(app);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use keyless_core::qr_sign_in::SignInLink;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    /// A request as the server keeps it.
    struct Row {
        secret: String,
        status: &'static str,
        approver_key: Option<String>,
        payload: Option<String>,
    }

    type Rows = Arc<std::sync::Mutex<HashMap<String, Row>>>;

    /// The server's QR code functions, as `20261015000000_qr_sign_in.sql`
    /// answers them.
    fn answer(rows: &Rows, name: &str, args: &Value) -> Value {
        let mut rows = rows.lock().unwrap();
        let id = args["p_id"].as_str().unwrap_or_default().to_string();
        let secret = args["p_secret"].as_str().unwrap_or_default();
        match name {
            "start_qr_sign_in" => {
                rows.insert(id, Row { secret: secret.into(), status: "waiting", approver_key: None, payload: None });
                json!({ "ok": true })
            }
            "qr_sign_in_status" => match rows.get(&id) {
                Some(row) if row.secret == secret && row.status == "approved" => {
                    let row = rows.remove(&id).unwrap();
                    json!({ "status": "approved", "approver_key": row.approver_key, "payload": row.payload })
                }
                Some(row) if row.secret == secret => json!({ "status": row.status }),
                _ => json!({ "status": "unknown" }),
            },
            "cancel_qr_sign_in" => {
                if rows.get(&id).is_some_and(|row| row.secret == secret) {
                    rows.remove(&id);
                }
                Value::Null
            }
            _ => json!({ "message": "not found" }),
        }
    }

    /// Serves `rest/v1/rpc/*` on a local port, one request per connection.
    async fn server(rows: Rows) -> Api {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                let (head, body) = loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    data.extend_from_slice(&buf[..n]);
                    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                    let head = String::from_utf8_lossy(&data[..end]).to_string();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                        .unwrap_or(0);
                    if data.len() >= end + 4 + length {
                        break (head, data[end + 4..end + 4 + length].to_vec());
                    }
                };
                let path = head.split(' ').nth(1).unwrap_or_default();
                let name = path.strip_prefix("/rest/v1/rpc/").unwrap_or_default();
                let args: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let reply = answer(&rows, name, &args).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Api::local(&format!("http://127.0.0.1:{port}/"))
    }

    /// The link a QR code on screen holds (what the phone reads).
    async fn link(qrs: &QrSignIns, id: &str) -> SignInLink {
        SignInLink::parse(&qrs.0.lock().await[id].link()).unwrap()
    }

    /// The phone approves request `id`: seals the email and Secret Key with
    /// what it read from `link`.
    fn approve(rows: &Rows, id: &str, link: &SignInLink, email: &str, secret_key: &SecretKey) {
        let payload = SetupPayload { email: email.into(), secret_key: secret_key.to_display() };
        let (key, envelope) = link.seal(&payload).unwrap();
        let mut rows = rows.lock().unwrap();
        let row = rows.get_mut(id).unwrap();
        row.status = "approved";
        row.approver_key = Some(key);
        row.payload = Some(envelope);
    }

    #[tokio::test]
    async fn the_qr_code_brings_the_email_and_secret_key() {
        let rows = Rows::default();
        let api = server(rows.clone()).await;
        let qrs = QrSignIns::default();

        let qr = qrs.start(&api, "linux").await.unwrap();
        assert!(qr.svg.contains("<svg"));
        assert!(rows.lock().unwrap().contains_key(&qr.id));
        assert!(matches!(qrs.poll(&api, &qr.id).await.unwrap(), QrProgress::Waiting));

        let link = link(&qrs, &qr.id).await;
        assert_eq!(link.id(), qr.id);
        let sent = SecretKey::generate().unwrap();
        approve(&rows, &qr.id, &link, " Me@Example.com ", &sent);
        let QrProgress::Approved { email, secret_key } = qrs.poll(&api, &qr.id).await.unwrap() else {
            panic!("not approved");
        };
        assert_eq!(email, "me@example.com");
        assert_eq!(secret_key.as_bytes(), sent.as_bytes());

        // Handed out once: the server and this device forgot the request.
        assert!(rows.lock().unwrap().is_empty());
        assert!(qrs.poll(&api, &qr.id).await.is_err());
    }

    #[tokio::test]
    async fn each_screen_cancels_only_its_own_qr_code() {
        let rows = Rows::default();
        let api = server(rows.clone()).await;
        let qrs = QrSignIns::default();

        let first = qrs.start(&api, "linux").await.unwrap();
        let second = qrs.start(&api, "linux").await.unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(rows.lock().unwrap().len(), 2);

        qrs.cancel(&api, &first.id).await;
        assert!(!rows.lock().unwrap().contains_key(&first.id));
        assert!(qrs.poll(&api, &first.id).await.is_err());
        assert!(matches!(qrs.poll(&api, &second.id).await.unwrap(), QrProgress::Waiting));

        // Gone from the server some other way (it expired): the screen says so.
        rows.lock().unwrap().clear();
        assert!(matches!(qrs.poll(&api, &second.id).await.unwrap(), QrProgress::Expired));
        assert!(qrs.0.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_denied_or_tampered_answer_signs_nobody_in() {
        let rows = Rows::default();
        let api = server(rows.clone()).await;
        let qrs = QrSignIns::default();

        let qr = qrs.start(&api, "linux").await.unwrap();
        rows.lock().unwrap().get_mut(&qr.id).unwrap().status = "denied";
        assert!(matches!(qrs.poll(&api, &qr.id).await.unwrap(), QrProgress::Denied));
        assert!(qrs.0.lock().await.is_empty());

        // Sealed for another QR code: this one cannot open it.
        let qr = qrs.start(&api, "linux").await.unwrap();
        let other = SignInLink::parse(&SignInRequest::new().unwrap().link()).unwrap();
        approve(&rows, &qr.id, &other, "me@example.com", &SecretKey::generate().unwrap());
        assert!(qrs.poll(&api, &qr.id).await.is_err());
        assert!(qrs.0.lock().await.is_empty());
    }
}
