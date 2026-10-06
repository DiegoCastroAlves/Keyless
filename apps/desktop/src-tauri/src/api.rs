//! Minimal Supabase client (GoTrue auth + PostgREST).
//!
//! Every payload sent here is either ciphertext, a public key, or the derived
//! auth secret (never the master password, Secret Key or any decryption key).

use std::time::Duration;

use keyless_core::{account::AccountBundle, keys::KdfParams};
use reqwest::{Method, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config,
    error::{AppError, AppResult, Msg},
};

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: Url,
    key: String,
}

pub struct AuthSession {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    /// Unix seconds.
    pub expires_at: i64,
    pub user_id: String,
}

pub enum SignUpOutcome {
    Session(AuthSession),
    ConfirmationRequired,
}

#[derive(Deserialize)]
struct RawSession {
    access_token: String,
    refresh_token: String,
    expires_in: Option<i64>,
    expires_at: Option<i64>,
    user: RawUser,
}

#[derive(Deserialize)]
struct RawUser {
    id: String,
}

impl RawSession {
    fn into_session(self) -> AuthSession {
        let now = now_secs();
        AuthSession {
            access_token: Zeroizing::new(self.access_token),
            refresh_token: Zeroizing::new(self.refresh_token),
            expires_at: self
                .expires_at
                .unwrap_or_else(|| now + self.expires_in.unwrap_or(3600)),
            user_id: self.user.id,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RemoteProfile {
    pub format: u16,
    pub kdf: KdfParams,
    pub enc_user_key: String,
    pub public_key: String,
    pub enc_private_key: String,
    #[serde(default)]
    pub pending_kdf: Option<KdfParams>,
    #[serde(default)]
    pub pending_enc_user_key: Option<String>,
}

impl RemoteProfile {
    pub fn bundle(&self) -> AccountBundle {
        AccountBundle {
            format: self.format,
            kdf: self.kdf.clone(),
            enc_user_key: self.enc_user_key.clone(),
            public_key: self.public_key.clone(),
            enc_private_key: self.enc_private_key.clone(),
        }
    }

    pub fn pending_bundle(&self) -> Option<AccountBundle> {
        Some(AccountBundle {
            format: self.format,
            kdf: self.pending_kdf.clone()?,
            enc_user_key: self.pending_enc_user_key.clone()?,
            public_key: self.public_key.clone(),
            enc_private_key: self.enc_private_key.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RemoteVault {
    pub owner_id: String,
    pub enc_meta: String,
    pub seq: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RemoteMembership {
    pub vault_id: String,
    pub role: String,
    pub enc_vault_key: String,
    pub vaults: RemoteVault,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RemoteItem {
    pub id: String,
    pub vault_id: String,
    pub enc_overview: Option<String>,
    pub enc_details: Option<String>,
    pub revision: i64,
    pub seq: i64,
    pub deleted_at: Option<String>,
}

#[derive(Serialize)]
pub struct ItemWrite<'a> {
    pub enc_overview: Option<&'a str>,
    pub enc_details: Option<&'a str>,
    /// `Some("now")` is not valid; the server accepts an RFC 3339 timestamp.
    pub deleted_at: Option<String>,
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Api {
    pub fn new() -> AppResult<Self> {
        // reqwest picks up the process-wide rustls provider and verifies
        // certificates with the operating system's trust store.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("Keyless/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AppError::Server(e.to_string()))?;
        let base = Url::parse(config::SUPABASE_URL).map_err(|e| AppError::Server(e.to_string()))?;
        Ok(Self { http, base, key: config::SUPABASE_PUBLISHABLE_KEY.to_string() })
    }

    pub fn server_url(&self) -> String {
        self.base.as_str().trim_end_matches('/').to_string()
    }

    fn url(&self, path: &str, query: &[(&str, &str)]) -> Url {
        let mut url = self.base.join(path).expect("static path");
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        url
    }

    fn request(&self, method: Method, url: Url, token: Option<&str>) -> RequestBuilder {
        let mut req = self.http.request(method, url).header("apikey", &self.key);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        req
    }

    async fn send<T: DeserializeOwned>(&self, req: RequestBuilder) -> AppResult<T> {
        let resp = req.send().await?;
        let status = resp.status();
        if status.is_success() {
            // `Prefer: return=minimal` answers 201/204 with an empty body.
            let body = resp.bytes().await?;
            if body.iter().all(u8::is_ascii_whitespace) {
                return serde_json::from_value(Value::Null).map_err(AppError::from);
            }
            return Ok(serde_json::from_slice(&body)?);
        }
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        Err(map_error(status, &body))
    }

    // ----- auth -----------------------------------------------------------

    pub async fn sign_up(&self, email: &str, auth_secret: &str) -> AppResult<SignUpOutcome> {
        let req = self
            .request(Method::POST, self.url("auth/v1/signup", &[]), None)
            .json(&json!({ "email": email, "password": auth_secret }));
        let body: Value = self.send(req).await?;
        if body.get("access_token").is_some() {
            let raw: RawSession = serde_json::from_value(body)?;
            Ok(SignUpOutcome::Session(raw.into_session()))
        } else {
            Ok(SignUpOutcome::ConfirmationRequired)
        }
    }

    pub async fn sign_in(&self, email: &str, auth_secret: &str) -> AppResult<AuthSession> {
        let req = self
            .request(Method::POST, self.url("auth/v1/token", &[("grant_type", "password")]), None)
            .json(&json!({ "email": email, "password": auth_secret }));
        let raw: RawSession = self.send(req).await?;
        Ok(raw.into_session())
    }

    pub async fn refresh(&self, refresh_token: &str) -> AppResult<AuthSession> {
        let req = self
            .request(Method::POST, self.url("auth/v1/token", &[("grant_type", "refresh_token")]), None)
            .json(&json!({ "refresh_token": refresh_token }));
        let raw: RawSession = self.send(req).await?;
        Ok(raw.into_session())
    }

    pub async fn sign_out(&self, access_token: &str) -> AppResult<()> {
        let req = self.request(Method::POST, self.url("auth/v1/logout", &[("scope", "local")]), Some(access_token));
        let _: Value = self.send(req).await?;
        Ok(())
    }

    pub async fn resend_confirmation(&self, email: &str) -> AppResult<()> {
        let req = self
            .request(Method::POST, self.url("auth/v1/resend", &[]), None)
            .json(&json!({ "type": "signup", "email": email }));
        let _: Value = self.send(req).await?;
        Ok(())
    }

    /// Changes the sign-in secret (used by master password changes).
    pub async fn update_auth_secret(&self, token: &str, auth_secret: &str) -> AppResult<()> {
        let req = self
            .request(Method::PUT, self.url("auth/v1/user", &[]), Some(token))
            .json(&json!({ "password": auth_secret }));
        let _: Value = self.send(req).await?;
        Ok(())
    }

    // ----- profile --------------------------------------------------------

    pub async fn profile(&self, token: &str, user_id: &str) -> AppResult<Option<RemoteProfile>> {
        let filter = format!("eq.{user_id}");
        let req = self.request(
            Method::GET,
            self.url("rest/v1/profiles", &[("select", "*"), ("user_id", &filter)]),
            Some(token),
        );
        let mut rows: Vec<RemoteProfile> = self.send(req).await?;
        Ok(rows.pop())
    }

    pub async fn insert_profile(&self, token: &str, user_id: &str, bundle: &AccountBundle) -> AppResult<()> {
        let req = self
            .request(Method::POST, self.url("rest/v1/profiles", &[]), Some(token))
            .header("Prefer", "return=minimal")
            .json(&json!({
                "user_id": user_id,
                "format": bundle.format,
                "kdf": bundle.kdf,
                "enc_user_key": bundle.enc_user_key,
                "public_key": bundle.public_key,
                "enc_private_key": bundle.enc_private_key,
            }));
        let _: Value = self.send(req).await?;
        Ok(())
    }

    pub async fn update_profile(&self, token: &str, user_id: &str, patch: Value) -> AppResult<()> {
        let filter = format!("eq.{user_id}");
        let req = self
            .request(Method::PATCH, self.url("rest/v1/profiles", &[("user_id", &filter)]), Some(token))
            .header("Prefer", "return=minimal")
            .json(&patch);
        let _: Value = self.send(req).await?;
        Ok(())
    }

    // ----- vaults ---------------------------------------------------------

    pub async fn create_vault(&self, token: &str, id: &str, enc_meta: &str, enc_vault_key: &str) -> AppResult<RemoteVault> {
        let req = self
            .request(Method::POST, self.url("rest/v1/rpc/create_vault", &[]), Some(token))
            .json(&json!({ "p_id": id, "p_enc_meta": enc_meta, "p_enc_vault_key": enc_vault_key }));
        self.send(req).await
    }

    pub async fn memberships(&self, token: &str, user_id: &str) -> AppResult<Vec<RemoteMembership>> {
        let filter = format!("eq.{user_id}");
        let req = self.request(
            Method::GET,
            self.url(
                "rest/v1/vault_members",
                &[
                    ("select", "vault_id,role,enc_vault_key,vaults(owner_id,enc_meta,seq)"),
                    ("user_id", &filter),
                ],
            ),
            Some(token),
        );
        self.send(req).await
    }

    pub async fn update_vault_meta(&self, token: &str, id: &str, enc_meta: &str) -> AppResult<()> {
        let filter = format!("eq.{id}");
        let req = self
            .request(Method::PATCH, self.url("rest/v1/vaults", &[("id", &filter)]), Some(token))
            .header("Prefer", "return=minimal")
            .json(&json!({ "enc_meta": enc_meta }));
        let _: Value = self.send(req).await?;
        Ok(())
    }

    pub async fn delete_vault(&self, token: &str, id: &str) -> AppResult<()> {
        let filter = format!("eq.{id}");
        let req = self
            .request(Method::DELETE, self.url("rest/v1/vaults", &[("id", &filter)]), Some(token))
            .header("Prefer", "return=minimal");
        let _: Value = self.send(req).await?;
        Ok(())
    }

    // ----- items ----------------------------------------------------------

    pub async fn items_since(&self, token: &str, vault_id: &str, cursor: i64, limit: usize) -> AppResult<Vec<RemoteItem>> {
        let vault = format!("eq.{vault_id}");
        let seq = format!("gt.{cursor}");
        let limit = limit.to_string();
        let req = self.request(
            Method::GET,
            self.url(
                "rest/v1/items",
                &[
                    ("select", "*"),
                    ("vault_id", &vault),
                    ("seq", &seq),
                    ("order", "seq.asc"),
                    ("limit", &limit),
                ],
            ),
            Some(token),
        );
        self.send(req).await
    }

    pub async fn item(&self, token: &str, id: &str) -> AppResult<Option<RemoteItem>> {
        let filter = format!("eq.{id}");
        let req = self.request(Method::GET, self.url("rest/v1/items", &[("select", "*"), ("id", &filter)]), Some(token));
        let mut rows: Vec<RemoteItem> = self.send(req).await?;
        Ok(rows.pop())
    }

    /// Creates an item. Returns `Ok(None)` if an item with this id already
    /// exists (e.g. a previous upload whose response was lost).
    pub async fn insert_item(&self, token: &str, id: &str, vault_id: &str, enc_overview: &str, enc_details: &str) -> AppResult<Option<RemoteItem>> {
        let req = self
            .request(Method::POST, self.url("rest/v1/items", &[]), Some(token))
            .header("Prefer", "return=representation")
            .json(&json!({
                "id": id,
                "vault_id": vault_id,
                "enc_overview": enc_overview,
                "enc_details": enc_details,
            }));
        match self.send::<Vec<RemoteItem>>(req).await {
            Ok(mut rows) => Ok(rows.pop()),
            Err(AppError::Server(msg)) if msg.contains("23505") || msg.contains("duplicate key") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Updates an item only if the server still has `base_revision`.
    /// Returns `Ok(None)` on a revision conflict.
    pub async fn update_item(&self, token: &str, id: &str, base_revision: i64, write: &ItemWrite<'_>) -> AppResult<Option<RemoteItem>> {
        let id_filter = format!("eq.{id}");
        let rev_filter = format!("eq.{base_revision}");
        let req = self
            .request(
                Method::PATCH,
                self.url("rest/v1/items", &[("id", &id_filter), ("revision", &rev_filter)]),
                Some(token),
            )
            .header("Prefer", "return=representation")
            .json(write);
        let mut rows: Vec<RemoteItem> = self.send(req).await?;
        Ok(rows.pop())
    }

    pub async fn delete_account(&self, token: &str) -> AppResult<()> {
        let req = self
            .request(Method::POST, self.url("rest/v1/rpc/delete_account", &[]), Some(token))
            .json(&json!({}));
        let _: Value = self.send(req).await?;
        Ok(())
    }
}

fn map_error(status: StatusCode, body: &Value) -> AppError {
    let code = body
        .get("error_code")
        .or_else(|| body.get("code"))
        .or_else(|| body.get("error"))
        .map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))
        .unwrap_or_default();
    let message = body
        .get("msg")
        .or_else(|| body.get("message"))
        .or_else(|| body.get("error_description"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    match code.as_str() {
        "invalid_credentials" | "invalid_grant" => {
            return AppError::Auth(Msg::new("invalid_credentials"));
        }
        "email_not_confirmed" => {
            return AppError::Auth(Msg::new("email_not_confirmed"));
        }
        "over_email_send_rate_limit" | "over_request_rate_limit" | "over_sms_send_rate_limit" => {
            return AppError::Auth(Msg::new("too_many_attempts"));
        }
        "user_already_exists" | "email_exists" => {
            return AppError::Auth(Msg::new("email_exists"));
        }
        "signup_disabled" => return AppError::Auth(Msg::new("signup_disabled")),
        "email_address_invalid" | "validation_failed" => {
            return AppError::Auth(Msg::new("email_invalid"));
        }
        "refresh_token_not_found" | "refresh_token_already_used" | "session_not_found" | "bad_jwt" => {
            return AppError::Auth(Msg::new("session_expired"));
        }
        _ => {}
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return AppError::Auth(Msg::new("session_expired"));
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return AppError::Auth(Msg::new("too_many_attempts"));
    }
    let detail = if message.is_empty() { status.to_string() } else { format!("{message} ({code})") };
    AppError::Server(detail)
}
