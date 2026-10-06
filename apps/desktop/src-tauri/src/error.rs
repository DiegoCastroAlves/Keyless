use std::collections::BTreeMap;

use serde::{Serialize, Serializer, ser::SerializeStruct};

pub type AppResult<T> = Result<T, AppError>;

/// A user-facing message: a translation key (looked up in the UI's
/// `errors.*` namespace) plus named parameters. Messages must never contain
/// secrets.
#[derive(Debug, Clone)]
pub struct Msg {
    pub key: &'static str,
    pub params: Vec<(&'static str, String)>,
}

impl Msg {
    pub fn new(key: &'static str) -> Self {
        Self { key, params: Vec::new() }
    }

    pub fn with(mut self, name: &'static str, value: impl ToString) -> Self {
        self.params.push((name, value.to_string()));
        self
    }
}

impl std::fmt::Display for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.key)?;
        for (name, value) in &self.params {
            write!(f, " {name}={value}")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("locked")]
    Locked,
    #[error("no account")]
    NoAccount,
    #[error("wrong master password")]
    WrongPassword,
    #[error("auth: {0}")]
    Auth(Msg),
    #[error("offline")]
    Offline,
    #[error("server error: {0}")]
    Server(String),
    #[error("local storage error: {0}")]
    Store(String),
    #[error("invalid: {0}")]
    Invalid(Msg),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Core(#[from] keyless_core::Error),
    #[error("cancelled")]
    Cancelled,
    #[error("rate limited for {0} s")]
    RateLimited(u64),
}

impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Locked => "locked",
            AppError::NoAccount => "no_account",
            AppError::WrongPassword => "wrong_password",
            AppError::Auth(_) => "auth",
            AppError::Offline => "offline",
            AppError::Server(_) => "server",
            AppError::Store(_) => "store",
            AppError::Invalid(_) => "invalid",
            AppError::NotFound => "not_found",
            AppError::Core(_) => "core",
            AppError::Cancelled => "cancelled",
            AppError::RateLimited(_) => "rate_limited",
        }
    }

    /// Translation key and parameters for the UI.
    pub fn message(&self) -> Msg {
        use keyless_core::Error as Core;
        match self {
            AppError::Auth(msg) | AppError::Invalid(msg) => msg.clone(),
            AppError::Server(detail) => Msg::new("server").with("detail", detail),
            AppError::Store(detail) => Msg::new("store").with("detail", detail),
            AppError::RateLimited(seconds) => Msg::new("rate_limited").with("seconds", seconds),
            AppError::Core(err) => match err {
                Core::Decryption => Msg::new("decryption_failed"),
                Core::InvalidSecretKey => Msg::new("secret_key_invalid"),
                Core::UnsafeKdfParams => Msg::new("unsafe_kdf"),
                Core::EmptyPassword => Msg::new("empty_password"),
                Core::InvalidTotp(detail) => Msg::new("totp_invalid_detail").with("detail", detail),
                Core::Import(detail) => Msg::new("import_failed").with("detail", detail),
                Core::InvalidGeneratorOptions(detail) => Msg::new("generator_options").with("detail", detail),
                other => Msg::new("internal").with("detail", other),
            },
            other => Msg::new(other.code()),
        }
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let msg = self.message();
        let params: BTreeMap<&str, &str> = msg.params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut s = serializer.serialize_struct("AppError", 4)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("key", msg.key)?;
        s.serialize_field("params", &params)?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::Store(err.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_connect() || err.is_timeout() || err.is_request() {
            AppError::Offline
        } else {
            AppError::Server(err.without_url().to_string())
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Store(err.to_string())
    }
}
