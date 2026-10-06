use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("decryption failed: wrong key or tampered data")]
    Decryption,
    #[error("encryption failed")]
    Encryption,
    #[error("invalid ciphertext format")]
    InvalidEnvelope,
    #[error("invalid key material")]
    InvalidKey,
    #[error("invalid Secret Key")]
    InvalidSecretKey,
    #[error("unsupported or unsafe key derivation parameters")]
    UnsafeKdfParams,
    #[error("key derivation failed")]
    Kdf,
    #[error("the master password cannot be empty")]
    EmptyPassword,
    #[error("the operating system random number generator failed")]
    Rng,
    #[error("invalid data: {0}")]
    Serialization(String),
    #[error("invalid one-time password setup: {0}")]
    InvalidTotp(String),
    #[error("import failed: {0}")]
    Import(String),
    #[error("invalid generator options: {0}")]
    InvalidGeneratorOptions(String),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}
