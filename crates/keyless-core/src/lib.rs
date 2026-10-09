//! Keyless core: cryptography, data model and import logic shared by every
//! Keyless client.
//!
//! Everything that touches secrets lives here so it can be reviewed and tested
//! in one place. The server only ever sees the ciphertexts produced by this
//! crate. See `docs/SECURITY.md` for the full design.

#![forbid(unsafe_code)]

pub mod account;
pub mod attachment;
pub mod backup;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod export;
pub mod generator;
pub mod import;
pub mod item;
pub mod keys;
pub mod passkey;
pub mod password_rules;
pub mod recovery;
pub mod share;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
