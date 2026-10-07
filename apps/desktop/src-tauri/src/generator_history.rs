//! Passwords the user generated and then used: copied from the generator,
//! put in an item, or filled into a page by the browser extension. A sign-up
//! that fails, or an item never saved, does not lose them. Like 1Password's
//! and Bitwarden's generator history.
//!
//! Kept only in the local database (never synced), each entry encrypted with
//! a key derived from the account key; only the newest entries are kept.

use hkdf::Hkdf;
use keyless_core::{account::UnlockedAccount, crypto::SymmetricKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    api::now_secs,
    error::{AppError, AppResult},
    state::{AppState, Session},
};

/// Entries kept; older ones are deleted.
pub const MAX_ENTRIES: usize = 100;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub password: String,
    /// The website it was filled on, from the browser extension.
    pub site: Option<String>,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site: Option<String>,
}

fn key(account: &UnlockedAccount) -> AppResult<SymmetricKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"keyless/generator-history/v1"), account.user_key().as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"seal", key.as_mut()).map_err(|_| AppError::Server("generator history key".into()))?;
    Ok(SymmetricKey::from_slice(key.as_ref())?)
}

fn context(id: &str) -> Vec<u8> {
    keyless_core::crypto::context("generator-history", &[id])
}

/// Remembers a password that was used. The same password twice in a row is
/// kept once.
pub fn remember(state: &AppState, session: &Session, password: &str, site: Option<&str>) -> AppResult<()> {
    if password.is_empty() || password.len() > 1024 {
        return Ok(());
    }
    let key = key(&session.account)?;
    let store = state.store();
    if let Some((id, data, _)) = store.generated_entries(1)?.into_iter().next()
        && let Ok(plain) = key.open(&data, &context(&id))
        && serde_json::from_slice::<Sealed>(&plain).is_ok_and(|last| last.password == password)
    {
        return Ok(());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let sealed = Sealed { password: password.to_string(), site: site.map(str::to_string) };
    let plain = Zeroizing::new(serde_json::to_vec(&sealed).map_err(|e| AppError::Server(e.to_string()))?);
    let data = key.seal(&plain, &context(&id))?;
    store.add_generated(&id, &data, now_secs(), MAX_ENTRIES)
}

/// Newest first. Entries that cannot be read (another account's) are skipped.
pub fn list(state: &AppState, session: &Session) -> AppResult<Vec<Entry>> {
    let key = key(&session.account)?;
    let rows = state.store().generated_entries(MAX_ENTRIES)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, data, created_at)| {
            let plain = key.open(&data, &context(&id)).ok()?;
            let sealed: Sealed = serde_json::from_slice(&plain).ok()?;
            Some(Entry { id, password: sealed.password, site: sealed.site, created_at })
        })
        .collect())
}
