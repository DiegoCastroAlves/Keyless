//! Settings that follow the account to all its devices (for now, the
//! defaults of the passwords suggested in the browser). They are sealed with
//! a key derived from the account key and kept in the account's profile on
//! the server (`enc_settings`), which cannot read them; each device keeps a
//! copy in its local settings, for when it is locked or offline.
//!
//! The newest write wins: a device changing one sends them all.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use hkdf::Hkdf;
use keyless_core::{account::UnlockedAccount, crypto::SymmetricKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    error::{AppError, AppResult},
    state::AppState,
    sync,
};

/// The local copy, in the settings table.
const LOCAL: &str = "account_settings";
/// How often the server's copy is read again (after a sync).
const PULL_EVERY: Duration = Duration::from_secs(5 * 60);
static PULLED_AT: Mutex<Option<Instant>> = Mutex::new(None);

#[derive(Default, Serialize, Deserialize)]
struct Local {
    user_id: String,
    settings: Map<String, Value>,
    /// Changed here and not sent yet.
    #[serde(default)]
    pending: bool,
}

fn key(account: &UnlockedAccount) -> AppResult<SymmetricKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"keyless/account-settings/v1"), account.user_key().as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"seal", key.as_mut()).map_err(|_| AppError::Server("account settings key".into()))?;
    Ok(SymmetricKey::from_slice(key.as_ref())?)
}

fn context(user_id: &str) -> Vec<u8> {
    keyless_core::crypto::context("account-settings", &[user_id])
}

fn seal(account: &UnlockedAccount, user_id: &str, settings: &Map<String, Value>) -> AppResult<String> {
    let plain = Zeroizing::new(serde_json::to_vec(settings)?);
    Ok(key(account)?.seal_padded(&plain, &context(user_id))?)
}

fn open(account: &UnlockedAccount, user_id: &str, sealed: &str) -> AppResult<Map<String, Value>> {
    let plain = key(account)?.open_padded(sealed, &context(user_id))?;
    Ok(serde_json::from_slice(&plain)?)
}

/// The local copy, if it is this account's.
fn local(state: &AppState) -> Option<Local> {
    let account = state.store().account().ok().flatten()?;
    let kept: Local = state.store().setting(LOCAL).ok().flatten()?;
    (kept.user_id == account.user_id).then_some(kept)
}

/// A setting, as this device last saw it.
pub fn get(state: &AppState, name: &str) -> Option<Value> {
    local(state)?.settings.get(name).cloned()
}

/// Changes a setting (None removes it), here and then on the server (later,
/// if that fails now).
pub async fn set(app: &AppHandle, name: &str, value: Option<Value>) -> AppResult<()> {
    let state = app.state::<AppState>();
    let user_id = state.store().account()?.ok_or(AppError::NoAccount)?.user_id;
    let mut kept = local(&state).unwrap_or(Local { user_id, ..Default::default() });
    match value {
        Some(value) => kept.settings.insert(name.to_string(), value),
        None => kept.settings.remove(name),
    };
    kept.pending = true;
    state.store().set_setting(LOCAL, &kept)?;
    if let Err(err) = push(&state).await {
        log::info!("account settings: {err}");
    }
    Ok(())
}

/// Sends the local copy, if it changed here.
async fn push(state: &AppState) -> AppResult<()> {
    let Some(kept) = local(state).filter(|kept| kept.pending) else {
        return Ok(());
    };
    let sealed = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        seal(&session.account, &kept.user_id, &kept.settings)?
    };
    let (user_id, token) = sync::ensure_token(state).await?;
    state.api.update_profile(&token, &user_id, json!({ "enc_settings": sealed })).await?;
    // Sent, unless it changed again meanwhile.
    if let Some(mut now) = local(state)
        && now.settings == kept.settings
    {
        now.pending = false;
        state.store().set_setting(LOCAL, &now)?;
    }
    Ok(())
}

/// Brings the server's copy, now and then after a sync; sends this device's
/// first when it changed here.
pub async fn pull(app: &AppHandle) {
    {
        let mut at = PULLED_AT.lock().unwrap_or_else(|e| e.into_inner());
        if at.is_some_and(|at| at.elapsed() < PULL_EVERY) {
            return;
        }
        *at = Some(Instant::now());
    }
    let state = app.state::<AppState>();
    let result = async {
        if local(&state).is_some_and(|kept| kept.pending) {
            return push(&state).await;
        }
        let (user_id, token) = sync::ensure_token(&state).await?;
        let settings = match state.api.account_settings(&token, &user_id).await? {
            Some(sealed) => {
                let guard = state.session.lock().await;
                let session = guard.as_ref().ok_or(AppError::Locked)?;
                open(&session.account, &user_id, &sealed)?
            }
            None => Map::new(),
        };
        // Not over a change made here meanwhile.
        if local(&state).is_some_and(|kept| kept.pending) {
            return Ok(());
        }
        state.store().set_setting(LOCAL, &Local { user_id, settings, pending: false })?;
        Ok::<(), AppError>(())
    }
    .await;
    if let Err(err) = result {
        log::info!("account settings: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyless_core::{account::create_account, keys::KdfParams};

    #[test]
    fn sealed_for_the_account() {
        let (_, account) = create_account(&SymmetricKey::generate().unwrap(), KdfParams::recommended(), "user-1").unwrap();
        let mut settings = Map::new();
        settings.insert("suggestion".into(), json!({ "kind": "pin", "length": 6 }));
        let sealed = seal(&account, "user-1", &settings).unwrap();
        assert!(!sealed.contains("pin"));
        assert_eq!(open(&account, "user-1", &sealed).unwrap(), settings);
        // Bound to the account it was sealed for.
        assert!(open(&account, "user-2", &sealed).is_err());
    }
}
