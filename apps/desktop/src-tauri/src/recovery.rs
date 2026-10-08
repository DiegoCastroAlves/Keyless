//! Account recovery keys (see `keyless_core::recovery` and the
//! `recovery_key` migration). One is made, replaced or removed in
//! Settings > Account (always with the master password), and used on the
//! sign-in screen when the master password is forgotten or the Secret Key
//! lost:
//!
//! 1. `begin`: the server checks the key's proof and returns the user key it
//!    keeps encrypted with the recovery key; the account opens in memory.
//! 2. `prepare`: a new master password, a new Secret Key and the next
//!    recovery key are made, and shown for the user to save.
//! 3. `finish`: only then are they sent, and the device signs in. Should the
//!    answer get lost, the user already has what the server now expects.

use std::time::{Duration, Instant};

use keyless_core::{
    account::{AccountBundle, UnlockedAccount, rewrap_account, unlock_account},
    keys::{AccountKeys, KdfParams, SecretKey},
    recovery::RecoveryKey,
};
use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    auth,
    error::{AppError, AppResult, Msg},
    state::AppState,
    sync,
};

/// How long a recovery may wait between its steps.
const PENDING_FOR: Duration = Duration::from_secs(15 * 60);

/// A recovery between its steps: the account is open in memory.
pub struct PendingRecovery {
    email: String,
    user_id: String,
    proof: Zeroizing<String>,
    bundle: AccountBundle,
    account: UnlockedAccount,
    started: Instant,
    prepared: Option<Prepared>,
}

/// The new credentials, shown but not sent yet.
struct Prepared {
    kdf: KdfParams,
    keys: AccountKeys,
    secret_key: SecretKey,
    new_bundle: AccountBundle,
    next_key: RecoveryKey,
    next_enc_user_key: String,
}

/// Drops whatever recovery state is in memory (on lock and sign-out).
pub fn forget(state: &AppState) {
    *state.pending_recovery.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *state.shown_recovery_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// When the signed-in account's recovery key was made, if it has one.
pub async fn status(state: &AppState) -> AppResult<Option<String>> {
    let (_, token) = sync::ensure_token(state).await?;
    state.api.recovery_key_created(&token).await
}

/// Makes a recovery key for the signed-in account, replacing any other.
/// Returns it to be shown; it stays available for copying until hidden.
pub async fn create(app: &AppHandle, master_password: Zeroizing<String>) -> AppResult<Zeroizing<String>> {
    let state = app.state::<AppState>();
    let (local, keys, _) = auth::verify_master_password(&state, master_password).await?;
    let account = unlock_account(&local.bundle, &keys.kek, &local.user_id)?;
    let key = RecoveryKey::generate()?;
    let enc_user_key = key.wrap_user_key(&account, &local.user_id)?;
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.set_recovery_key(&token, &key.proof()?, &enc_user_key).await?;
    let display = key.to_display();
    *state.shown_recovery_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(display.clone());
    Ok(display)
}

pub async fn remove(app: &AppHandle, master_password: Zeroizing<String>) -> AppResult<()> {
    let state = app.state::<AppState>();
    auth::verify_master_password(&state, master_password).await?;
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.remove_recovery_key(&token).await
}

/// The text the recovery screens offer to copy: `"recovery_key"` (the one
/// just made, or the next one of a recovery) or `"secret_key"` (the new one
/// of a recovery).
pub fn copyable(state: &AppState, which: &str) -> AppResult<Zeroizing<String>> {
    let pending = state.pending_recovery.lock().unwrap_or_else(|e| e.into_inner());
    let prepared = pending.as_ref().and_then(|p| p.prepared.as_ref());
    match (which, prepared) {
        ("secret_key", Some(prepared)) => Ok(prepared.secret_key.to_display()),
        ("recovery_key", Some(prepared)) => Ok(prepared.next_key.to_display()),
        ("recovery_key", None) => state
            .shown_recovery_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(AppError::NotFound),
        _ => Err(AppError::NotFound),
    }
}

pub fn hide(state: &AppState) {
    *state.shown_recovery_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Step 1: checks `recovery_key` for the account of `email` and opens it.
pub async fn begin(app: &AppHandle, email: &str, recovery_key: Zeroizing<String>) -> AppResult<()> {
    let state = app.state::<AppState>();
    let email = auth::normalize_email(email)?;
    if let Some(existing) = state.store().account()? {
        return Err(AppError::Invalid(Msg::new("device_other_account").with("email", &existing.email)));
    }
    let key = RecoveryKey::parse(&recovery_key).map_err(|_| AppError::Invalid(Msg::new("recovery_key_invalid")))?;
    let proof = key.proof()?;
    let start = state.api.begin_recovery(&email, &proof).await?;
    let bundle = AccountBundle {
        format: start.format,
        kdf: KdfParams::recommended(),
        enc_user_key: String::new(),
        public_key: start.public_key,
        enc_private_key: start.enc_private_key,
    };
    let account = key
        .open_account(&bundle, &start.enc_recovery_user_key, &start.user_id)
        .map_err(|_| AppError::Invalid(Msg::new("recovery_failed")))?;
    *state.pending_recovery.lock().unwrap_or_else(|e| e.into_inner()) = Some(PendingRecovery {
        email,
        user_id: start.user_id,
        proof,
        bundle,
        account,
        started: Instant::now(),
        prepared: None,
    });
    Ok(())
}

/// What the user saves before the recovery is sent.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepare {
    email: String,
    secret_key: String,
    recovery_key: String,
}

/// Step 2: makes the new credentials for `master_password` and returns what
/// to show.
pub async fn prepare(app: &AppHandle, master_password: Zeroizing<String>) -> AppResult<Prepare> {
    let state = app.state::<AppState>();
    let (email, user_id) = {
        let pending = state.pending_recovery.lock().unwrap_or_else(|e| e.into_inner());
        let pending = fresh(pending.as_ref())?;
        (pending.email.clone(), pending.user_id.clone())
    };
    auth::validate_new_master_password(&master_password, &email)?;
    let kdf = KdfParams::recommended();
    let (keys, secret_key) = auth::derive(master_password, SecretKey::generate()?, kdf.clone()).await?;

    let mut guard = state.pending_recovery.lock().unwrap_or_else(|e| e.into_inner());
    let pending = guard.as_mut().filter(|p| p.user_id == user_id).ok_or_else(expired)?;
    let new_bundle = rewrap_account(&pending.bundle, &pending.account, &keys.kek, kdf.clone(), &user_id)?;
    let next_key = RecoveryKey::generate()?;
    let next_enc_user_key = next_key.wrap_user_key(&pending.account, &user_id)?;
    let shown = Prepare { email, secret_key: secret_key.to_display().to_string(), recovery_key: next_key.to_display().to_string() };
    pending.prepared = Some(Prepared { kdf, keys, secret_key, new_bundle, next_key, next_enc_user_key });
    Ok(shown)
}

/// Step 3: sends the new credentials, then signs in with them. Returns
/// whether signing in worked (the recovery is done either way).
pub async fn finish(app: &AppHandle) -> AppResult<bool> {
    let state = app.state::<AppState>();
    let (email, proof, auth_secret, kdf, enc_user_key, next_proof, next_enc) = {
        let pending = state.pending_recovery.lock().unwrap_or_else(|e| e.into_inner());
        let pending = fresh(pending.as_ref())?;
        let prepared = pending.prepared.as_ref().ok_or_else(expired)?;
        (
            pending.email.clone(),
            pending.proof.clone(),
            prepared.keys.auth_secret.clone(),
            prepared.new_bundle.kdf.clone(),
            prepared.new_bundle.enc_user_key.clone(),
            prepared.next_key.proof()?,
            prepared.next_enc_user_key.clone(),
        )
    };
    state
        .api
        .complete_recovery(&email, &proof, &auth_secret, &kdf, &enc_user_key, &next_proof, &next_enc)
        .await?;

    let Some(pending) = state.pending_recovery.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return Ok(false);
    };
    let Some(prepared) = pending.prepared else { return Ok(false) };
    match auth::sign_in_with_keys(app, &email, prepared.kdf, prepared.keys, &prepared.secret_key).await {
        Ok(()) => Ok(true),
        Err(err) => {
            log::warn!("recovery: signing in afterwards failed: {err}");
            Ok(false)
        }
    }
}

fn fresh(pending: Option<&PendingRecovery>) -> AppResult<&PendingRecovery> {
    pending.filter(|p| p.started.elapsed() < PENDING_FOR).ok_or_else(expired)
}

fn expired() -> AppError {
    AppError::Invalid(Msg::new("recovery_expired"))
}
