//! Account flows: create, sign in, unlock, lock, sign out, change password.

use keyless_core::{
    account::{AccountBundle, UnlockedAccount, create_account as create_keys, rewrap_account, unlock_account},
    crypto::context,
    keys::{AccountKeys, KdfParams, SecretKey, derive_account_keys, normalize_master_password},
    vault::{VaultKey, VaultMeta},
};
use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::{
    api::{AuthSession, SignUpOutcome},
    error::{AppError, AppResult, Msg},
    state::{AppState, Session, SyncStatus, Tokens},
    store::LocalAccount,
    sync::{self, EVENT_LOCKED, load_caches},
};

const PENDING_EMAIL: &str = "pending_email";
pub const MIN_MASTER_PASSWORD_CHARS: usize = 10;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    /// "no_account", "locked" or "unlocked".
    pub state: &'static str,
    pub email: Option<String>,
    /// Email of an account created on this device that still needs its first
    /// sign-in (e.g. waiting for email confirmation).
    pub pending_email: Option<String>,
    /// Whether this device already has the Secret Key for `pending_email`.
    pub has_secret_key: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedAccount {
    pub secret_key: String,
    pub confirmation_required: bool,
}

pub fn normalize_email(email: &str) -> AppResult<String> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        })
        && !email.chars().any(char::is_whitespace);
    if valid { Ok(email) } else { Err(AppError::Invalid(Msg::new("email_invalid"))) }
}

/// Minimum zxcvbn score (0-4) for a new master password.
pub const MIN_MASTER_PASSWORD_SCORE: u8 = 3;

pub fn validate_new_master_password(password: &str, email: &str) -> AppResult<()> {
    let normalized = normalize_master_password(password);
    if normalized.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(AppError::Invalid(Msg::new("password_too_short").with("min", MIN_MASTER_PASSWORD_CHARS)));
    }
    let local_part = email.split('@').next().unwrap_or("");
    if crate::health::strength(&normalized, &[local_part, "keyless"]).score < MIN_MASTER_PASSWORD_SCORE {
        return Err(AppError::Invalid(Msg::new("password_weak")));
    }
    Ok(())
}

/// Runs the (deliberately slow) key derivation off the async runtime.
async fn derive(master_password: Zeroizing<String>, secret_key: SecretKey, kdf: KdfParams) -> AppResult<(AccountKeys, SecretKey)> {
    tauri::async_runtime::spawn_blocking(move || {
        derive_account_keys(&master_password, &secret_key, &kdf).map(|keys| (keys, secret_key))
    })
    .await
    .map_err(|e| AppError::Store(e.to_string()))?
    .map_err(AppError::from)
}

pub async fn status(state: &AppState) -> AppResult<AppStatus> {
    let unlocked_email = state.session.lock().await.as_ref().map(|s| s.email.clone());
    let store = state.store();
    let account = store.account()?;
    let pending_email: Option<String> = store.setting(PENDING_EMAIL)?;
    drop(store);
    let has_secret_key = match pending_email.as_ref().or(account.as_ref().map(|a| &a.email)) {
        Some(email) => state.secrets.load_secret_key(email).ok().flatten().is_some(),
        None => false,
    };
    Ok(AppStatus {
        state: if unlocked_email.is_some() {
            "unlocked"
        } else if account.is_some() {
            "locked"
        } else {
            "no_account"
        },
        email: unlocked_email.or(account.map(|a| a.email)),
        pending_email,
        has_secret_key,
    })
}

pub async fn create_account(app: &AppHandle, email: &str, master_password: Zeroizing<String>) -> AppResult<CreatedAccount> {
    let state = app.state::<AppState>();
    let email = normalize_email(email)?;
    validate_new_master_password(&master_password, &email)?;
    if state.store().account()?.is_some() {
        return Err(AppError::Invalid(Msg::new("device_has_account")));
    }

    let kdf = KdfParams::recommended();
    let (keys, secret_key) = derive(master_password, SecretKey::generate()?, kdf.clone()).await?;
    let display = secret_key.to_display();

    let outcome = state.api.sign_up(&email, &keys.auth_secret).await?;
    // Only keep the Secret Key once the server accepted the sign-up.
    state.secrets.save_secret_key(&email, &secret_key)?;
    state.store().set_setting(PENDING_EMAIL, &email)?;

    let confirmation_required = match outcome {
        SignUpOutcome::Session(auth) => {
            complete_sign_in(app, &email, kdf, keys, auth).await?;
            false
        }
        SignUpOutcome::ConfirmationRequired => true,
    };
    Ok(CreatedAccount { secret_key: display.to_string(), confirmation_required })
}

/// Creates the account for an email proven with Google (see `oauth`). The
/// Google session is used once, to set the secret derived from the new master
/// password and Secret Key; the account then signs in with that secret like
/// any other.
pub async fn create_account_with_google(app: &AppHandle, master_password: Zeroizing<String>) -> AppResult<CreatedAccount> {
    let state = app.state::<AppState>();
    let mut slot = state.pending_google.lock().await;
    let email = slot
        .as_ref()
        .map(|p| p.email.clone())
        .ok_or_else(|| AppError::Auth(Msg::new("google_session_expired")))?;
    let email = normalize_email(&email)?;
    validate_new_master_password(&master_password, &email)?;
    if state.store().account()?.is_some() {
        return Err(AppError::Invalid(Msg::new("device_has_account")));
    }
    let Some(pending) = slot.take() else {
        return Err(AppError::Auth(Msg::new("google_session_expired")));
    };
    drop(slot);

    let mut google = pending.session;
    if google.expires_at - 60 <= crate::api::now_secs() {
        google = state
            .api
            .refresh(&google.refresh_token)
            .await
            .map_err(|_| AppError::Auth(Msg::new("google_session_expired")))?;
    }

    let kdf = KdfParams::recommended();
    let (keys, secret_key) = derive(master_password, SecretKey::generate()?, kdf.clone()).await?;
    let display = secret_key.to_display();
    state.api.update_auth_secret(&google.access_token, &keys.auth_secret).await?;
    // Only keep the Secret Key once the server accepted the new secret.
    state.secrets.save_secret_key(&email, &secret_key)?;
    state.store().set_setting(PENDING_EMAIL, &email)?;
    let _ = state.api.sign_out(&google.access_token).await;

    let auth = state.api.sign_in(&email, &keys.auth_secret).await?;
    complete_sign_in(app, &email, kdf, keys, auth).await?;
    Ok(CreatedAccount { secret_key: display.to_string(), confirmation_required: false })
}

pub async fn sign_in(app: &AppHandle, email: &str, secret_key: Option<String>, master_password: Zeroizing<String>) -> AppResult<()> {
    let state = app.state::<AppState>();
    let _busy = state.begin_unlock()?;
    let email = normalize_email(email)?;
    let secret_key = match secret_key.map(Zeroizing::new).filter(|s| !s.trim().is_empty()) {
        Some(input) => SecretKey::parse(&input)
            .map_err(|_| AppError::Invalid(Msg::new("secret_key_invalid")))?,
        None => state
            .secrets
            .load_secret_key(&email)?
            .ok_or_else(|| AppError::Invalid(Msg::new("secret_key_required")))?,
    };
    if let Some(existing) = state.store().account()?
        && existing.email != email
    {
        return Err(AppError::Invalid(Msg::new("device_other_account").with("email", &existing.email)));
    }

    let kdf = KdfParams::recommended();
    let (keys, secret_key) = derive(master_password, secret_key, kdf.clone()).await?;
    let auth = match state.api.sign_in(&email, &keys.auth_secret).await {
        Ok(auth) => auth,
        Err(err) => {
            if matches!(err, AppError::Auth(_)) {
                state.record_unlock_result(false);
            }
            return Err(err);
        }
    };
    state.secrets.save_secret_key(&email, &secret_key)?;
    complete_sign_in(app, &email, kdf, keys, auth).await
}

/// Called after the server accepted our auth secret: fetch (or create) the
/// account keys, cache everything locally and open a session.
async fn complete_sign_in(app: &AppHandle, email: &str, kdf: KdfParams, keys: AccountKeys, auth: AuthSession) -> AppResult<()> {
    let state = app.state::<AppState>();
    let token = auth.access_token.clone();
    let user_id = auth.user_id.clone();

    let (bundle, account) = match state.api.profile(&token, &user_id).await? {
        None => {
            // This device already holds keys for this account: never replace
            // them because the server claims there are none.
            if state.store().account()?.is_some_and(|a| a.user_id == user_id) {
                return Err(AppError::Auth(Msg::new("account_keys_missing")));
            }
            initialize_remote_account(&state, &token, &user_id, &keys, kdf).await?
        }
        Some(profile) => match unlock_account(&profile.bundle(), &keys.kek, &user_id) {
            Ok(account) => (profile.bundle(), account),
            Err(_) => {
                // A master password change may have been interrupted after the
                // sign-in secret was updated: finish it now.
                let pending = profile
                    .pending_bundle()
                    .ok_or_else(|| AppError::Auth(Msg::new("account_keys_undecryptable")))?;
                let account = unlock_account(&pending, &keys.kek, &user_id)?;
                state
                    .api
                    .update_profile(
                        &token,
                        &user_id,
                        json!({
                            "kdf": pending.kdf,
                            "enc_user_key": pending.enc_user_key,
                            "pending_kdf": null,
                            "pending_enc_user_key": null,
                        }),
                    )
                    .await?;
                (pending, account)
            }
        },
    };

    let session_ctx = context("local-session", &[&user_id]);
    let enc_session = account.user_key().seal(auth.refresh_token.as_bytes(), &session_ctx)?;
    let local = LocalAccount {
        user_id: user_id.clone(),
        email: email.to_string(),
        server_url: state.api.server_url(),
        bundle,
        enc_session: Some(enc_session),
    };

    let mut session = Session {
        user_id,
        email: email.to_string(),
        account,
        vaults: Default::default(),
        items: Default::default(),
        tokens: Some(Tokens::from(auth)),
        unreadable_items: 0,
    };
    {
        let store = state.store();
        if let Some(existing) = store.account()?
            && existing.user_id != local.user_id
        {
            store.wipe_account_data()?;
        }
        store.save_account(&local)?;
        store.delete_setting(PENDING_EMAIL)?;
        load_caches(&mut session, &store)?;
    }
    *state.session.lock().await = Some(session);
    state.record_unlock_result(true);
    state.touch();

    // First sign-in on a device: wait for the data so the UI is not empty.
    if let Err(err) = sync::sync_now(app).await {
        log::warn!("initial sync failed: {err}");
    }
    ensure_default_vault(app).await
}

/// Every account needs at least one vault it owns. Creates "Personal" if the
/// server has none (e.g. a first sign-in that was interrupted).
async fn ensure_default_vault(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let has_vault = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        session.vaults.values().any(|v| v.role == "owner")
    };
    if has_vault || state.sync_status().state != "idle" {
        // Unknown state when the last sync failed: do not create duplicates.
        return Ok(());
    }
    let meta = VaultMeta { name: "Personal".into(), icon: "user".into(), ..Default::default() };
    crate::items::create_vault(app, meta).await?;
    let _ = app.emit(sync::EVENT_ITEMS_CHANGED, ());
    Ok(())
}

async fn initialize_remote_account(
    state: &AppState,
    token: &str,
    user_id: &str,
    keys: &AccountKeys,
    kdf: KdfParams,
) -> AppResult<(AccountBundle, UnlockedAccount)> {
    let (bundle, account) = create_keys(&keys.kek, kdf, user_id)?;
    if let Err(err) = state.api.insert_profile(token, user_id, &bundle).await {
        // Another device may have initialised the account at the same time.
        if let Some(profile) = state.api.profile(token, user_id).await? {
            let account = unlock_account(&profile.bundle(), &keys.kek, user_id)?;
            return Ok((profile.bundle(), account));
        }
        return Err(err);
    }

    let vault_id = uuid::Uuid::new_v4().to_string();
    let vault_key = VaultKey::generate()?;
    let meta = VaultMeta { name: "Personal".into(), icon: "user".into(), ..Default::default() };
    let enc_meta = vault_key.seal_meta(&vault_id, &meta)?;
    let enc_vault_key = vault_key.wrap(account.user_key(), &vault_id)?;
    state.api.create_vault(token, &vault_id, &enc_meta, &enc_vault_key).await?;
    Ok((bundle, account))
}

pub async fn unlock(app: &AppHandle, master_password: Zeroizing<String>) -> AppResult<()> {
    let state = app.state::<AppState>();
    let _busy = state.begin_unlock()?;
    let local = state.store().account()?.ok_or(AppError::NoAccount)?;
    let secret_key = state.secrets.load_secret_key(&local.email)?.ok_or_else(|| {
        AppError::Auth(Msg::new("secret_key_missing"))
    })?;

    let (keys, secret_key) = derive(master_password, secret_key, local.bundle.kdf.clone()).await?;
    match unlock_account(&local.bundle, &keys.kek, &local.user_id) {
        Ok(account) => {
            let mut session = Session {
                user_id: local.user_id.clone(),
                email: local.email.clone(),
                account,
                vaults: Default::default(),
                items: Default::default(),
                tokens: None,
                unreadable_items: 0,
            };
            load_caches(&mut session, &state.store())?;
            *state.session.lock().await = Some(session);
            state.record_unlock_result(true);
            state.touch();
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                match sync::sync_now(&app).await {
                    Ok(()) => {
                        if let Err(err) = ensure_default_vault(&app).await {
                            log::warn!("could not create the default vault: {err}");
                        }
                    }
                    Err(err) => log::info!("sync after unlock: {err}"),
                }
            });
            Ok(())
        }
        Err(_) => {
            // The master password may have been changed on another device:
            // the server knows the new one.
            match state.api.sign_in(&local.email, &keys.auth_secret).await {
                Ok(auth) => {
                    let _ = secret_key;
                    complete_sign_in(app, &local.email, local.bundle.kdf.clone(), keys, auth).await
                }
                Err(_) => {
                    state.record_unlock_result(false);
                    Err(AppError::WrongPassword)
                }
            }
        }
    }
}

/// Re-authenticates with the server when the stored session expired.
pub async fn reauthenticate(app: &AppHandle, master_password: Zeroizing<String>) -> AppResult<()> {
    let state = app.state::<AppState>();
    let email = state
        .session
        .lock()
        .await
        .as_ref()
        .map(|s| s.email.clone())
        .ok_or(AppError::Locked)?;
    sign_in(app, &email, None, master_password).await
}

pub async fn lock(app: &AppHandle) {
    let state = app.state::<AppState>();
    let was_unlocked = state.session.lock().await.take().is_some();
    state.clipboard.clear_now();
    *state.pending_import.lock().unwrap_or_else(|e| e.into_inner()) = None;
    if was_unlocked {
        let _ = app.emit(EVENT_LOCKED, ());
    }
}

pub async fn sign_out(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let session = state.session.lock().await.take();
    if let Some(tokens) = session.as_ref().and_then(|s| s.tokens.as_ref()) {
        let _ = state.api.sign_out(&tokens.access).await;
    }
    let store = state.store();
    let email = store.account()?.map(|a| a.email).or(store.setting::<String>(PENDING_EMAIL)?);
    if let Some(email) = email {
        state.secrets.delete_secret_key(&email);
    }
    store.wipe_account_data()?;
    store.delete_setting(PENDING_EMAIL)?;
    drop(store);
    state.clipboard.clear_now();
    *state.pending_import.lock().unwrap_or_else(|e| e.into_inner()) = None;
    state.set_sync_status(SyncStatus::default());
    let _ = app.emit(EVENT_LOCKED, ());
    Ok(())
}

/// Verifies the master password against the local account keys.
async fn verify_master_password(state: &AppState, master_password: Zeroizing<String>) -> AppResult<(LocalAccount, AccountKeys, SecretKey)> {
    let local = state.store().account()?.ok_or(AppError::NoAccount)?;
    let secret_key = state.secrets.load_secret_key(&local.email)?.ok_or(AppError::NoAccount)?;
    let (keys, secret_key) = derive(master_password, secret_key, local.bundle.kdf.clone()).await?;
    unlock_account(&local.bundle, &keys.kek, &local.user_id).map_err(|_| AppError::WrongPassword)?;
    Ok((local, keys, secret_key))
}

/// Shows the Secret Key after re-entering the master password (throttled
/// like unlocking).
pub async fn reveal_secret_key(state: &AppState, master_password: Zeroizing<String>) -> AppResult<String> {
    if state.session.lock().await.is_none() {
        return Err(AppError::Locked);
    }
    let _busy = state.begin_unlock()?;
    match verify_master_password(state, master_password).await {
        Ok((_, _, key)) => {
            state.record_unlock_result(true);
            Ok(key.to_display().to_string())
        }
        Err(err) => {
            if matches!(err, AppError::WrongPassword) {
                state.record_unlock_result(false);
            }
            Err(err)
        }
    }
}

/// Copies the Secret Key of this device's account (or of an account waiting
/// for email confirmation) with the protected clipboard. Used by the
/// Emergency Kit right after sign-up, before there is a session.
pub fn secret_key_for_kit(state: &AppState) -> AppResult<Zeroizing<String>> {
    let store = state.store();
    let email = match store.account()? {
        Some(account) => account.email,
        None => store.setting::<String>(PENDING_EMAIL)?.ok_or(AppError::NoAccount)?,
    };
    drop(store);
    let key = state.secrets.load_secret_key(&email)?.ok_or(AppError::NotFound)?;
    Ok(key.to_display())
}

pub async fn change_master_password(app: &AppHandle, current: Zeroizing<String>, new: Zeroizing<String>) -> AppResult<()> {
    let state = app.state::<AppState>();
    let email = state.store().account()?.map(|a| a.email).unwrap_or_default();
    validate_new_master_password(&new, &email)?;
    let (local, current_keys, secret_key) = verify_master_password(&state, current).await?;
    let account = unlock_account(&local.bundle, &current_keys.kek, &local.user_id)?;
    let kdf = KdfParams::recommended();
    let (new_keys, _) = derive(new, secret_key, kdf.clone()).await?;
    let new_bundle = rewrap_account(&local.bundle, &account, &new_keys.kek, kdf, &local.user_id)?;

    let (user_id, token) = sync::ensure_token(&state).await?;
    // 1. Stage the new wrapping so a crash at any point stays recoverable.
    state
        .api
        .update_profile(
            &token,
            &user_id,
            json!({ "pending_kdf": new_bundle.kdf, "pending_enc_user_key": new_bundle.enc_user_key }),
        )
        .await?;
    // 2. Switch the sign-in secret. If that fails, drop the staged keys.
    if let Err(err) = state.api.update_auth_secret(&token, &new_keys.auth_secret).await {
        let _ = state
            .api
            .update_profile(&token, &user_id, json!({ "pending_kdf": null, "pending_enc_user_key": null }))
            .await;
        return Err(err);
    }
    // 3. Promote the staged keys.
    state
        .api
        .update_profile(
            &token,
            &user_id,
            json!({
                "kdf": new_bundle.kdf,
                "enc_user_key": new_bundle.enc_user_key,
                "pending_kdf": null,
                "pending_enc_user_key": null,
            }),
        )
        .await?;
    let mut updated = local;
    updated.bundle = new_bundle;
    state.store().save_account(&updated)?;
    Ok(())
}

/// Schedules the account for deletion in 7 days (cancellable by signing in
/// again) and signs this device out.
pub async fn delete_account(app: &AppHandle, master_password: Zeroizing<String>) -> AppResult<()> {
    let state = app.state::<AppState>();
    verify_master_password(&state, master_password).await?;
    let (_, token) = sync::ensure_token(&state).await?;
    state.api.delete_account(&token).await?;
    sign_out(app).await
}

/// Server-side account information for the UI.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub email: String,
    /// When the account will be deleted, if a deletion is scheduled.
    pub delete_after: Option<String>,
    /// The Secret Key is stored in a plain file (no OS credential store).
    pub secret_key_in_file: bool,
}

pub async fn account_info(state: &AppState) -> AppResult<AccountInfo> {
    let email = state
        .session
        .lock()
        .await
        .as_ref()
        .map(|s| s.email.clone())
        .ok_or(AppError::Locked)?;
    let secret_key_in_file = state.secrets.uses_fallback();
    let delete_after = match sync::ensure_token(state).await {
        Ok((user_id, token)) => state.api.profile(&token, &user_id).await.ok().flatten().and_then(|p| p.delete_after),
        Err(_) => None,
    };
    Ok(AccountInfo { email, delete_after, secret_key_in_file })
}

pub async fn cancel_account_deletion(state: &AppState) -> AppResult<()> {
    let (_, token) = sync::ensure_token(state).await?;
    state.api.cancel_account_deletion(&token).await
}

pub async fn resend_confirmation(state: &AppState, email: &str) -> AppResult<()> {
    let email = normalize_email(email)?;
    state.api.resend_confirmation(&email).await
}
