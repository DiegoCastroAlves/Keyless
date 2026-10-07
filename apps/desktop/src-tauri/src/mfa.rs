//! Two-step verification for the Keyless account (see the `account_2fa`
//! migration): a TOTP factor in Supabase Auth, asked for when signing in on
//! a device (unlocking stays local and needs only the master password), and
//! recovery codes for losing the authenticator app. A recovery code only
//! replaces the code: the master password and Secret Key are still needed,
//! and using one turns two-step verification off until it is set up again.

use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keyless_core::keys::{AccountKeys, KdfParams, SecretKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    api::{AuthSession, now_secs},
    error::{AppError, AppResult, Msg},
    state::AppState,
    sync,
};

/// How long a sign-in waits for its code.
const PENDING_FOR: Duration = Duration::from_secs(10 * 60);
const RECOVERY_CODES: usize = 10;
/// Crockford's base32: no I, L, O or U to misread.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A sign-in whose password was accepted and that waits for the second step.
pub struct Pending {
    email: String,
    kdf: KdfParams,
    keys: AccountKeys,
    secret_key: SecretKey,
    auth: AuthSession,
    factor_id: String,
    at: Instant,
}

/// The claim `name` of an access token (not verified: only to know what to
/// ask; the server checks the token).
fn claim(token: &str, name: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?).ok()?;
    json.get(name)?.as_str().map(String::from)
}

/// The verified factor a new session still has to prove, if any.
pub async fn factor_to_prove(state: &AppState, auth: &AuthSession) -> AppResult<Option<String>> {
    if claim(&auth.access_token, "aal").as_deref() == Some("aal2") {
        return Ok(None);
    }
    let factors = state.api.mfa_factors(&auth.access_token).await?;
    Ok(factors.into_iter().find(|f| f.status == "verified" && f.factor_type == "totp").map(|f| f.id))
}

/// Keeps a sign-in until the user gives the second step.
pub async fn hold(state: &AppState, email: String, kdf: KdfParams, keys: AccountKeys, secret_key: SecretKey, auth: AuthSession, factor_id: String) {
    *state.pending_mfa.lock().await = Some(Pending { email, kdf, keys, secret_key, auth, factor_id, at: Instant::now() });
}

pub async fn cancel(state: &AppState) {
    state.pending_mfa.lock().await.take();
}

/// What the user gave for the second step.
pub enum Proof {
    Code(String),
    RecoveryCode(String),
}

/// Finishes the sign-in waiting for its second step. Returns whether a
/// recovery code was used (which turned two-step verification off).
pub async fn finish_sign_in(app: &AppHandle, proof: Proof) -> AppResult<bool> {
    let state = app.state::<AppState>();
    // Wrong codes count like wrong passwords.
    let _busy = state.begin_unlock()?;
    let pending = state
        .pending_mfa
        .lock()
        .await
        .take()
        .filter(|p| p.at.elapsed() < PENDING_FOR)
        .ok_or_else(|| AppError::Invalid(Msg::new("mfa_expired")))?;
    let verified = match &proof {
        Proof::Code(code) => {
            let digits: String = code.chars().filter(char::is_ascii_digit).collect();
            state.api.mfa_verify(&pending.auth.access_token, &pending.factor_id, &digits).await.map(Some)
        }
        Proof::RecoveryCode(code) => match state.api.use_recovery_code(&pending.auth.access_token, &normalize_code(code)).await {
            Ok(true) => Ok(None),
            Ok(false) => Err(AppError::Invalid(Msg::new("recovery_code_invalid"))),
            Err(err) => Err(err),
        },
    };
    let verified = match verified {
        Ok(verified) => verified,
        Err(err) => {
            if matches!(err, AppError::Invalid(_)) {
                state.record_unlock_result(false);
            }
            // Another try with the same sign-in.
            *state.pending_mfa.lock().await = Some(pending);
            return Err(err);
        }
    };
    // A recovery code keeps the first session: it no longer needs the step.
    let recovered = verified.is_none();
    let Pending { email, kdf, keys, secret_key, auth, .. } = pending;
    state.secrets.save_secret_key(&email, &secret_key)?;
    crate::auth::complete_sign_in(app, &email, kdf, keys, verified.unwrap_or(auth)).await?;
    Ok(recovered)
}

// ----- settings ----------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub enabled: bool,
    pub recovery_codes_left: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub factor_id: String,
    /// The QR code to scan, an SVG data URL.
    pub qr_code: String,
    /// The same secret, for typing in by hand.
    pub secret: Zeroizing<String>,
}

pub async fn status(state: &AppState) -> AppResult<Status> {
    let (_, token) = sync::ensure_token(state).await?;
    let factors = state.api.mfa_factors(&token).await?;
    let enabled = factors.iter().any(|f| f.status == "verified");
    let recovery_codes_left = if enabled { state.api.recovery_codes_left(&token).await? } else { 0 };
    Ok(Status { enabled, recovery_codes_left })
}

/// Starts setting up the authenticator app: a new factor to confirm with a
/// code (see `activate`). Factors left half set up are removed first.
pub async fn enroll(state: &AppState) -> AppResult<Enrollment> {
    let (_, token) = sync::ensure_token(state).await?;
    let factors = state.api.mfa_factors(&token).await?;
    if factors.iter().any(|f| f.status == "verified") {
        return Err(AppError::Invalid(Msg::new("mfa_already_on")));
    }
    for factor in factors.iter().filter(|f| f.status != "verified") {
        state.api.mfa_unenroll(&token, &factor.id).await?;
    }
    let enrollment = state.api.mfa_enroll(&token, &format!("Keyless {}", now_secs())).await?;
    Ok(Enrollment { factor_id: enrollment.id, qr_code: qr_svg(&enrollment.totp.uri)?, secret: enrollment.totp.secret })
}

/// A QR code of `text`, as an SVG data URL.
fn qr_svg(text: &str) -> AppResult<String> {
    use qrcode::{QrCode, render::svg};
    let code = QrCode::new(text.as_bytes()).map_err(|e| AppError::Server(format!("QR code: {e}")))?;
    let svg = code.render::<svg::Color>().min_dimensions(240, 240).dark_color(svg::Color("#000000")).light_color(svg::Color("#ffffff")).build();
    Ok(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)))
}

/// Confirms the new factor with a code from the authenticator app. This
/// session now carries the second step; returns the recovery codes, shown
/// once.
pub async fn activate(state: &AppState, factor_id: &str, code: &str) -> AppResult<Vec<Zeroizing<String>>> {
    let (user_id, token) = sync::ensure_token(state).await?;
    let digits: String = code.chars().filter(char::is_ascii_digit).collect();
    let auth = state.api.mfa_verify(&token, factor_id, &digits).await?;
    sync::adopt_session(state, auth).await?;
    new_recovery_codes(state, &user_id).await
}

/// Replaces the recovery codes with new ones (the old stop working).
pub async fn regenerate(state: &AppState) -> AppResult<Vec<Zeroizing<String>>> {
    let (user_id, _) = sync::ensure_token(state).await?;
    new_recovery_codes(state, &user_id).await
}

async fn new_recovery_codes(state: &AppState, user_id: &str) -> AppResult<Vec<Zeroizing<String>>> {
    let codes: Vec<Zeroizing<String>> = (0..RECOVERY_CODES).map(|_| generate_code()).collect::<AppResult<_>>()?;
    let hashes: Vec<String> = codes.iter().map(|c| hash_code(user_id, &normalize_code(c))).collect();
    let (_, token) = sync::ensure_token(state).await?;
    state.api.set_recovery_codes(&token, &hashes).await?;
    Ok(codes)
}

/// Turns two-step verification off (after the master password).
pub async fn disable(state: &AppState, master_password: Zeroizing<String>) -> AppResult<()> {
    crate::auth::confirm_master_password(state, master_password).await?;
    let (_, token) = sync::ensure_token(state).await?;
    state.api.clear_recovery_codes(&token).await?;
    for factor in state.api.mfa_factors(&token).await? {
        state.api.mfa_unenroll(&token, &factor.id).await?;
    }
    Ok(())
}

/// A recovery code: 16 characters (80 bits), shown as XXXX-XXXX-XXXX-XXXX.
fn generate_code() -> AppResult<Zeroizing<String>> {
    let bytes = keyless_core::crypto::random_array::<10>()?;
    let mut bits: u128 = 0;
    for byte in bytes.iter() {
        bits = (bits << 8) | u128::from(*byte);
    }
    let mut code = Zeroizing::new(String::with_capacity(19));
    for i in 0..16 {
        if i > 0 && i % 4 == 0 {
            code.push('-');
        }
        let index = ((bits >> (75 - 5 * i)) & 31) as usize;
        code.push(ALPHABET[index] as char);
    }
    Ok(code)
}

/// A code as typed, the way it was generated: capitals, no separators, and
/// the letters people confuse with digits read as those digits.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

/// What the server keeps of a code (see the migration).
fn hash_code(user_id: &str, normalized: &str) -> String {
    hex::encode(Sha256::digest(format!("{user_id}:{normalized}").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_codes() {
        let code = generate_code().unwrap();
        assert_eq!(code.len(), 19);
        assert_eq!(code.matches('-').count(), 3);
        assert!(normalize_code(&code).chars().all(|c| ALPHABET.contains(&(c as u8))));
        assert_ne!(*generate_code().unwrap(), *code);
        assert_eq!(normalize_code("abcd-efgh ijkl-mnop"), "ABCDEFGH1JK1MN0P");
        // Same as the server: sha256(user id || ':' || code).
        assert_eq!(hash_code("u", "ABC"), hex::encode(Sha256::digest(b"u:ABC")));
    }

    #[test]
    fn qr_codes() {
        let url = qr_svg("otpauth://totp/Keyless:ana?secret=JBSWY3DPEHPK3PXP&issuer=Keyless").unwrap();
        assert!(url.starts_with("data:image/svg+xml;base64,"));
        let svg = base64::engine::general_purpose::STANDARD.decode(&url["data:image/svg+xml;base64,".len()..]).unwrap();
        assert!(String::from_utf8(svg).unwrap().contains("<svg"));
    }

    #[test]
    fn claims() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"aal":"aal2","sub":"x"}"#);
        assert_eq!(claim(&format!("h.{payload}.s"), "aal").as_deref(), Some("aal2"));
        assert_eq!(claim("garbage", "aal"), None);
    }
}
