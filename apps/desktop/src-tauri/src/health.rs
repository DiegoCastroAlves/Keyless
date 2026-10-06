//! Password health ("Watchtower"): weak, reused and breached passwords.
//!
//! Weak and reused checks run locally. The breach check uses the Have I Been
//! Pwned range API with k-anonymity: only the first 5 hex characters of each
//! password's SHA-1 hash are sent, and responses are padded, so the service
//! never learns the password or even which hash was looked up.

use std::collections::{HashMap, HashSet};

use keyless_core::item::FieldPurpose;
use serde::Serialize;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
    pub guesses_log10: f64,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    pub checked: usize,
    pub weak: Vec<String>,
    /// Groups of item ids that share the same password.
    pub reused: Vec<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachReport {
    pub checked: usize,
    /// Item ids whose password appears in known breaches, with the count.
    pub breached: Vec<(String, u64)>,
}

pub fn strength(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength { score: 0, guesses_log10: 0.0, warning: None, suggestions: vec![] };
    }
    // zxcvbn is quadratic in length; anything this long is strong anyway.
    let sample: String = password.chars().take(100).collect();
    let entropy = zxcvbn::zxcvbn(&sample, user_inputs);
    Strength {
        score: entropy.score() as u8,
        guesses_log10: entropy.guesses_log10(),
        warning: entropy.feedback().and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: entropy
            .feedback()
            .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

/// Collects `(item_id, password)` for every active item with a password.
async fn passwords(state: &AppState) -> AppResult<Vec<(String, Zeroizing<String>)>> {
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let store = state.store();
    let mut out = Vec::new();
    for (id, cached) in &session.items {
        if cached.overview.trashed_at.is_some() || cached.overview.archived {
            continue;
        }
        let Some(local) = store.item(id)? else { continue };
        let (Some(enc), Ok(vault)) = (local.enc_details.as_deref(), session.vault(&local.vault_id)) else {
            continue;
        };
        let Ok(details) = vault.key.open_details(&local.vault_id, id, enc) else { continue };
        if let Some(field) = details.field_by_purpose(FieldPurpose::Password)
            && !field.value.is_empty()
        {
            out.push((id.clone(), Zeroizing::new(field.value.clone())));
        }
    }
    Ok(out)
}

pub async fn report(state: &AppState) -> AppResult<HealthReport> {
    let entries = passwords(state).await?;
    let mut report = HealthReport { checked: entries.len(), ..Default::default() };
    let mut by_password: HashMap<&str, Vec<String>> = HashMap::new();
    for (id, password) in &entries {
        if strength(password, &[]).score < 3 {
            report.weak.push(id.clone());
        }
        by_password.entry(password.as_str()).or_default().push(id.clone());
    }
    report.reused = by_password.into_values().filter(|ids| ids.len() > 1).collect();
    Ok(report)
}

pub async fn breaches(state: &AppState) -> AppResult<BreachReport> {
    let entries = passwords(state).await?;
    let mut hashes: HashMap<String, Vec<String>> = HashMap::new();
    for (id, password) in &entries {
        let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
        hashes.entry(hash).or_default().push(id.clone());
    }
    let prefixes: HashSet<String> = hashes.keys().map(|h| h[..5].to_string()).collect();

    let client = reqwest::Client::builder()
        .https_only(true)
        .user_agent(concat!("Keyless/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Server(e.to_string()))?;
    let mut breached = Vec::new();
    for prefix in prefixes {
        let body = client
            .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
            .header("Add-Padding", "true")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        for line in body.lines() {
            let Some((suffix, count)) = line.trim().split_once(':') else { continue };
            let count: u64 = count.trim().parse().unwrap_or(0);
            if count == 0 {
                continue; // padding entries
            }
            if let Some(ids) = hashes.get(&format!("{prefix}{}", suffix.trim())) {
                breached.extend(ids.iter().map(|id| (id.clone(), count)));
            }
        }
    }
    Ok(BreachReport { checked: entries.len(), breached })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_scores() {
        assert!(strength("password", &[]).score <= 1);
        assert!(strength("correct-horse-battery-staple-91", &[]).score >= 3);
        assert_eq!(strength("", &[]).score, 0);
    }
}
