//! Importing from 1Password (.1pux) and CSV exports.
//!
//! The file is chosen in a native dialog opened from Rust, so the UI never
//! supplies file paths. Parsed items are held in memory (wiped on lock)
//! until the user confirms.

use std::io::Read;

use keyless_core::{
    import::{ImportResult, ImportSummary, csv::parse_csv, onepux::parse_1pux},
    vault::VaultMeta,
};
use serde::Deserialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::{
    error::{AppError, AppResult, Msg},
    items,
    state::AppState,
    sync,
};

const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    OnePux,
    Csv,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ImportTarget {
    /// Recreate the source vaults as new Keyless vaults.
    NewVaults,
    /// Put everything into one existing vault.
    Vault {
        #[serde(rename = "vaultId")]
        vault_id: String,
    },
}

pub async fn pick_and_parse(app: &AppHandle, format: ImportFormat) -> AppResult<ImportSummary> {
    let state = app.state::<AppState>();
    if state.session.lock().await.is_none() {
        return Err(AppError::Locked);
    }
    let dialog = app.dialog().file().set_title("Choose a file to import");
    let dialog = match format {
        ImportFormat::OnePux => dialog.add_filter("1Password export", &["1pux"]),
        ImportFormat::Csv => dialog.add_filter("CSV file", &["csv"]),
    };
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_pick_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unreadable")))?;

    let result = tauri::async_runtime::spawn_blocking(move || -> AppResult<ImportResult> {
        let file = std::fs::File::open(&path).map_err(|e| AppError::Invalid(Msg::new("file_unreadable").with("detail", e)))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if size > MAX_FILE_BYTES {
            return Err(AppError::Invalid(Msg::new("file_too_large")));
        }
        match format {
            ImportFormat::OnePux => Ok(parse_1pux(file)?),
            ImportFormat::Csv => {
                let mut contents = Zeroizing::new(Vec::new());
                file.take(MAX_FILE_BYTES).read_to_end(&mut contents).map_err(|e| AppError::Invalid(Msg::new("file_unreadable").with("detail", e)))?;
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| format!("Imported ({s})"))
                    .unwrap_or_else(|| "Imported".into());
                Ok(parse_csv(contents.as_slice(), &name)?)
            }
        }
    })
    .await
    .map_err(|e| AppError::Store(e.to_string()))??;

    let summary = result.summary();
    if summary.total_items == 0 {
        return Err(AppError::Invalid(Msg::new("import_empty")));
    }
    *state.pending_import.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
    Ok(summary)
}

pub async fn commit(app: &AppHandle, target: ImportTarget) -> AppResult<usize> {
    let state = app.state::<AppState>();
    let pending = state
        .pending_import
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| AppError::Invalid(Msg::new("import_no_file")))?;

    let mut total = 0;
    for vault in pending.vaults {
        if vault.items.is_empty() {
            continue;
        }
        let vault_id = match &target {
            ImportTarget::NewVaults => {
                items::create_vault(app, VaultMeta { name: vault.name.clone(), ..Default::default() }).await?
            }
            ImportTarget::Vault { vault_id } => vault_id.clone(),
        };
        {
            let guard = state.session.lock().await;
            let session = guard.as_ref().ok_or(AppError::Locked)?;
            if !session.vault(&vault_id)?.can_write() {
                return Err(AppError::Invalid(Msg::new("vault_read_only")));
            }
        }
        let batch = vault.items.into_iter().map(|i| (i.overview, i.details)).collect();
        total += items::insert_imported(&state, &vault_id, batch).await?;
    }
    sync::spawn_sync(app);
    Ok(total)
}

pub fn cancel(state: &AppState) {
    *state.pending_import.lock().unwrap_or_else(|e| e.into_inner()) = None;
}
