//! Importing from 1Password (.1pux) and CSV exports.
//!
//! The file is chosen in a native dialog opened from Rust, so the UI never
//! supplies file paths. Parsed items are held in memory (wiped on lock)
//! until the user confirms.

use std::io::Read;

use keyless_core::{
    backup::{BackupData, BackupItem, BackupVault, MAX_BACKUP_BYTES, decrypt_backup, export_backup},
    import::{ImportResult, ImportSummary, csv::parse_csv, onepux::parse_1pux},
    vault::VaultMeta,
};
use serde::Deserialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::{
    api::now_secs,
    auth::MIN_MASTER_PASSWORD_CHARS,
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
    KeylessBackup,
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

pub async fn pick_and_parse(app: &AppHandle, format: ImportFormat, password: Option<Zeroizing<String>>) -> AppResult<ImportSummary> {
    let state = app.state::<AppState>();
    if state.session.lock().await.is_none() {
        return Err(AppError::Locked);
    }
    let dialog = app.dialog().file().set_title("Choose a file to import");
    let dialog = match format {
        ImportFormat::OnePux => dialog.add_filter("1Password export", &["1pux"]),
        ImportFormat::Csv => dialog.add_filter("CSV file", &["csv"]),
        ImportFormat::KeylessBackup => dialog.add_filter("Keyless backup", &["keyless"]),
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
            ImportFormat::KeylessBackup => {
                let password = password.ok_or_else(|| AppError::Invalid(Msg::new("backup_password_required")))?;
                let mut contents = Zeroizing::new(Vec::new());
                file.take(MAX_BACKUP_BYTES as u64 + 1)
                    .read_to_end(&mut contents)
                    .map_err(|e| AppError::Invalid(Msg::new("file_unreadable").with("detail", e)))?;
                match decrypt_backup(&password, &contents) {
                    Ok(data) => Ok(data.into_import()),
                    Err(keyless_core::Error::Decryption) => Err(AppError::Invalid(Msg::new("backup_wrong_password"))),
                    Err(err) => Err(err.into()),
                }
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

/// Exports every vault the user can read into an encrypted `.keyless` file.
/// Returns the number of items written, or `Cancelled` if no file was chosen.
pub async fn export(app: &AppHandle, master_password: Zeroizing<String>, password: Zeroizing<String>) -> AppResult<usize> {
    let state = app.state::<AppState>();
    // A backup holds every secret in the vault: ask for the master password
    // even when the vault was unlocked another way.
    crate::auth::confirm_master_password(&state, master_password).await?;
    // A backup has no Secret Key: its password alone protects it against
    // offline guessing, so it must be strong.
    let normalized = keyless_core::keys::normalize_master_password(&password);
    if normalized.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(AppError::Invalid(Msg::new("backup_password_too_short").with("min", MIN_MASTER_PASSWORD_CHARS)));
    }
    if crate::health::strength(&normalized, &["keyless"]).score < crate::auth::MIN_MASTER_PASSWORD_SCORE {
        return Err(AppError::Invalid(Msg::new("password_weak")));
    }

    let data = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        let store = state.store();
        let mut vaults: Vec<(String, BackupVault)> = session
            .vaults
            .iter()
            .map(|(id, v)| {
                (id.clone(), BackupVault { name: v.meta.name.clone(), description: v.meta.description.clone(), items: Vec::new() })
            })
            .collect();
        for item in store.items()? {
            let Some(cached) = session.items.get(&item.id) else { continue };
            if cached.overview.trashed_at.is_some() {
                continue;
            }
            let (Some(enc), Ok(vault)) = (item.enc_details.as_deref(), session.vault(&item.vault_id)) else { continue };
            let details = vault.key.open_details(&item.vault_id, &item.id, enc)?;
            if let Some((_, target)) = vaults.iter_mut().find(|(id, _)| *id == item.vault_id) {
                target.items.push(BackupItem { overview: cached.overview.clone(), details });
            }
        }
        BackupData { exported_at: now_secs(), vaults: vaults.into_iter().map(|(_, v)| v).collect() }
    };
    let count = data.vaults.iter().map(|v| v.items.len()).sum();

    let dialog = app
        .dialog()
        .file()
        .set_title("Save encrypted backup")
        .add_filter("Keyless backup", &["keyless"])
        .set_file_name(format!("keyless-backup-{}.keyless", today()));
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|e| AppError::Store(e.to_string()))?
        .ok_or(AppError::Cancelled)?;
    let path = picked.into_path().map_err(|_| AppError::Invalid(Msg::new("file_unwritable")))?;

    tauri::async_runtime::spawn_blocking(move || -> AppResult<()> {
        let contents = export_backup(&password, &data)?;
        write_private(&path, contents.as_bytes())
    })
    .await
    .map_err(|e| AppError::Store(e.to_string()))??;
    Ok(count)
}

fn write_private(path: &std::path::Path, contents: &[u8]) -> AppResult<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| AppError::Invalid(Msg::new("file_unwritable").with("detail", e)))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|e| AppError::Invalid(Msg::new("file_unwritable").with("detail", e)))
}

fn today() -> String {
    let days = now_secs().div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}
