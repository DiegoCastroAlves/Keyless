//! Tauri commands: the only interface between the UI and the Rust side.
//! Each command records user activity for the auto-lock timer.

use std::time::Duration;

use keyless_core::{
    generator::{GeneratedPassword, GeneratorOptions, generate},
    import::ImportSummary,
    vault::VaultMeta,
};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

use crate::{
    auth::{self, AppStatus, CreatedAccount},
    clipboard,
    error::{AppError, AppResult, Msg},
    health::{self, BreachReport, HealthReport, Strength},
    import::{self, ImportFormat, ImportTarget},
    items::{self, HistoryEntry, ItemDetailView, ItemDraft, ItemSummary, TotpCode, VaultDto},
    oauth,
    state::{AppState, Settings, SyncStatus},
    sync, updates,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyResult {
    pub clear_after_seconds: u32,
}

fn copy(app: &AppHandle, state: &AppState, value: Zeroizing<String>) -> AppResult<CopyResult> {
    let seconds = state.settings().clipboard_clear_seconds;
    let generation = state.clipboard.copy(value, true)?;
    clipboard::schedule_clear(app.clone(), generation, Duration::from_secs(seconds as u64));
    Ok(CopyResult { clear_after_seconds: seconds })
}

/// Counts a use of the item for sorting (local only; failures are ignored).
pub fn record_use(state: &AppState, item_id: &str) {
    if let Err(err) = state.store().record_item_use(item_id) {
        log::warn!("could not record item use: {err}");
    }
}

// ----- account ------------------------------------------------------------

#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> AppResult<AppStatus> {
    auth::status(&state).await
}

#[tauri::command]
pub async fn create_account(app: AppHandle, email: String, master_password: String) -> AppResult<CreatedAccount> {
    auth::create_account(&app, &email, Zeroizing::new(master_password)).await
}

#[tauri::command]
pub async fn sign_in_with_google(app: AppHandle, page: oauth::BrowserPage) -> AppResult<oauth::GoogleResult> {
    oauth::sign_in_with_google(&app, page).await
}

#[tauri::command]
pub async fn cancel_google_sign_in(state: State<'_, AppState>) -> AppResult<()> {
    oauth::cancel(&state).await;
    Ok(())
}

#[tauri::command]
pub async fn create_account_with_google(app: AppHandle, master_password: String) -> AppResult<CreatedAccount> {
    auth::create_account_with_google(&app, Zeroizing::new(master_password)).await
}

#[tauri::command]
pub async fn sign_in(app: AppHandle, email: String, secret_key: Option<String>, master_password: String) -> AppResult<()> {
    auth::sign_in(&app, &email, secret_key, Zeroizing::new(master_password)).await
}

#[tauri::command]
pub async fn unlock(app: AppHandle, master_password: String) -> AppResult<()> {
    auth::unlock(&app, Zeroizing::new(master_password)).await
}

#[tauri::command]
pub async fn unlock_with_system(app: AppHandle) -> AppResult<()> {
    auth::unlock_with_system(&app).await
}

#[tauri::command]
pub async fn set_system_unlock(app: AppHandle, enabled: bool, master_password: Option<String>) -> AppResult<Settings> {
    auth::set_system_unlock(&app, enabled, master_password.map(Zeroizing::new)).await
}

#[tauri::command]
pub async fn reauthenticate(app: AppHandle, master_password: String) -> AppResult<()> {
    auth::reauthenticate(&app, Zeroizing::new(master_password)).await
}

#[tauri::command]
pub async fn lock(app: AppHandle) -> AppResult<()> {
    auth::lock(&app).await;
    Ok(())
}

#[tauri::command]
pub async fn sign_out(app: AppHandle) -> AppResult<()> {
    auth::sign_out(&app).await
}

#[tauri::command]
pub async fn resend_confirmation(state: State<'_, AppState>, email: String) -> AppResult<()> {
    auth::resend_confirmation(&state, &email).await
}

#[tauri::command]
pub async fn reveal_secret_key(state: State<'_, AppState>, master_password: String) -> AppResult<String> {
    state.touch();
    auth::reveal_secret_key(&state, Zeroizing::new(master_password)).await
}

/// Copies the Secret Key for the Emergency Kit (works before the first
/// sign-in, e.g. while waiting for email confirmation).
#[tauri::command]
pub fn copy_secret_key(app: AppHandle, state: State<'_, AppState>) -> AppResult<CopyResult> {
    let key = auth::secret_key_for_kit(&state)?;
    copy(&app, &state, key)
}

#[tauri::command]
pub async fn account_info(state: State<'_, AppState>) -> AppResult<auth::AccountInfo> {
    auth::account_info(&state).await
}

#[tauri::command]
pub async fn cancel_account_deletion(state: State<'_, AppState>) -> AppResult<()> {
    state.touch();
    auth::cancel_account_deletion(&state).await
}

#[tauri::command]
pub fn bridge_pair_respond(state: State<'_, AppState>, request_id: String, approve: bool) {
    crate::bridge::server::respond_to_pairing(&state, &request_id, approve);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgePeer {
    pub public_key: String,
    pub name: String,
    pub paired_at: i64,
}

#[tauri::command]
pub fn list_bridge_peers(state: State<'_, AppState>) -> AppResult<Vec<BridgePeer>> {
    Ok(state
        .store()
        .bridge_peers()?
        .into_iter()
        .map(|(public_key, name, paired_at)| BridgePeer { public_key, name, paired_at })
        .collect())
}

#[tauri::command]
pub fn remove_bridge_peer(state: State<'_, AppState>, public_key: String) -> AppResult<()> {
    state.touch();
    state.store().remove_bridge_peer(&public_key)
}

#[tauri::command]
pub async fn change_master_password(app: AppHandle, current: String, new: String) -> AppResult<()> {
    auth::change_master_password(&app, Zeroizing::new(current), Zeroizing::new(new)).await
}

#[tauri::command]
pub async fn delete_account(app: AppHandle, master_password: String) -> AppResult<()> {
    auth::delete_account(&app, Zeroizing::new(master_password)).await
}

#[tauri::command]
pub fn password_strength(password: String, email: Option<String>) -> Strength {
    let password = Zeroizing::new(password);
    let email = email.unwrap_or_default();
    let local_part = email.split('@').next().unwrap_or("");
    health::strength(&password, &[local_part, "keyless"])
}

// ----- activity, settings, sync ------------------------------------------

#[tauri::command]
pub fn heartbeat(state: State<'_, AppState>) {
    state.touch();
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Settings {
    state.settings()
}

#[tauri::command]
pub fn update_settings(state: State<'_, AppState>, settings: Settings) -> AppResult<Settings> {
    let mut settings = settings.sanitized();
    let current = state.settings();
    // Only `set_system_unlock` changes it: turning it on needs the master password.
    settings.system_unlock = current.system_unlock;
    if settings.browser_integration != current.browser_integration {
        let enabled = settings.browser_integration;
        std::thread::spawn(move || crate::bridge::install::sync_registration(enabled));
    }
    if settings.start_at_login != current.start_at_login {
        let enabled = settings.start_at_login;
        std::thread::spawn(move || crate::autostart::sync(enabled));
    }
    state.save_settings(&settings)?;
    Ok(settings)
}

#[tauri::command]
pub fn get_sync_status(state: State<'_, AppState>) -> SyncStatus {
    state.sync_status()
}

#[tauri::command]
pub async fn sync_now(app: AppHandle) -> AppResult<()> {
    sync::sync_now(&app).await
}

// ----- vaults -------------------------------------------------------------

#[tauri::command]
pub async fn list_vaults(state: State<'_, AppState>) -> AppResult<Vec<VaultDto>> {
    items::list_vaults(&state).await
}

#[tauri::command]
pub async fn create_vault(app: AppHandle, state: State<'_, AppState>, meta: VaultMeta) -> AppResult<String> {
    state.touch();
    items::create_vault(&app, meta).await
}

#[tauri::command]
pub async fn update_vault(app: AppHandle, state: State<'_, AppState>, vault_id: String, meta: VaultMeta) -> AppResult<()> {
    state.touch();
    items::update_vault(&app, &vault_id, meta).await
}

#[tauri::command]
pub async fn delete_vault(app: AppHandle, state: State<'_, AppState>, vault_id: String) -> AppResult<()> {
    state.touch();
    items::delete_vault(&app, &vault_id).await
}

// ----- items --------------------------------------------------------------

#[tauri::command]
pub async fn list_items(state: State<'_, AppState>) -> AppResult<Vec<ItemSummary>> {
    items::list_items(&state).await
}

#[tauri::command]
pub async fn get_item(state: State<'_, AppState>, item_id: String) -> AppResult<ItemDetailView> {
    state.touch();
    items::get_item(&state, &item_id).await
}

#[tauri::command]
pub async fn get_item_draft(state: State<'_, AppState>, item_id: String) -> AppResult<ItemDraft> {
    state.touch();
    items::get_item_draft(&state, &item_id).await
}

#[tauri::command]
pub async fn save_item(app: AppHandle, draft: ItemDraft) -> AppResult<ItemSummary> {
    items::save_item(&app, draft).await
}

#[tauri::command]
pub async fn reveal_field(state: State<'_, AppState>, item_id: String, field_id: String) -> AppResult<String> {
    state.touch();
    let value = items::reveal_field(&state, &item_id, &field_id).await?.to_string();
    record_use(&state, &item_id);
    Ok(value)
}

#[tauri::command]
pub async fn get_totp(state: State<'_, AppState>, item_id: String, field_id: String) -> AppResult<TotpCode> {
    items::totp_code(&state, &item_id, &field_id).await
}

#[tauri::command]
pub async fn get_password_history(state: State<'_, AppState>, item_id: String) -> AppResult<Vec<HistoryEntry>> {
    state.touch();
    items::password_history(&state, &item_id).await
}

#[tauri::command]
pub async fn copy_field(app: AppHandle, state: State<'_, AppState>, item_id: String, field_id: String) -> AppResult<CopyResult> {
    state.touch();
    let value = items::copy_value(&state, &item_id, Some(&field_id), None).await?;
    record_use(&state, &item_id);
    copy(&app, &state, value)
}

#[tauri::command]
pub async fn copy_item_value(app: AppHandle, state: State<'_, AppState>, item_id: String, purpose: String) -> AppResult<CopyResult> {
    state.touch();
    let value = items::copy_value(&state, &item_id, None, Some(&purpose)).await?;
    record_use(&state, &item_id);
    copy(&app, &state, value)
}

#[tauri::command]
pub async fn copy_text(app: AppHandle, state: State<'_, AppState>, text: String) -> AppResult<CopyResult> {
    state.touch();
    if state.session.lock().await.is_none() {
        return Err(AppError::Locked);
    }
    copy(&app, &state, Zeroizing::new(text))
}

#[tauri::command]
pub async fn open_item_url(app: AppHandle, state: State<'_, AppState>, item_id: String, index: usize) -> AppResult<()> {
    state.touch();
    let url = items::item_url(&state, &item_id, index).await?;
    record_use(&state, &item_id);
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|e| AppError::Invalid(Msg::new("open_url_failed").with("detail", e)))
}

#[tauri::command]
pub async fn set_favorite(app: AppHandle, state: State<'_, AppState>, item_id: String, favorite: bool) -> AppResult<()> {
    state.touch();
    items::set_favorite(&app, &item_id, favorite).await
}

#[tauri::command]
pub async fn set_archived(app: AppHandle, state: State<'_, AppState>, item_id: String, archived: bool) -> AppResult<()> {
    state.touch();
    items::set_archived(&app, &item_id, archived).await
}

#[tauri::command]
pub async fn trash_item(app: AppHandle, state: State<'_, AppState>, item_id: String) -> AppResult<()> {
    state.touch();
    items::trash_item(&app, &item_id).await
}

#[tauri::command]
pub async fn restore_item(app: AppHandle, state: State<'_, AppState>, item_id: String) -> AppResult<()> {
    state.touch();
    items::restore_item(&app, &item_id).await
}

#[tauri::command]
pub async fn delete_items_permanently(app: AppHandle, state: State<'_, AppState>, item_ids: Vec<String>) -> AppResult<()> {
    state.touch();
    items::delete_items_permanently(&app, &item_ids).await
}

// ----- tools --------------------------------------------------------------

#[tauri::command]
pub fn generate_password(state: State<'_, AppState>, options: GeneratorOptions) -> AppResult<GeneratedPassword> {
    state.touch();
    Ok(generate(&options)?)
}

#[tauri::command]
pub async fn password_health(state: State<'_, AppState>) -> AppResult<HealthReport> {
    state.touch();
    health::report(&state).await
}

#[tauri::command]
pub async fn check_breaches(state: State<'_, AppState>) -> AppResult<BreachReport> {
    state.touch();
    health::breaches(&state).await
}

#[tauri::command]
pub async fn import_pick(app: AppHandle, state: State<'_, AppState>, format: ImportFormat, password: Option<String>) -> AppResult<ImportSummary> {
    state.touch();
    import::pick_and_parse(&app, format, password.map(Zeroizing::new)).await
}

#[tauri::command]
pub async fn export_backup(app: AppHandle, state: State<'_, AppState>, master_password: String, password: String) -> AppResult<usize> {
    state.touch();
    import::export(&app, Zeroizing::new(master_password), Zeroizing::new(password)).await
}

#[tauri::command]
pub async fn import_commit(app: AppHandle, state: State<'_, AppState>, target: ImportTarget) -> AppResult<usize> {
    state.touch();
    import::commit(&app, target).await
}

#[tauri::command]
pub fn import_cancel(state: State<'_, AppState>) {
    import::cancel(&state);
}

// ----- updates -------------------------------------------------------------

#[tauri::command]
pub fn version_info(state: State<'_, AppState>) -> updates::VersionInfo {
    updates::version_info(&state)
}

#[tauri::command]
pub async fn check_for_updates(app: AppHandle) -> AppResult<updates::VersionInfo> {
    updates::check_now(&app).await
}

#[tauri::command]
pub fn open_update_page(app: AppHandle, state: State<'_, AppState>) -> AppResult<()> {
    let url = updates::update_url(&state).ok_or(AppError::NotFound)?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| AppError::Invalid(Msg::new("open_url_failed").with("detail", e)))
}

#[tauri::command]
pub async fn install_update(app: AppHandle) -> AppResult<()> {
    updates::install(&app).await
}

// ----- tray ----------------------------------------------------------------

/// Creates the tray icon (or updates its menu) with texts translated by the UI.
#[tauri::command]
pub fn configure_tray(app: AppHandle, labels: crate::tray::TrayLabels) {
    if let Err(err) = crate::tray::configure(&app, &labels) {
        log::warn!("tray icon unavailable: {err}");
        // Without a tray there is no way back to a hidden window.
        crate::tray::show_main(&app);
    }
}

// ----- Quick Access --------------------------------------------------------

#[tauri::command]
pub fn show_quick_access(app: AppHandle) -> AppResult<()> {
    crate::quick_access::show(&app).map_err(|e| AppError::Server(e.to_string()))
}

#[tauri::command]
pub fn quick_access_ready(app: AppHandle) -> AppResult<()> {
    crate::quick_access::ready(&app).map_err(|e| AppError::Server(e.to_string()))
}

#[tauri::command]
pub fn hide_quick_access(app: AppHandle) {
    crate::quick_access::hide(&app);
}

#[tauri::command]
pub fn show_item_in_app(app: AppHandle, item_id: String) {
    crate::quick_access::show_item(&app, &item_id);
}

/// Changes the shortcut the app registers itself (Windows).
#[tauri::command]
pub fn set_quick_access_shortcut(app: AppHandle, state: State<'_, AppState>, shortcut: String) -> AppResult<Settings> {
    #[cfg(windows)]
    crate::quick_access::register_shortcut(&app, &shortcut)?;
    #[cfg(not(windows))]
    let _ = &app;
    let mut settings = state.settings();
    settings.quick_access_shortcut = shortcut.trim().to_string();
    state.save_settings(&settings)?;
    Ok(settings)
}

// ----- moving items ---------------------------------------------------------

#[tauri::command]
pub async fn move_items(app: AppHandle, state: State<'_, AppState>, item_ids: Vec<String>, vault_id: String) -> AppResult<usize> {
    state.touch();
    items::move_items(&app, &item_ids, &vault_id).await
}

#[tauri::command]
pub async fn move_vault_items(app: AppHandle, state: State<'_, AppState>, from_vault: String, to_vault: String, delete_source: bool) -> AppResult<usize> {
    state.touch();
    items::move_vault_items(&app, &from_vault, &to_vault, delete_source).await
}
