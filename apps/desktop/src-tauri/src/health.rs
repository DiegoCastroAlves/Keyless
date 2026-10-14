//! Sentinel: weak, reused and breached passwords, duplicate items, websites
//! without HTTPS, expiring cards and documents, websites breached since the
//! password was last changed, and websites that offer two-factor
//! authentication or passkeys the item does not use.
//!
//! Everything is compared on this device:
//! - breached websites, two-factor support and passkey support come from
//!   public lists (Have I Been Pwned's breaches, 2fa.directory and its
//!   Passkeys Directory), downloaded whole once a day and kept on disk, so
//!   they follow the websites as they change, work offline, and nothing about
//!   the items is sent. Each list can be turned off in the settings: it is
//!   then neither downloaded nor kept, and its alert is off;
//! - breached passwords use the Have I Been Pwned range API with k-anonymity:
//!   only the first 5 hex characters of each password's SHA-1 hash are sent,
//!   and responses are padded, so the service never learns the password or
//!   even which hash was looked up. It runs when the user asks, or by itself
//!   with the setting on; what it found is kept, encrypted, until the
//!   password changes.
//!
//! What is computed lives in `keyless_core::health`, shared with the other
//! apps; here are the items, the lists kept on disk, the downloads and the
//! notifications.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

pub use keyless_core::health::{HealthReport, Strength, strength};
use keyless_core::{
    health::{self, BreachCheck, ChecksKey, Entry, LISTS, ListError, ListKind, MAX_LIST_BYTES, Online, PasswordChecks, Sites, analyze, compromised, range_matches},
    item::ItemUrl,
};
use serde::{Serialize, de::DeserializeOwned};
use tauri::{AppHandle, Emitter, Manager};

use crate::{
    api::now_secs,
    error::{AppError, AppResult, Msg},
    state::{AppState, Settings},
    store::Store,
};

/// The editor's check of a password being typed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordCheck {
    /// 0 (very weak) to 6 (excellent), see `keyless_core::health::level`.
    pub level: u8,
    /// Other items that already use it.
    pub reused: usize,
}

/// Every item that is neither archived nor in Recently Deleted.
async fn entries(state: &AppState) -> AppResult<Vec<Entry>> {
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let store = state.store();
    let mut out = Vec::new();
    for (id, cached) in &session.items {
        let o = &cached.overview;
        if o.trashed_at.is_some() || o.archived {
            continue;
        }
        let Some(local) = store.item(id)? else { continue };
        let (Some(enc), Ok(vault)) = (local.enc_details.as_deref(), session.vault(&local.vault_id)) else {
            continue;
        };
        let Ok(details) = vault.key.open_details(&local.vault_id, id, enc) else { continue };
        out.push(Entry::new(id, &local.vault_id, o, details));
    }
    Ok(out)
}

pub async fn report(app: &AppHandle) -> AppResult<HealthReport> {
    compute(app, true).await
}

/// The report; with `wake`, new passwords not checked online yet start the
/// automatic check.
async fn compute(app: &AppHandle, wake: bool) -> AppResult<HealthReport> {
    let state = app.state::<AppState>();
    let entries = entries(&state).await?;
    // Online alerts, from the last check and the lists on disk.
    let key = checks_key(&state).await?;
    let checks = key.load(&state.store());
    let settings = state.settings();
    let lists = lists(app);
    let seen = |password: &str| checks.seen.get(&key.id(password)).copied();
    let online = Online {
        seen: &seen,
        checked: checks.checked_at.is_some(),
        lists: LISTS.into_iter().filter(|kind| kind.enabled(&settings)).filter_map(|kind| lists.get(&kind).map(|list| (kind, &list.sites))).collect(),
        off: LISTS.into_iter().filter(|kind| !kind.enabled(&settings)).collect(),
    };
    let mut report = analyze(&entries, &online, now_secs());
    report.passwords_checked_at = checks.checked_at;
    report.lists_updated_at = health::lists_updated_at(LISTS.into_iter().filter(|kind| kind.enabled(&settings)).map(|kind| lists.get(&kind).map(|list| list.fetched_at)));
    // New passwords: checked in the background, with the setting on.
    if wake && report.unchecked > 0 {
        state.sentinel.wake.notify_one();
    }
    Ok(report)
}

/// Serious alerts not announced yet (breached passwords and websites, dates
/// due, LastPass imports): a notification says how many there are, then
/// they are remembered (encrypted, like the checks). The first time, what is
/// there already is only remembered.
async fn notify_new_alerts(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let report = compute(app, false).await?;
    let key = checks_key(&state).await?;
    let previous: Option<BTreeSet<String>> = key.load_row(&state.store(), NOTIFIED);
    let current = announced(&report, previous.as_ref());
    key.save_row(&state.store(), NOTIFIED, &current)?;
    let new = previous.map_or(0, |seen| current.difference(&seen).count());
    if new > 0 && state.settings().sentinel_notifications {
        crate::notify::sentinel(app, new);
    }
    Ok(())
}

/// The serious alerts to remember as announced: the report's, and those
/// announced before from a list that is now off or not downloaded (they are
/// unknown, not gone: forgetting them would announce them all again once
/// the list is back).
fn announced(report: &HealthReport, previous: Option<&BTreeSet<String>>) -> BTreeSet<String> {
    let mut current: BTreeSet<String> = report
        .breached
        .iter()
        .map(|(id, _)| format!("breached:{id}"))
        .chain(report.compromised.iter().map(|issue| format!("compromised:{}:{}", issue.id, issue.site)))
        .chain(report.expiring.iter().map(|e| format!("expiring:{}:{}", e.id, e.expires_at)))
        .chain(report.lastpass.iter().map(|id| format!("lastpass:{id}")))
        .collect();
    for alert in LISTS.map(ListKind::alert).into_iter().filter(|alert| report.off.contains(alert) || report.pending.contains(alert)) {
        let prefix = format!("{alert}:");
        current.extend(previous.into_iter().flatten().filter(|seen| seen.starts_with(&prefix)).cloned());
    }
    current
}

/// What the browser extension warns about on a website: its logins whose
/// password was seen in breaches, or that the website lost in a breach
/// after the password was set.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteAlert {
    pub item_id: String,
    pub title: String,
    pub username: String,
    /// "breached" or "compromised".
    pub kind: &'static str,
    /// The website's breach date (YYYY-MM-DD).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// The serious alerts of the logins for `site` (a registrable domain).
/// Ignored alerts are left out; nothing is looked up online.
pub async fn site_alerts(app: &AppHandle, site: &str) -> AppResult<Vec<SiteAlert>> {
    let state = app.state::<AppState>();
    let entries: Vec<Entry> = entries(&state).await?.into_iter().filter(|e| e.is_login() && e.sites().contains(site)).collect();
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let key = checks_key(&state).await?;
    let checks = key.load(&state.store());
    let mut alerts = Vec::new();
    let alert = |entry: &Entry, kind, date| SiteAlert {
        item_id: entry.id.clone(),
        title: entry.title.clone(),
        username: entry.username().unwrap_or_default(),
        kind,
        date,
    };
    for entry in &entries {
        if let Some(password) = entry.password()
            && checks.seen.get(&key.id(password)).is_some_and(|&seen| seen > 0)
            && !entry.ignores("breached")
        {
            alerts.push(alert(entry, "breached", None));
        }
    }
    let breaches = ListKind::Breaches.enabled(&state.settings()).then(|| lists(app).get(&ListKind::Breaches).cloned()).flatten();
    if let Some(list) = breaches {
        for issue in compromised(&entries, &list.sites).into_iter().filter(|i| i.site == site) {
            if let Some(entry) = entries.iter().find(|e| e.id == issue.id)
                && !entry.ignores("compromised")
                && !alerts.iter().any(|a: &SiteAlert| a.item_id == issue.id)
            {
                alerts.push(alert(entry, "compromised", issue.date));
            }
        }
    }
    Ok(alerts)
}

/// A password being typed in the editor: its strength (against the item's
/// own words, like its user name) and how many other items already use it.
/// Nothing leaves this device.
pub async fn check_password(state: &AppState, password: &str, item_id: Option<&str>, inputs: &[&str]) -> AppResult<PasswordCheck> {
    let entries = entries(state).await?;
    Ok(PasswordCheck { level: strength(password, inputs).level, reused: health::reuses(&entries, password, item_id) })
}

/// "Use HTTPS" on an item's addresses: the ones on plain http's own port
/// move to https. Refused for an item in Recently Deleted (saving it would
/// restore it), and when no address can simply switch.
fn switch_to_https(urls: &mut [ItemUrl], trashed: bool) -> AppResult<()> {
    if trashed {
        return Err(AppError::Invalid(Msg::new("https_trashed")));
    }
    if !health::switch_to_https(urls) {
        return Err(AppError::Invalid(Msg::new("https_unavailable")));
    }
    Ok(())
}

/// "Use HTTPS": the item's websites on plain `http` move to `https`, saved
/// like any edit (a new version, synced).
pub async fn use_https(app: &AppHandle, item_id: &str) -> AppResult<()> {
    let state = app.state::<AppState>();
    let trashed = {
        let guard = state.session.lock().await;
        let session = guard.as_ref().ok_or(AppError::Locked)?;
        session.items.get(item_id).ok_or(AppError::NotFound)?.overview.trashed_at.is_some()
    };
    let mut draft = crate::items::get_item_draft(&state, item_id).await?;
    switch_to_https(&mut draft.urls, trashed)?;
    crate::items::save_item(app, draft).await.map(|_| ())
}

fn client() -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(concat!("Keyless/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Server(e.to_string()))
}

fn io_error(err: std::io::Error) -> AppError {
    AppError::Store(err.to_string())
}

async fn get_list(client: &reqwest::Client, url: &str) -> AppResult<Vec<u8>> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_LIST_BYTES {
            return Err(AppError::Server("list too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

// ----- background checks ------------------------------------------------------

#[derive(Default)]
pub struct SentinelState {
    /// The public lists, once read from disk.
    lists: std::sync::Mutex<Option<Lists>>,
    /// No automatic download or check before this, after one failed
    /// (offline).
    retry_at: std::sync::Mutex<Option<std::time::Instant>>,
    /// Wakes the automatic checks: there are new passwords to check.
    wake: tokio::sync::Notify,
    /// One check at a time.
    busy: tokio::sync::Mutex<()>,
}

/// How often the lists are downloaded again, and the passwords checked again
/// (with the setting on).
const AUTO_EVERY: i64 = 24 * 3600;
/// How long the automatic checks wait after one failed.
const AUTO_RETRY: std::time::Duration = std::time::Duration::from_secs(3600);
pub const EVENT_UPDATED: &str = "keyless://sentinel-updated";

/// "Check online": downloads the lists again (unless they are from the last
/// hour) and checks every password.
pub async fn check_online(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let _busy = state.sentinel.busy.lock().await;
    if let Err(err) = refresh_lists(app, 3600).await {
        log::warn!("Sentinel lists: {err}");
    }
    let checked = check_passwords(app, 0).await;
    let _ = app.emit(EVENT_UPDATED, ());
    checked.map(|_| ())
}

/// While Keyless is unlocked, keeps the lists up to date (they say nothing
/// about the items) and, with the setting on, checks the passwords: every
/// one once a day, and new ones as they are saved.
pub fn init(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let mut locked = state.lock_state.subscribe();
        loop {
            let unlocked = tokio::select! {
                changed = locked.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    true
                }
                _ = state.sentinel.wake.notified() => false,
                _ = tokio::time::sleep(std::time::Duration::from_secs(15 * 60)) => false,
            };
            if *locked.borrow_and_update() {
                continue;
            }
            // Just unlocked: not to slow down the first sync. Otherwise a
            // moment for edits to settle.
            tokio::time::sleep(std::time::Duration::from_secs(if unlocked { 60 } else { 3 })).await;
            run_due(&app).await;
        }
    });
}

async fn run_due(app: &AppHandle) {
    let state = app.state::<AppState>();
    if state.session.lock().await.is_none() {
        return;
    }
    if state.sentinel.retry_at.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|at| std::time::Instant::now() < at) {
        return;
    }
    let _busy = state.sentinel.busy.lock().await;
    let mut changed = false;
    let mut failed = false;
    // A list turned off while Keyless was not running, or while it was
    // being downloaded, is not kept.
    forget_off_lists(app);
    match refresh_lists(app, AUTO_EVERY).await {
        Ok(updated) => changed |= updated,
        Err(err) => {
            log::info!("automatic Sentinel lists: {err}");
            failed = true;
        }
    }
    if state.settings().sentinel_check_passwords {
        match check_passwords(app, AUTO_EVERY).await {
            Ok(checked) => changed |= checked,
            Err(AppError::Locked) => {}
            Err(err) => {
                log::info!("automatic Sentinel check: {err}");
                failed = true;
            }
        }
    }
    if failed {
        *state.sentinel.retry_at.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now() + AUTO_RETRY);
    }
    if changed {
        let _ = app.emit(EVENT_UPDATED, ());
    }
    if let Err(err) = notify_new_alerts(app).await {
        log::info!("Sentinel notifications: {err}");
    }
}

// ----- public lists -----------------------------------------------------------

/// Where the desktop keeps each public list (see
/// `keyless_core::health::ListKind`), and whether it is turned on.
trait ListFile {
    fn file(self) -> &'static str;
    /// Turned on in the settings.
    fn enabled(self, settings: &Settings) -> bool;
    /// The sites in the list as downloaded, or why it is not the real one.
    fn read(self, body: &[u8]) -> AppResult<Sites>;
}

impl ListFile for ListKind {
    fn file(self) -> &'static str {
        match self {
            Self::Breaches => "breaches.json",
            Self::TwoFactor => "two-factor.json",
            Self::Passkeys => "passkeys.json",
        }
    }

    fn enabled(self, settings: &Settings) -> bool {
        match self {
            Self::Breaches => settings.sentinel_breach_list,
            Self::TwoFactor => settings.sentinel_two_factor_list,
            Self::Passkeys => settings.sentinel_passkey_list,
        }
    }

    fn read(self, body: &[u8]) -> AppResult<Sites> {
        self.parse(body).map_err(|err| match err {
            ListError::Json(err) => err.into(),
            ListError::Incomplete(sites) => AppError::Server(format!("{} looks incomplete ({sites} sites)", self.file())),
        })
    }
}

struct SiteList {
    sites: Sites,
    /// When it was downloaded (Unix seconds).
    fetched_at: i64,
}

type Lists = HashMap<ListKind, Arc<SiteList>>;

fn lists_dir(app: &AppHandle) -> AppResult<PathBuf> {
    Ok(app.path().app_local_data_dir().map_err(|e| AppError::Store(e.to_string()))?.join("sentinel"))
}

/// The lists, read from disk once per run.
fn lists(app: &AppHandle) -> Lists {
    let state = app.state::<AppState>();
    let mut cached = state.sentinel.lists.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(lists) = cached.as_ref() {
        return lists.clone();
    }
    let mut lists = Lists::new();
    if let Ok(dir) = lists_dir(app) {
        for kind in LISTS {
            match read_list(&dir, kind) {
                Ok(Some(list)) => {
                    lists.insert(kind, Arc::new(list));
                }
                Ok(None) => {}
                Err(err) => log::warn!("Sentinel list {}: {err}", kind.file()),
            }
        }
    }
    *cached = Some(lists.clone());
    lists
}

fn read_list(dir: &Path, kind: ListKind) -> AppResult<Option<SiteList>> {
    let path = dir.join(kind.file());
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(io_error(err)),
    };
    let modified = std::fs::metadata(&path).and_then(|m| m.modified()).map_err(io_error)?;
    let fetched_at = modified.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    Ok(Some(SiteList { sites: kind.read(&body)?, fetched_at }))
}

/// Downloads the lists older than `max_age` seconds. Returns whether any was
/// updated; fails only when none of them could be.
async fn refresh_lists(app: &AppHandle, max_age: i64) -> AppResult<bool> {
    let now = now_secs();
    let current = lists(app);
    let settings = app.state::<AppState>().settings();
    let due: Vec<ListKind> = LISTS
        .into_iter()
        .filter(|kind| kind.enabled(&settings))
        // A list from the future: the clock was wrong.
        .filter(|kind| current.get(kind).is_none_or(|list| now - list.fetched_at >= max_age || list.fetched_at > now))
        .collect();
    if due.is_empty() {
        return Ok(false);
    }
    let client = client()?;
    let dir = lists_dir(app)?;
    let state = app.state::<AppState>();
    let mut updated = false;
    let mut failure = None;
    for kind in due {
        // Turned off since the lists due were chosen.
        if !kind.enabled(&state.settings()) {
            continue;
        }
        let downloaded = async {
            let body = get_list(&client, kind.url()).await?;
            let sites = kind.read(&body)?;
            Ok::<_, AppError>((body, sites))
        }
        .await;
        // Kept under the lists' lock, where turning a list off deletes it:
        // a download under way cannot bring back a list just turned off.
        let kept = downloaded.and_then(|(body, sites)| {
            let mut cached = state.sentinel.lists.lock().unwrap_or_else(|e| e.into_inner());
            keep_list(&dir, &mut cached, kind, &state.settings(), &body, sites)
        });
        match kept {
            Ok(kept) => updated |= kept,
            Err(err) => {
                log::warn!("Sentinel list {}: {err}", kind.file());
                failure = Some(err);
            }
        }
    }
    match failure {
        Some(err) if !updated => Err(err),
        _ => Ok(updated),
    }
}

/// Keeps a list just downloaded, written to disk and cached, unless it was
/// turned off meanwhile. Returns whether it was kept. Called with the
/// lists' lock held.
fn keep_list(dir: &Path, cached: &mut Option<Lists>, kind: ListKind, settings: &Settings, body: &[u8], sites: Sites) -> AppResult<bool> {
    if !kind.enabled(settings) {
        return Ok(false);
    }
    replace_file(dir, kind.file(), body)?;
    cached.get_or_insert_with(Lists::new).insert(kind, Arc::new(SiteList { sites, fetched_at: now_secs() }));
    Ok(true)
}

/// Forgets the lists turned off: from the cache and from disk. Called with
/// the lists' lock held.
fn drop_off_lists(dir: Option<&Path>, cached: &mut Option<Lists>, settings: &Settings) {
    for kind in LISTS.into_iter().filter(|kind| !kind.enabled(settings)) {
        if let Some(lists) = cached.as_mut() {
            lists.remove(&kind);
        }
        if let Some(dir) = dir
            && let Err(err) = std::fs::remove_file(dir.join(kind.file()))
            && err.kind() != std::io::ErrorKind::NotFound
        {
            log::warn!("Sentinel list {}: {err}", kind.file());
        }
    }
}

/// Deletes the lists turned off (see `drop_off_lists`).
fn forget_off_lists(app: &AppHandle) {
    let state = app.state::<AppState>();
    let dir = lists_dir(app).ok();
    let mut cached = state.sentinel.lists.lock().unwrap_or_else(|e| e.into_inner());
    drop_off_lists(dir.as_deref(), &mut cached, &state.settings());
}

/// A list was turned on or off in the settings: one turned off is deleted
/// (downloaded again when it is turned back on), one turned on is
/// downloaded in a moment, and the report is computed again.
pub fn lists_changed(app: &AppHandle) {
    let state = app.state::<AppState>();
    forget_off_lists(app);
    // The user asked: no waiting for the retry after a failed download.
    *state.sentinel.retry_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
    state.sentinel.wake.notify_one();
    let _ = app.emit(EVENT_UPDATED, ());
}

/// Writes a new file beside the old one and renames it over it, so a crash
/// or a full disk leaves the old copy whole.
fn replace_file(dir: &Path, name: &str, data: &[u8]) -> AppResult<()> {
    std::fs::create_dir_all(dir).map_err(io_error)?;
    let part = dir.join(format!("{name}.part"));
    let written = std::fs::File::create(&part).and_then(|mut file| {
        file.write_all(data)?;
        file.sync_all()
    });
    if let Err(err) = written.and_then(|_| std::fs::rename(&part, dir.join(name))) {
        let _ = std::fs::remove_file(&part);
        return Err(io_error(err));
    }
    Ok(())
}

// ----- breached passwords -----------------------------------------------------

/// The alerts already announced (see `notify_new_alerts`).
const NOTIFIED: &str = "notified";

/// What Sentinel keeps in the local database, encrypted with a key derived
/// from the account key (`ChecksKey`).
trait Kept {
    fn load(&self, store: &Store) -> PasswordChecks;
    fn save(&self, store: &Store, checks: &PasswordChecks) -> AppResult<()>;
    fn load_row<T: DeserializeOwned>(&self, store: &Store, row: &str) -> Option<T>;
    fn save_row<T: Serialize>(&self, store: &Store, row: &str, value: &T) -> AppResult<()>;
}

impl Kept for ChecksKey {
    /// Nothing yet, or another account's: nothing checked.
    fn load(&self, store: &Store) -> PasswordChecks {
        self.load_row(store, ChecksKey::ROW).unwrap_or_default()
    }

    fn save(&self, store: &Store, checks: &PasswordChecks) -> AppResult<()> {
        self.save_row(store, ChecksKey::ROW, checks)
    }

    fn load_row<T: DeserializeOwned>(&self, store: &Store, row: &str) -> Option<T> {
        store.sentinel_data(row).ok().flatten().and_then(|data| self.open_row(row, &data))
    }

    fn save_row<T: Serialize>(&self, store: &Store, row: &str, value: &T) -> AppResult<()> {
        store.set_sentinel_data(row, &self.seal_row(row, value)?)
    }
}

/// Sentinel data that never leaves this device (the developer scan's
/// ignored findings), encrypted like the checks.
pub(crate) async fn load_private<T: DeserializeOwned>(state: &AppState, row: &str) -> AppResult<Option<T>> {
    let key = checks_key(state).await?;
    Ok(key.load_row(&state.store(), row))
}

pub(crate) async fn save_private<T: Serialize>(state: &AppState, row: &str, value: &T) -> AppResult<()> {
    let key = checks_key(state).await?;
    key.save_row(&state.store(), row, value)
}

async fn checks_key(state: &AppState) -> AppResult<ChecksKey> {
    let guard = state.session.lock().await;
    Ok(ChecksKey::new(guard.as_ref().ok_or(AppError::Locked)?.account.user_key())?)
}

/// Checks the passwords on Have I Been Pwned: all of them when the last full
/// check is older than `max_age` seconds, otherwise only the ones never
/// checked. Returns whether anything was checked.
async fn check_passwords(app: &AppHandle, max_age: i64) -> AppResult<bool> {
    let state = app.state::<AppState>();
    let entries = entries(&state).await?;
    let key = checks_key(&state).await?;
    let old = key.load(&state.store());
    let all = old.full_check_due(max_age, now_secs());
    let check = BreachCheck::new(&key, entries.iter().filter_map(Entry::password), &old, all);
    drop(entries);
    if check.is_done() {
        return Ok(false);
    }
    let found = breached_hashes(&client()?, check.ranges()).await?;
    let checks = check.finish(old, &found, now_secs());
    // Not after signing out, which deletes the results.
    let guard = state.session.lock().await;
    if guard.is_none() {
        return Err(AppError::Locked);
    }
    key.save(&state.store(), &checks)?;
    Ok(true)
}

/// The SHA-1 hashes (uppercase hex) seen in breaches, with how often, from
/// the hashes to ask about by range (see `BreachCheck::ranges`). Asks Have I
/// Been Pwned's range API with k-anonymity: only the first 5 characters of
/// each hash are sent, and the responses are padded.
async fn breached_hashes(client: &reqwest::Client, ranges: BTreeMap<&str, Vec<&str>>) -> AppResult<HashMap<String, u64>> {
    let mut found = HashMap::new();
    for (prefix, suffixes) in ranges {
        let body = client
            .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
            .header("Add-Padding", "true")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        found.extend(range_matches(prefix, &body, &suffixes));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use keyless_core::health::SiteIssue;

    use super::*;

    #[test]
    fn lists_are_replaced_whole() {
        let dir = std::env::temp_dir().join(format!("keyless-sentinel-{}", uuid::Uuid::new_v4()));
        replace_file(&dir, "list.json", b"old").unwrap();
        replace_file(&dir, "list.json", b"new").unwrap();
        assert_eq!(std::fs::read(dir.join("list.json")).unwrap(), b"new");
        assert!(!dir.join("list.json.part").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn use_https_on_items() {
        let url = |href: &str| ItemUrl { href: href.into(), ..Default::default() };
        let mut urls = [url("http://example.com/login"), url("http://example.com:8080/admin"), url("http://192.168.0.1")];
        switch_to_https(&mut urls, false).unwrap();
        assert_eq!(urls.map(|u| u.href), ["https://example.com/login", "http://example.com:8080/admin", "http://192.168.0.1"]);
        // Saving an item in Recently Deleted would restore it.
        let mut urls = [url("http://example.com")];
        assert!(matches!(switch_to_https(&mut urls, true), Err(AppError::Invalid(m)) if m.key == "https_trashed"));
        assert_eq!(urls[0].href, "http://example.com");
        let mut urls = [url("http://example.com:8080")];
        assert!(matches!(switch_to_https(&mut urls, false), Err(AppError::Invalid(m)) if m.key == "https_unavailable"));
    }

    #[test]
    fn announced_alerts_survive_a_list_turned_off() {
        let issue = |id: &str| SiteIssue { id: id.into(), site: "adobe.com".into(), date: None, breach: None };
        let previous: BTreeSet<String> = ["breached:a", "compromised:b:adobe.com", "lastpass:c"].map(String::from).into();
        // The breach list is off: the breached websites announced stay
        // remembered; the others follow the report.
        let off = HealthReport { breached: vec![("a".into(), 3)], off: vec!["compromised"], ..Default::default() };
        let kept = announced(&off, Some(&previous));
        assert_eq!(kept, ["breached:a", "compromised:b:adobe.com"].map(String::from).into());
        // Back on, with the same breach: nothing new to announce.
        let on = HealthReport { breached: vec![("a".into(), 3)], compromised: vec![issue("b")], ..Default::default() };
        let now = announced(&on, Some(&kept));
        assert_eq!(now.difference(&kept).count(), 0);
        // Not downloaded yet counts as unknown too; fixed alerts are dropped.
        let pending = HealthReport { pending: vec!["compromised"], ..Default::default() };
        assert_eq!(announced(&pending, Some(&previous)), ["compromised:b:adobe.com"].map(String::from).into());
        assert!(announced(&HealthReport::default(), Some(&previous)).is_empty());
    }

    #[test]
    fn lists_turned_off_are_not_kept() {
        let dir = std::env::temp_dir().join(format!("keyless-sentinel-{}", uuid::Uuid::new_v4()));
        let mut settings = Settings { sentinel_two_factor_list: false, ..Default::default() };
        let mut cached = None;
        // A download that ends after its list was turned off is dropped.
        assert!(!keep_list(&dir, &mut cached, ListKind::TwoFactor, &settings, b"[]", Sites::new()).unwrap());
        assert!(!dir.join(ListKind::TwoFactor.file()).exists());
        assert!(cached.is_none());
        settings.sentinel_two_factor_list = true;
        for kind in LISTS {
            assert!(keep_list(&dir, &mut cached, kind, &settings, b"[]", Sites::new()).unwrap());
        }
        assert_eq!(cached.as_ref().unwrap().len(), 3);
        // Turned off: deleted from disk and forgotten; the others stay.
        settings.sentinel_breach_list = false;
        drop_off_lists(Some(&dir), &mut cached, &settings);
        assert!(!dir.join(ListKind::Breaches.file()).exists());
        assert!(dir.join(ListKind::TwoFactor.file()).exists() && dir.join(ListKind::Passkeys.file()).exists());
        assert!(!cached.as_ref().unwrap().contains_key(&ListKind::Breaches));
        assert_eq!(cached.as_ref().unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
