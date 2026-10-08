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
//!   the items is sent;
//! - breached passwords use the Have I Been Pwned range API with k-anonymity:
//!   only the first 5 hex characters of each password's SHA-1 hash are sent,
//!   and responses are padded, so the service never learns the password or
//!   even which hash was looked up. It runs when the user asks, or by itself
//!   with the setting on; what it found is kept, encrypted, until the
//!   password changes.

use std::{
    collections::{HashMap, HashSet},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use hkdf::Hkdf;
use keyless_core::{
    account::UnlockedAccount,
    crypto::SymmetricKey,
    item::{Category, FieldKind, FieldPurpose, ItemDetails, ItemUrl},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::{
    api::now_secs,
    bridge::{forms::parse_expiry, handlers::{site_of, url_host}},
    error::{AppError, AppResult},
    state::AppState,
    store::Store,
};

/// Cards and documents expiring this soon are reported.
const EXPIRING_SOON: i64 = 30 * 24 * 3600;
/// The public lists are a few megabytes; anything far larger is refused.
const MAX_LIST_BYTES: usize = 20 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// zxcvbn's 0 (very weak) to 4 (very strong): what the rules use (a
    /// weak password is below 3).
    pub score: u8,
    /// What the user sees: 0 (very weak) to 6 (excellent), see `level`.
    pub level: u8,
    pub guesses_log10: f64,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Expiry {
    pub id: String,
    /// Unix seconds.
    pub expires_at: i64,
    pub expired: bool,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    pub checked: usize,
    pub weak: Vec<String>,
    /// Groups of item ids that share the same password.
    pub reused: Vec<Vec<String>>,
    /// Groups of item ids for the same account: the same website and user
    /// name.
    pub duplicates: Vec<Vec<String>>,
    /// Items with a website on plain `http`.
    pub unsecured: Vec<String>,
    pub expiring: Vec<Expiry>,
    /// Item ids whose password appears in known breaches, with the count.
    pub breached: Vec<(String, u64)>,
    /// Websites breached after the item's password was set.
    pub compromised: Vec<SiteIssue>,
    /// Websites that offer two-factor codes the item does not have.
    pub two_factor: Vec<SiteIssue>,
    /// Websites that accept passkeys, for items without one.
    pub passkeys: Vec<SiteIssue>,
    /// Alerts not known yet: their list was never downloaded, or the
    /// passwords never checked online.
    pub pending: Vec<&'static str>,
    /// Passwords not checked online yet (new or changed since).
    pub unchecked: usize,
    /// When every password was last checked online (Unix seconds).
    pub passwords_checked_at: Option<i64>,
    /// When the oldest list was downloaded (Unix seconds).
    pub lists_updated_at: Option<i64>,
    /// Alerts the user ignored: (item id, alert).
    pub ignored: Vec<(String, String)>,
    /// Item id -> its password's strength level (0 to 6, see `level`).
    pub levels: HashMap<String, u8>,
}

/// The editor's check of a password being typed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordCheck {
    /// 0 (very weak) to 6 (excellent), see `level`.
    pub level: u8,
    /// Other items that already use it.
    pub reused: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteIssue {
    pub id: String,
    pub site: String,
    /// The breach date (YYYY-MM-DD) for breached websites.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// Seven levels, finer than zxcvbn's five scores at the strong end, where
/// most generated passwords are: the first four are the scores 0 to 3 (so
/// "weak" means the same everywhere), and score 4 (at least 10^10 guesses)
/// is split at 10^12 and 10^16 guesses.
pub fn level(score: u8, guesses_log10: f64) -> u8 {
    match score {
        0..=3 => score,
        _ if guesses_log10 < 12.0 => 4,
        _ if guesses_log10 < 16.0 => 5,
        _ => 6,
    }
}

pub fn strength(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength { score: 0, level: 0, guesses_log10: 0.0, warning: None, suggestions: vec![] };
    }
    // zxcvbn is quadratic in length; anything this long is strong anyway.
    let sample: String = password.chars().take(100).collect();
    let entropy = zxcvbn::zxcvbn(&sample, user_inputs);
    let score = entropy.score() as u8;
    Strength {
        score,
        level: level(score, entropy.guesses_log10()),
        guesses_log10: entropy.guesses_log10(),
        warning: entropy.feedback().and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: entropy
            .feedback()
            .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

/// An active item, as the checks need it.
struct Entry {
    id: String,
    title: String,
    /// Alerts the user ignored for this item.
    ignored: Vec<String>,
    category: Category,
    urls: Vec<ItemUrl>,
    created_at: i64,
    details: ItemDetails,
}

impl Entry {
    fn ignores(&self, alert: &str) -> bool {
        self.ignored.iter().any(|a| a == alert)
    }

    fn password(&self) -> Option<&str> {
        self.details.field_by_purpose(FieldPurpose::Password).map(|f| f.value.as_str()).filter(|p| !p.is_empty())
    }

    /// When the current password was set: when the previous one was
    /// replaced, or when the item was created.
    fn password_set_at(&self) -> i64 {
        self.details.password_history.iter().map(|h| h.changed_at).max().unwrap_or(self.created_at)
    }

    /// The user name, compared without case or surrounding spaces.
    fn username(&self) -> Option<String> {
        self.details
            .field_by_purpose(FieldPurpose::Username)
            .map(|f| f.value.trim().to_lowercase())
            .filter(|u| !u.is_empty())
    }

    /// Weaker when it holds the item's own words, as the editor shows it.
    fn strength(&self, password: &str) -> Strength {
        let username = self.username();
        let inputs: Vec<&str> = username.as_deref().into_iter().chain([self.title.as_str()]).filter(|s| !s.trim().is_empty()).collect();
        strength(password, &inputs)
    }

    fn is_login(&self) -> bool {
        matches!(self.category, Category::Login | Category::Password)
    }

    fn has_totp(&self) -> bool {
        self.details.all_fields().any(|f| f.kind == FieldKind::Totp && !f.value.trim().is_empty())
    }

    fn sites(&self) -> HashSet<String> {
        self.urls.iter().filter_map(|u| url_host(&u.href)).map(|h| site_of(&h)).collect()
    }
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
        out.push(Entry {
            id: id.clone(),
            title: o.title.clone(),
            ignored: o.sentinel_ignored.clone(),
            category: o.category,
            urls: o.urls.clone(),
            created_at: o.created_at,
            details,
        });
    }
    Ok(out)
}

pub async fn report(app: &AppHandle) -> AppResult<HealthReport> {
    let state = app.state::<AppState>();
    let entries = entries(&state).await?;
    let now = now_secs();
    let mut report = HealthReport::default();
    let mut by_password: HashMap<&str, Vec<String>> = HashMap::new();
    for entry in &entries {
        // Every ignored alert is listed, so it can be watched again.
        report.ignored.extend(entry.ignored.iter().map(|alert| (entry.id.clone(), alert.clone())));
        let skip = |alert: &str| entry.ignores(alert);
        if let Some(password) = entry.password() {
            report.checked += 1;
            let strength = entry.strength(password);
            report.levels.insert(entry.id.clone(), strength.level);
            if strength.score < 3 && !skip("weak") {
                report.weak.push(entry.id.clone());
            }
            // Grouped even when ignored: the other items still share it.
            by_password.entry(password).or_default().push(entry.id.clone());
        }
        if entry.urls.iter().any(|u| unsecured(&u.href)) && !skip("unsecured") {
            report.unsecured.push(entry.id.clone());
        }
        if let Some(expires_at) = expiry(&entry.details)
            && expires_at - now < EXPIRING_SOON
            && !skip("expiring")
        {
            report.expiring.push(Expiry { id: entry.id.clone(), expires_at, expired: expires_at < now });
        }
    }
    report.reused = by_password.into_values().filter(|ids| ids.len() > 1).collect();
    report.duplicates = duplicate_accounts(&entries);
    report.expiring.sort_by_key(|e| e.expires_at);

    // Online alerts, from the last check and the lists on disk.
    let key = checks_key(&state).await?;
    let checks = key.load(&state.store());
    for entry in &entries {
        let Some(password) = entry.password() else { continue };
        match checks.seen.get(&key.id(password)) {
            Some(&seen) if seen > 0 && !entry.ignores("breached") => report.breached.push((entry.id.clone(), seen)),
            Some(_) => {}
            None => report.unchecked += 1,
        }
    }
    report.passwords_checked_at = checks.checked_at;
    if checks.checked_at.is_none() {
        report.pending.push("breached");
    }
    let lists = lists(app);
    for kind in LISTS {
        let Some(list) = lists.get(&kind) else {
            report.pending.push(kind.alert());
            continue;
        };
        match kind {
            ListKind::Breaches => report.compromised = compromised(&entries, &list.sites),
            ListKind::TwoFactor => report.two_factor = missing_two_factor(&entries, &list.sites),
            ListKind::Passkeys => report.passkeys = missing_passkeys(&entries, &list.sites),
        }
    }
    report.lists_updated_at = LISTS.iter().map(|kind| lists.get(kind).map(|list| list.fetched_at)).collect::<Option<Vec<_>>>().and_then(|at| at.into_iter().min());
    // New passwords: checked in the background, with the setting on.
    if report.unchecked > 0 {
        state.sentinel.wake.notify_one();
    }
    Ok(report)
}

/// A password being typed in the editor: its strength (against the item's
/// own words, like its user name) and how many other items already use it.
/// Nothing leaves this device.
pub async fn check_password(state: &AppState, password: &str, item_id: Option<&str>, inputs: &[&str]) -> AppResult<PasswordCheck> {
    let entries = entries(state).await?;
    let reused = entries.iter().filter(|e| Some(e.id.as_str()) != item_id && e.password() == Some(password)).count();
    Ok(PasswordCheck { level: strength(password, inputs).level, reused })
}

/// Groups of logins for the same account: the first website's site and the
/// user name. Grouped even when ignored, like reused passwords.
fn duplicate_accounts(entries: &[Entry]) -> Vec<Vec<String>> {
    let mut by_account: HashMap<(String, String), Vec<String>> = HashMap::new();
    for entry in entries.iter().filter(|e| e.is_login()) {
        let site = entry.urls.first().and_then(|u| url_host(&u.href)).map(|h| site_of(&h));
        if let (Some(site), Some(user)) = (site, entry.username()) {
            by_account.entry((site, user)).or_default().push(entry.id.clone());
        }
    }
    by_account.into_values().filter(|ids| ids.len() > 1).collect()
}

/// A website on plain `http` that is not on this computer or the local
/// network (routers, printers and the like rarely have a choice).
fn unsecured(href: &str) -> bool {
    let href = href.trim();
    if !href.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://")) {
        return false;
    }
    let Some(host) = url_host(href) else { return false };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return !match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
    }
    let local = [".localhost", ".local", ".lan", ".home", ".internal", ".home.arpa", ".test"];
    !(host == "localhost" || !host.contains('.') || local.iter().any(|s| host.ends_with(s)))
}

/// Labels of fields that hold an expiry date (the item templates' and what
/// people type in the three languages).
fn is_expiry_label(label: &str) -> bool {
    let label = label.to_lowercase();
    ["expir", "expires", "valid until", "validade", "vencimento", "vence", "caducidad", "vencimiento", "válido hasta"]
        .iter()
        .any(|word| label.contains(word))
}

/// The earliest expiry date in the item, in Unix seconds.
fn expiry(details: &ItemDetails) -> Option<i64> {
    details
        .all_fields()
        .filter(|f| matches!(f.kind, FieldKind::Date | FieldKind::MonthYear) && is_expiry_label(&f.label))
        .filter_map(|f| match f.kind {
            FieldKind::Date => parse_date(&f.value),
            // The end of the month.
            _ => parse_expiry(&f.value).map(|(month, year)| {
                let (year, month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
                unix_day(year as i64, month, 1) - 1
            }),
        })
        .min()
}

/// "2027-05-31" (as date inputs store it), at the end of that day.
fn parse_date(text: &str) -> Option<i64> {
    let mut parts = text.trim().splitn(3, '-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.get(..2)?.parse().ok()?;
    ((1900..=2200).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day)).then(|| unix_day(year, month, day) + 86_399)
}

/// Unix seconds at the start of a day (UTC), from Howard Hinnant's
/// days-from-civil.
pub(crate) fn unix_day(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400
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
}

// ----- public lists -----------------------------------------------------------

/// The public lists of websites, kept on disk so Sentinel works offline, and
/// downloaded again once a day. A new copy replaces the old one only once it
/// downloaded whole and reads as a real list; otherwise the old one stays.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ListKind {
    /// Have I Been Pwned's breaches.
    Breaches,
    /// 2fa.directory's websites with one-time codes.
    TwoFactor,
    /// The Passkeys Directory.
    Passkeys,
}

const LISTS: [ListKind; 3] = [ListKind::Breaches, ListKind::TwoFactor, ListKind::Passkeys];

impl ListKind {
    fn url(self) -> &'static str {
        match self {
            Self::Breaches => "https://haveibeenpwned.com/api/v3/breaches",
            Self::TwoFactor => "https://api.2fa.directory/v3/totp.json",
            Self::Passkeys => "https://passkeys-api.2fa.directory/v1/supported.json",
        }
    }

    fn file(self) -> &'static str {
        match self {
            Self::Breaches => "breaches.json",
            Self::TwoFactor => "two-factor.json",
            Self::Passkeys => "passkeys.json",
        }
    }

    /// The alert the list is for.
    fn alert(self) -> &'static str {
        match self {
            Self::Breaches => "compromised",
            Self::TwoFactor => "two_factor",
            Self::Passkeys => "passkey",
        }
    }

    /// A list with fewer sites than this is a broken download, not the real
    /// one: they have hundreds to thousands.
    fn min_sites(self) -> usize {
        match self {
            Self::Breaches => 100,
            Self::TwoFactor => 200,
            Self::Passkeys => 50,
        }
    }

    fn parse(self, body: &[u8]) -> AppResult<Sites> {
        let sites = match self {
            Self::Breaches => sites_from_breaches(serde_json::from_slice(body)?),
            Self::TwoFactor => sites_from_directory(&serde_json::from_slice(body)?),
            Self::Passkeys => sites_from_passkey_directory(&serde_json::from_slice(body)?),
        };
        if sites.len() < self.min_sites() {
            return Err(AppError::Server(format!("{} looks incomplete ({} sites)", self.file(), sites.len())));
        }
        Ok(sites)
    }
}

/// Site (registrable domain) -> the date of its latest breach, for breached
/// websites; empty for the others.
type Sites = HashMap<String, String>;

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
    Ok(Some(SiteList { sites: kind.parse(&body)?, fetched_at }))
}

/// Downloads the lists older than `max_age` seconds. Returns whether any was
/// updated; fails only when none of them could be.
async fn refresh_lists(app: &AppHandle, max_age: i64) -> AppResult<bool> {
    let now = now_secs();
    let current = lists(app);
    let due: Vec<ListKind> = LISTS
        .into_iter()
        // A list from the future: the clock was wrong.
        .filter(|kind| current.get(kind).is_none_or(|list| now - list.fetched_at >= max_age || list.fetched_at > now))
        .collect();
    if due.is_empty() {
        return Ok(false);
    }
    let client = client()?;
    let dir = lists_dir(app)?;
    let mut updated = false;
    let mut failure = None;
    for kind in due {
        match download_list(&client, &dir, kind).await {
            Ok(list) => {
                let state = app.state::<AppState>();
                let mut lists = state.sentinel.lists.lock().unwrap_or_else(|e| e.into_inner());
                lists.get_or_insert_with(Lists::new).insert(kind, Arc::new(list));
                updated = true;
            }
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

async fn download_list(client: &reqwest::Client, dir: &Path, kind: ListKind) -> AppResult<SiteList> {
    let body = get_list(client, kind.url()).await?;
    let sites = kind.parse(&body)?;
    replace_file(dir, kind.file(), &body)?;
    Ok(SiteList { sites, fetched_at: now_secs() })
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

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Breach {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    breach_date: String,
    #[serde(default)]
    data_classes: Vec<String>,
    #[serde(default)]
    is_verified: bool,
    #[serde(default)]
    is_fabricated: bool,
    #[serde(default)]
    is_spam_list: bool,
}

/// Site -> date of its latest verified breach that exposed passwords, from
/// Have I Been Pwned's list.
fn sites_from_breaches(list: Vec<Breach>) -> Sites {
    let mut sites = Sites::new();
    for breach in list {
        if breach.domain.is_empty() || !breach.is_verified || breach.is_fabricated || breach.is_spam_list {
            continue;
        }
        if !breach.data_classes.iter().any(|c| c == "Passwords") || parse_date(&breach.breach_date).is_none() {
            continue;
        }
        let Some(host) = url_host(&breach.domain) else { continue };
        let entry = sites.entry(site_of(&host)).or_default();
        if breach.breach_date > *entry {
            *entry = breach.breach_date;
        }
    }
    sites
}

fn compromised(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    let mut issues = Vec::new();
    for entry in entries.iter().filter(|e| e.password().is_some() && !e.ignores("compromised")) {
        for site in entry.sites() {
            let Some(date) = sites.get(&site) else { continue };
            // The breach happened (or ended) after this password was set.
            if parse_date(date).is_some_and(|breached_at| entry.password_set_at() < breached_at) {
                issues.push(SiteIssue { id: entry.id.clone(), site, date: Some(date.clone()) });
                break;
            }
        }
    }
    issues
}

/// Sites that offer one-time password codes, from 2fa.directory: a list of
/// `[name, {domain, additional-domains, ...}]`.
fn sites_from_directory(list: &Value) -> Sites {
    let mut sites = Sites::new();
    for entry in list.as_array().into_iter().flatten() {
        let Some(info) = entry.get(1) else { continue };
        let domains = info.get("domain").into_iter().chain(info.get("additional-domains").and_then(Value::as_array).into_iter().flatten());
        for domain in domains.filter_map(Value::as_str) {
            if let Some(host) = url_host(domain) {
                sites.insert(site_of(&host), String::new());
            }
        }
    }
    sites
}

/// Sites that accept passkeys, from the Passkeys Directory
/// (passkeys.2fa.directory): `{domain: {passwordless, mfa, ...}}`, every
/// website with some passkey support. Big services list their subdomains
/// (mail.google.com), counted for the whole site (google.com).
fn sites_from_passkey_directory(list: &Value) -> Sites {
    list.as_object()
        .into_iter()
        .flatten()
        .filter_map(|(domain, _)| url_host(domain))
        .map(|host| (site_of(&host), String::new()))
        .collect()
}

fn missing_passkeys(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    entries
        .iter()
        .filter(|e| e.is_login() && e.details.passkeys.is_empty() && !e.ignores("passkey"))
        .filter_map(|e| e.sites().into_iter().find(|s| sites.contains_key(s)).map(|site| SiteIssue { id: e.id.clone(), site, date: None }))
        .collect()
}

fn missing_two_factor(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    entries
        .iter()
        .filter(|e| e.is_login() && e.password().is_some() && !e.has_totp() && !e.ignores("two_factor"))
        .filter_map(|e| e.sites().into_iter().find(|s| sites.contains_key(s)).map(|site| SiteIssue { id: e.id.clone(), site, date: None }))
        .collect()
}

// ----- breached passwords -----------------------------------------------------

/// What the online check found about the passwords. Kept in the local
/// database, encrypted with a key derived from the account key; passwords are
/// named by a keyed hash, so a password that changes is checked again.
#[derive(Serialize, Deserialize, Default)]
struct PasswordChecks {
    /// When every password was last checked (Unix seconds).
    checked_at: Option<i64>,
    /// Keyed hash of each password checked -> times seen in breaches (0: not
    /// seen).
    seen: HashMap<String, u64>,
}

struct ChecksKey {
    seal: SymmetricKey,
    ids: Hkdf<Sha256>,
}

impl ChecksKey {
    const ROW: &str = "passwords";

    fn new(account: &UnlockedAccount) -> AppResult<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"keyless/sentinel/v1"), account.user_key().as_bytes());
        let mut seal = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"seal", seal.as_mut()).map_err(|_| AppError::Server("sentinel key".into()))?;
        Ok(Self { seal: SymmetricKey::from_slice(seal.as_ref())?, ids: hkdf })
    }

    fn id(&self, password: &str) -> String {
        let mut id = [0u8; 16];
        let _ = self.ids.expand_multi_info(&[b"password:", password.as_bytes()], &mut id);
        hex::encode(id)
    }

    fn context() -> Vec<u8> {
        keyless_core::crypto::context("sentinel", &[Self::ROW])
    }

    /// Nothing yet, or another account's: nothing checked.
    fn load(&self, store: &Store) -> PasswordChecks {
        store
            .sentinel_data(Self::ROW)
            .ok()
            .flatten()
            .and_then(|data| self.seal.open(&data, &Self::context()).ok())
            .and_then(|plain| serde_json::from_slice(&plain).ok())
            .unwrap_or_default()
    }

    fn save(&self, store: &Store, checks: &PasswordChecks) -> AppResult<()> {
        let plain = Zeroizing::new(serde_json::to_vec(checks)?);
        store.set_sentinel_data(Self::ROW, &self.seal.seal(&plain, &Self::context())?)
    }
}

async fn checks_key(state: &AppState) -> AppResult<ChecksKey> {
    let guard = state.session.lock().await;
    ChecksKey::new(&guard.as_ref().ok_or(AppError::Locked)?.account)
}

/// Checks the passwords on Have I Been Pwned: all of them when the last full
/// check is older than `max_age` seconds, otherwise only the ones never
/// checked. Returns whether anything was checked.
async fn check_passwords(app: &AppHandle, max_age: i64) -> AppResult<bool> {
    let state = app.state::<AppState>();
    let entries = entries(&state).await?;
    let key = checks_key(&state).await?;
    let old = key.load(&state.store());
    let all = old.checked_at.is_none_or(|at| now_secs() - at >= max_age);
    // Keyed hash -> SHA-1, as Have I Been Pwned has it, of each password.
    let mut current: HashMap<String, String> = HashMap::new();
    for password in entries.iter().filter_map(Entry::password) {
        current.entry(key.id(password)).or_insert_with(|| hex::encode_upper(Sha1::digest(password.as_bytes())));
    }
    drop(entries);
    let to_check: HashMap<&String, &String> = current.iter().filter(|(id, _)| all || !old.seen.contains_key(*id)).collect();
    if !all && to_check.is_empty() {
        return Ok(false);
    }
    let found = breached_hashes(&client()?, to_check.values().copied()).await?;
    // Old passwords are forgotten.
    let mut seen: HashMap<String, u64> =
        if all { HashMap::new() } else { old.seen.into_iter().filter(|(id, _)| current.contains_key(id)).collect() };
    for (id, hash) in to_check {
        seen.insert(id.clone(), found.get(hash).copied().unwrap_or(0));
    }
    let checks = PasswordChecks { checked_at: if all { Some(now_secs()) } else { old.checked_at }, seen };
    // Not after signing out, which deletes the results.
    let guard = state.session.lock().await;
    if guard.is_none() {
        return Err(AppError::Locked);
    }
    key.save(&state.store(), &checks)?;
    Ok(true)
}

/// The SHA-1 hashes (uppercase hex) seen in breaches, with how often. Asks
/// Have I Been Pwned's range API with k-anonymity: only the first 5 characters
/// of each hash are sent, and the responses are padded.
async fn breached_hashes<'a>(client: &reqwest::Client, hashes: impl Iterator<Item = &'a String>) -> AppResult<HashMap<String, u64>> {
    let mut by_prefix: HashMap<&str, Vec<&str>> = HashMap::new();
    for hash in hashes {
        by_prefix.entry(&hash[..5]).or_default().push(&hash[5..]);
    }
    let mut found = HashMap::new();
    for (prefix, suffixes) in by_prefix {
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
            // Padding entries have a count of 0.
            if count > 0 && suffixes.contains(&suffix.trim()) {
                found.insert(format!("{prefix}{}", suffix.trim()), count);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use keyless_core::item::{Field, PasswordHistoryEntry};

    use super::*;

    #[test]
    fn strength_scores() {
        assert!(strength("password", &[]).score <= 1);
        assert!(strength("correct-horse-battery-staple-91", &[]).score >= 3);
        assert_eq!(strength("", &[]).score, 0);
    }

    #[test]
    fn strength_levels() {
        // The weak ones are the scores, so "weak" means the same.
        for score in 0..=3 {
            assert_eq!(level(score, 20.0), score);
        }
        assert_eq!(level(4, 10.5), 4);
        assert_eq!(level(4, 13.0), 5);
        assert_eq!(level(4, 16.0), 6);
        assert_eq!(strength("password", &[]).level, 0);
        assert_eq!(strength("8]bz-Pv&wu~AO5uEF?f{Uec>", &[]).level, 6);
    }

    #[test]
    fn plain_http_websites() {
        assert!(unsecured("http://example.com/login"));
        assert!(unsecured("HTTP://8.8.8.8"));
        assert!(!unsecured("https://example.com"));
        assert!(!unsecured("example.com"));
        for local in ["http://localhost:8080", "http://192.168.0.1", "http://10.1.2.3", "http://[::1]", "http://router.lan", "http://nas", "http://printer.local"] {
            assert!(!unsecured(local), "{local}");
        }
    }

    #[test]
    fn dates() {
        assert_eq!(unix_day(1970, 1, 1), 0);
        assert_eq!(unix_day(2000, 3, 1), 951_868_800);
        assert_eq!(parse_date("2024-02-29"), Some(unix_day(2024, 2, 29) + 86_399));
        assert_eq!(parse_date("29/02/2024"), None);
        let mut details = ItemDetails::default();
        let field = |label: &str, kind, value: &str| Field { id: label.into(), label: label.into(), kind, value: value.into(), purpose: None };
        details.fields = vec![field("expiry date", FieldKind::MonthYear, "05/2027"), field("birth date", FieldKind::Date, "1990-01-01")];
        // The end of May 2027, not the birth date.
        assert_eq!(expiry(&details), Some(unix_day(2027, 6, 1) - 1));
        details.sections = vec![];
        details.fields.push(field("Validade", FieldKind::Date, "2026-01-10"));
        assert_eq!(expiry(&details), Some(unix_day(2026, 1, 10) + 86_399));
    }

    fn login(id: &str, url: &str, created_at: i64, changed_at: Option<i64>, totp: bool) -> Entry {
        let mut details = ItemDetails::default();
        details.fields = vec![Field {
            id: "p".into(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: "secret".into(),
            purpose: Some(FieldPurpose::Password),
        }];
        if totp {
            details.fields.push(Field { id: "t".into(), label: "one-time password".into(), kind: FieldKind::Totp, value: "otpauth://x".into(), purpose: None });
        }
        if let Some(at) = changed_at {
            details.password_history.push(PasswordHistoryEntry { value: "old".into(), changed_at: at });
        }
        Entry {
            id: id.into(),
            title: String::new(),
            ignored: Vec::new(),
            category: Category::Login,
            urls: vec![ItemUrl { href: url.into(), ..Default::default() }],
            created_at,
            details,
        }
    }

    #[test]
    fn breached_websites() {
        let breaches: Vec<Breach> = serde_json::from_str(
            r#"[
              {"Name":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","DataClasses":["Email addresses","Passwords"],"IsVerified":true},
              {"Name":"Fake","Domain":"fake.com","BreachDate":"2020-01-01","DataClasses":["Passwords"],"IsVerified":true,"IsFabricated":true},
              {"Name":"Emails","Domain":"mail.example.org","BreachDate":"2021-05-01","DataClasses":["Email addresses"],"IsVerified":true}
            ]"#,
        )
        .unwrap();
        let sites = sites_from_breaches(breaches);
        assert_eq!(sites.len(), 1);
        let before = unix_day(2012, 1, 1);
        let after = unix_day(2014, 1, 1);
        let entries = [
            login("old", "https://accounts.adobe.com", before, None, false),
            login("changed", "https://adobe.com", before, Some(after), false),
            login("other", "https://example.org", before, None, false),
        ];
        let found = compromised(&entries, &sites);
        assert_eq!(found.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["old"]);
        assert_eq!(found[0].date.as_deref(), Some("2013-10-04"));
    }

    #[test]
    fn two_factor_support() {
        let list: Value = serde_json::from_str(
            r#"[["GitHub",{"domain":"github.com","additional-domains":["githubusercontent.com"]}],["Weird",{"name":"no domain"}]]"#,
        )
        .unwrap();
        let sites = sites_from_directory(&list);
        let entries = [
            login("plain", "https://github.com/login", 0, None, false),
            login("with-code", "https://github.com", 0, None, true),
            login("elsewhere", "https://example.com", 0, None, false),
        ];
        let found = missing_two_factor(&entries, &sites);
        assert_eq!(found.iter().map(|i| (i.id.as_str(), i.site.as_str())).collect::<Vec<_>>(), [("plain", "github.com")]);
    }

    #[test]
    fn passkey_support() {
        let list: Value = serde_json::from_str(
            r#"{"github.com":{"passwordless":"allowed"},"accounts.example.org":{"mfa":"allowed"},"mail.google.com":{"passwordless":"allowed"}}"#,
        )
        .unwrap();
        let sites = sites_from_passkey_directory(&list);
        let mut saved = login("saved", "https://github.com", 0, None, false);
        saved.details.passkeys.push(
            serde_json::from_value(serde_json::json!({"credentialId": "Y3JlZA", "rpId": "github.com", "userHandle": "dQ", "key": "a2V5"})).unwrap(),
        );
        let entries = [
            login("plain", "https://github.com/login", 0, None, false),
            saved,
            login("subdomain", "https://www.example.org", 0, None, false),
            login("elsewhere", "https://example.com", 0, None, false),
            // Listed as mail.google.com and others.
            login("google", "https://accounts.google.com/", 0, None, false),
        ];
        let mut found: Vec<(String, String)> = missing_passkeys(&entries, &sites).into_iter().map(|i| (i.id, i.site)).collect();
        found.sort();
        let expected = [("google", "google.com"), ("plain", "github.com"), ("subdomain", "example.org")];
        assert_eq!(found, expected.map(|(id, site)| (id.to_string(), site.to_string())));
    }

    #[test]
    fn incomplete_lists_are_refused() {
        let few = serde_json::to_vec(&serde_json::json!({"github.com": {}, "google.com": {}})).unwrap();
        assert!(ListKind::Passkeys.parse(&few).is_err());
        assert!(ListKind::Passkeys.parse(b"<html>maintenance</html>").is_err());
        let many: serde_json::Map<String, Value> = (0..60).map(|i| (format!("site{i}.com"), serde_json::json!({}))).collect();
        let sites = ListKind::Passkeys.parse(&serde_json::to_vec(&many).unwrap()).unwrap();
        assert_eq!(sites.len(), 60);
    }

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
    fn duplicate_items() {
        let with_user = |id: &str, url: &str, user: &str| {
            let mut entry = login(id, url, 0, None, false);
            entry.details.fields.push(Field { id: "u".into(), label: "username".into(), kind: FieldKind::Text, value: user.into(), purpose: Some(FieldPurpose::Username) });
            entry
        };
        let entries = [
            with_user("a", "https://github.com/login", "Ana@Example.com"),
            with_user("b", "https://www.github.com", " ana@example.com "),
            with_user("c", "https://github.com", "bob@example.com"),
            with_user("d", "https://gitlab.com", "ana@example.com"),
            login("e", "https://github.com", 0, None, false),
        ];
        let mut groups = duplicate_accounts(&entries);
        for group in &mut groups {
            group.sort();
        }
        assert_eq!(groups, [vec!["a".to_string(), "b".to_string()]]);
    }
}
