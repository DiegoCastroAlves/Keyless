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

use std::{
    collections::{BTreeSet, HashMap, HashSet},
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
    error::{AppError, AppResult, Msg},
    state::{AppState, Settings},
    store::Store,
};

/// Dates whose label says they expire, with no alert chosen, are reported
/// this many days ahead.
const DEFAULT_ALERT_DAYS: i64 = 30;
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
    /// Those whose website can simply move to `https` ("Use HTTPS"): on
    /// plain http's own port.
    pub https_ready: Vec<String>,
    pub expiring: Vec<Expiry>,
    /// Item ids whose password appears in known breaches, with the count.
    pub breached: Vec<(String, u64)>,
    /// Websites breached after the item's password was set.
    pub compromised: Vec<SiteIssue>,
    /// Websites that offer two-factor codes the item does not have.
    pub two_factor: Vec<SiteIssue>,
    /// Websites that accept passkeys, for items without one.
    pub passkeys: Vec<SiteIssue>,
    /// Logins imported from LastPass whose password was not changed since:
    /// LastPass's stored vaults were stolen in 2022.
    pub lastpass: Vec<String>,
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
    /// The ignored alerts that no longer apply (the problem was fixed), as
    /// far as can be known: (item id, alert).
    pub stale: Vec<(String, String)>,
    /// Alerts whose list is turned off in the settings.
    pub off: Vec<&'static str>,
    /// Item id -> its password's strength level (0 to 6, see `level`).
    pub levels: HashMap<String, u8>,
    /// Vault id -> how many of its passwords are at each strength level.
    pub strengths: HashMap<String, [usize; 7]>,
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
    /// What the list says about the breach, for breached websites.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breach: Option<BreachDetails>,
}

/// A website's breach, as Have I Been Pwned's list describes it.
#[derive(Clone, Default, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachDetails {
    /// The breach's name ("Adobe").
    pub title: String,
    /// What leaked, as the list words it ("Email addresses", "Passwords"…).
    pub data_classes: Vec<String>,
    /// Accounts in the breach.
    pub accounts: u64,
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
    imported_from: String,
    vault_id: String,
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
            imported_from: o.imported_from.clone(),
            vault_id: local.vault_id.clone(),
            details,
        });
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
    report.lists_updated_at = LISTS
        .into_iter()
        .filter(|kind| kind.enabled(&settings))
        .map(|kind| lists.get(&kind).map(|list| list.fetched_at))
        .collect::<Option<Vec<_>>>()
        .and_then(|at| at.into_iter().min());
    // New passwords: checked in the background, with the setting on.
    if wake && report.unchecked > 0 {
        state.sentinel.wake.notify_one();
    }
    Ok(report)
}

/// What the report compares the items with online.
struct Online<'a> {
    /// Times a password was seen in breaches; `None` when it was never
    /// checked.
    seen: &'a dyn Fn(&str) -> Option<u64>,
    /// Every password was checked at least once.
    checked: bool,
    /// The lists turned on and downloaded.
    lists: HashMap<ListKind, &'a Sites>,
    /// The lists turned off.
    off: Vec<ListKind>,
}

/// The report, from the items and what is known online (nothing is read or
/// downloaded here).
fn analyze(entries: &[Entry], online: &Online, now: i64) -> HealthReport {
    let mut report = HealthReport::default();
    // Every alert that applies, ignored or not: an ignored alert missing
    // here no longer applies.
    let mut found: HashSet<(String, &'static str)> = HashSet::new();
    let mut by_password: HashMap<&str, Vec<String>> = HashMap::new();
    for entry in entries {
        // Every ignored alert is listed, so it can be watched again.
        report.ignored.extend(entry.ignored.iter().map(|alert| (entry.id.clone(), alert.clone())));
        // Whether the alert shows: it applies and is not ignored.
        let mut shows = |alert: &'static str| {
            found.insert((entry.id.clone(), alert));
            !entry.ignores(alert)
        };
        if let Some(password) = entry.password() {
            report.checked += 1;
            let strength = entry.strength(password);
            report.levels.insert(entry.id.clone(), strength.level);
            report.strengths.entry(entry.vault_id.clone()).or_default()[usize::from(strength.level.min(6))] += 1;
            if strength.score < 3 && shows("weak") {
                report.weak.push(entry.id.clone());
            }
            // Grouped even when ignored: the other items still share it.
            by_password.entry(password).or_default().push(entry.id.clone());
            if entry.imported_from == "lastpass" && entry.details.password_history.is_empty() && shows("lastpass") {
                report.lastpass.push(entry.id.clone());
            }
            match (online.seen)(password) {
                Some(seen) if seen > 0 && shows("breached") => report.breached.push((entry.id.clone(), seen)),
                Some(_) => {}
                None => report.unchecked += 1,
            }
        }
        if entry.urls.iter().any(|u| unsecured(&u.href)) && shows("unsecured") {
            report.unsecured.push(entry.id.clone());
            if entry.urls.iter().any(|u| https_url(&u.href).is_some()) {
                report.https_ready.push(entry.id.clone());
            }
        }
        if let Some(expires_at) = expiry(&entry.details, now)
            && shows("expiring")
        {
            report.expiring.push(Expiry { id: entry.id.clone(), expires_at, expired: expires_at < now });
        }
    }
    report.reused = by_password.into_values().filter(|ids| ids.len() > 1).collect();
    report.duplicates = duplicate_accounts(entries);
    for (groups, alert) in [(&report.reused, "reused"), (&report.duplicates, "duplicate")] {
        found.extend(groups.iter().flatten().map(|id| (id.clone(), alert)));
    }
    report.expiring.sort_by_key(|e| e.expires_at);

    if !online.checked {
        report.pending.push("breached");
    }
    let by_id: HashMap<&str, &Entry> = entries.iter().map(|e| (e.id.as_str(), e)).collect();
    for kind in LISTS {
        if online.off.contains(&kind) {
            report.off.push(kind.alert());
            continue;
        }
        let Some(sites) = online.lists.get(&kind) else {
            report.pending.push(kind.alert());
            continue;
        };
        let issues = match kind {
            ListKind::Breaches => compromised(entries, sites),
            ListKind::TwoFactor => missing_two_factor(entries, sites),
            ListKind::Passkeys => missing_passkeys(entries, sites),
        };
        found.extend(issues.iter().map(|issue| (issue.id.clone(), kind.alert())));
        let shown = issues.into_iter().filter(|issue| !by_id.get(issue.id.as_str()).is_some_and(|e| e.ignores(kind.alert())));
        match kind {
            ListKind::Breaches => report.compromised = shown.collect(),
            ListKind::TwoFactor => report.two_factor = shown.collect(),
            ListKind::Passkeys => report.passkeys = shown.collect(),
        }
    }
    report.stale = stale_ignores(entries, &found, online);
    report
}

/// The ignored alerts that no longer apply: not among those `found`, and
/// knowable (an alert whose list is off or not downloaded, or a password
/// never checked online, could still apply).
fn stale_ignores(entries: &[Entry], found: &HashSet<(String, &'static str)>, online: &Online) -> Vec<(String, String)> {
    let mut stale = Vec::new();
    for entry in entries {
        for alert in &entry.ignored {
            let known = match alert.as_str() {
                "breached" => entry.password().is_none_or(|password| (online.seen)(password).is_some()),
                "weak" | "reused" | "unsecured" | "expiring" | "duplicate" | "lastpass" => true,
                list => LISTS.into_iter().any(|kind| kind.alert() == list && online.lists.contains_key(&kind)),
            };
            if known && !found.contains(&(entry.id.clone(), alert.as_str())) {
                stale.push((entry.id.clone(), alert.clone()));
            }
        }
    }
    stale
}

/// Serious alerts not announced yet (breached passwords and websites, dates
/// due, LastPass imports): a notification says how many there are, then
/// they are remembered (encrypted, like the checks). The first time, what is
/// there already is only remembered.
async fn notify_new_alerts(app: &AppHandle) -> AppResult<()> {
    let state = app.state::<AppState>();
    let report = compute(app, false).await?;
    let key = checks_key(&state).await?;
    let previous: Option<BTreeSet<String>> = key.load_row(&state.store(), ChecksKey::NOTIFIED);
    let current = announced(&report, previous.as_ref());
    key.save_row(&state.store(), ChecksKey::NOTIFIED, &current)?;
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
    let reused = entries.iter().filter(|e| Some(e.id.as_str()) != item_id && e.password() == Some(password)).count();
    Ok(PasswordCheck { level: strength(password, inputs).level, reused })
}

/// Groups of logins for the same account in the same vault: the first
/// website's site and the user name (a copy in another vault, shared with
/// other people, is on purpose). Grouped even when ignored, like reused
/// passwords.
fn duplicate_accounts(entries: &[Entry]) -> Vec<Vec<String>> {
    let mut by_account: HashMap<(String, String, String), Vec<String>> = HashMap::new();
    for entry in entries.iter().filter(|e| e.is_login()) {
        let site = entry.urls.first().and_then(|u| url_host(&u.href)).map(|h| site_of(&h));
        if let (Some(site), Some(user)) = (site, entry.username()) {
            by_account.entry((entry.vault_id.clone(), site, user)).or_default().push(entry.id.clone());
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

/// The website on `https` instead of plain `http`, for an address
/// `unsecured` reports on plain http's own port (none, or 80, which is
/// dropped); `None` for any other: a server on another port rarely answers
/// https there.
pub fn https_url(href: &str) -> Option<String> {
    if !unsecured(href) {
        return None;
    }
    let rest = &href.trim()[7..];
    let (authority, path) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let port = match host.strip_prefix('[') {
        Some(v6) => v6.split_once("]:").map(|(_, port)| port),
        None => host.rsplit_once(':').map(|(_, port)| port),
    };
    let authority = match port {
        None => authority,
        Some(port @ ("" | "80")) => &authority[..authority.len() - port.len() - 1],
        Some(_) => return None,
    };
    Some(format!("https://{authority}{path}"))
}

/// "Use HTTPS" on an item's addresses: the ones on plain http's own port
/// move to https. Refused for an item in Recently Deleted (saving it would
/// restore it), and when no address can simply switch.
fn switch_to_https(urls: &mut [ItemUrl], trashed: bool) -> AppResult<()> {
    if trashed {
        return Err(AppError::Invalid(Msg::new("https_trashed")));
    }
    let mut changed = false;
    for url in urls {
        if let Some(https) = https_url(&url.href) {
            url.href = https;
            changed = true;
        }
    }
    if !changed {
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

/// Labels of fields that hold an expiry date (the item templates' and what
/// people type in the three languages).
fn is_expiry_label(label: &str) -> bool {
    let label = label.to_lowercase();
    ["expir", "expires", "valid until", "validade", "vencimento", "vence", "caducidad", "vencimiento", "válido hasta"]
        .iter()
        .any(|word| label.contains(word))
}

/// The earliest date in the item that is due to be warned about at `now`,
/// in Unix seconds: a date field warns as early as its alert says, or, with
/// no alert chosen, a month ahead when its label says it expires.
fn expiry(details: &ItemDetails, now: i64) -> Option<i64> {
    details
        .all_fields()
        .filter(|f| f.kind.is_date())
        .filter_map(|f| {
            let ahead = match f.extra.alert {
                Some(alert) => alert.days()?,
                None if is_expiry_label(&f.label) => DEFAULT_ALERT_DAYS,
                None => return None,
            };
            let at = match f.kind {
                FieldKind::Date => parse_date(&f.value)?,
                // The end of the month.
                _ => parse_expiry(&f.value).map(|(month, year)| {
                    let (year, month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
                    unix_day(year as i64, month, 1) - 1
                })?,
            };
            (at - now < ahead * 86_400).then_some(at)
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

    /// Turned on in the settings.
    fn enabled(self, settings: &Settings) -> bool {
        match self {
            Self::Breaches => settings.sentinel_breach_list,
            Self::TwoFactor => settings.sentinel_two_factor_list,
            Self::Passkeys => settings.sentinel_passkey_list,
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

/// Site (registrable domain) -> what the list says about it.
type Sites = HashMap<String, SiteInfo>;

/// For breached websites, the latest breach that exposed passwords; nothing
/// for the other lists.
#[derive(Clone, Default)]
struct SiteInfo {
    /// The breach date (YYYY-MM-DD).
    date: String,
    details: BreachDetails,
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
    Ok(Some(SiteList { sites: kind.parse(&body)?, fetched_at }))
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
            let sites = kind.parse(&body)?;
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

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Breach {
    #[serde(default)]
    title: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    breach_date: String,
    #[serde(default)]
    pwn_count: u64,
    #[serde(default)]
    data_classes: Vec<String>,
    #[serde(default)]
    is_verified: bool,
    #[serde(default)]
    is_fabricated: bool,
    #[serde(default)]
    is_spam_list: bool,
}

/// Site -> its latest verified breach that exposed passwords, from Have I
/// Been Pwned's list.
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
        if breach.breach_date > entry.date {
            *entry = SiteInfo {
                date: breach.breach_date,
                details: BreachDetails { title: breach.title, data_classes: breach.data_classes, accounts: breach.pwn_count },
            };
        }
    }
    sites
}

/// Logins whose website was breached after their password was set (ignored
/// or not).
fn compromised(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    let mut issues = Vec::new();
    for entry in entries.iter().filter(|e| e.password().is_some()) {
        for site in entry.sites() {
            let Some(info) = sites.get(&site) else { continue };
            // The breach happened (or ended) after this password was set.
            if parse_date(&info.date).is_some_and(|breached_at| entry.password_set_at() < breached_at) {
                issues.push(SiteIssue { id: entry.id.clone(), site, date: Some(info.date.clone()), breach: Some(info.details.clone()) });
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
                sites.insert(site_of(&host), SiteInfo::default());
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
        .map(|host| (site_of(&host), SiteInfo::default()))
        .collect()
}

/// Logins without a passkey for a website that accepts them (ignored or
/// not).
fn missing_passkeys(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    entries
        .iter()
        .filter(|e| e.is_login() && e.details.passkeys.is_empty())
        .filter_map(|e| e.sites().into_iter().find(|s| sites.contains_key(s)).map(|site| SiteIssue { id: e.id.clone(), site, date: None, breach: None }))
        .collect()
}

/// Logins without one-time codes for a website that offers them (ignored or
/// not).
fn missing_two_factor(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    entries
        .iter()
        .filter(|e| e.is_login() && e.password().is_some() && !e.has_totp())
        .filter_map(|e| e.sites().into_iter().find(|s| sites.contains_key(s)).map(|site| SiteIssue { id: e.id.clone(), site, date: None, breach: None }))
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
    /// The alerts already announced.
    const NOTIFIED: &str = "notified";

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

    fn context(row: &str) -> Vec<u8> {
        keyless_core::crypto::context("sentinel", &[row])
    }

    /// Nothing yet, or another account's: nothing checked.
    fn load(&self, store: &Store) -> PasswordChecks {
        self.load_row(store, Self::ROW).unwrap_or_default()
    }

    fn save(&self, store: &Store, checks: &PasswordChecks) -> AppResult<()> {
        self.save_row(store, Self::ROW, checks)
    }

    fn load_row<T: serde::de::DeserializeOwned>(&self, store: &Store, row: &str) -> Option<T> {
        store
            .sentinel_data(row)
            .ok()
            .flatten()
            .and_then(|data| self.seal.open(&data, &Self::context(row)).ok())
            .and_then(|plain| serde_json::from_slice(&plain).ok())
    }

    fn save_row<T: Serialize>(&self, store: &Store, row: &str, value: &T) -> AppResult<()> {
        let plain = Zeroizing::new(serde_json::to_vec(value)?);
        store.set_sentinel_data(row, &self.seal.seal(&plain, &Self::context(row))?)
    }
}

/// Sentinel data that never leaves this device (the developer scan's
/// ignored findings), encrypted like the checks.
pub(crate) async fn load_private<T: serde::de::DeserializeOwned>(state: &AppState, row: &str) -> AppResult<Option<T>> {
    let key = checks_key(state).await?;
    Ok(key.load_row(&state.store(), row))
}

pub(crate) async fn save_private<T: Serialize>(state: &AppState, row: &str, value: &T) -> AppResult<()> {
    let key = checks_key(state).await?;
    key.save_row(&state.store(), row, value)
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
        let field = |label: &str, kind, value: &str| Field { id: label.into(), label: label.into(), kind, value: value.into(), purpose: None, extra: Default::default() };
        details.fields = vec![field("expiry date", FieldKind::MonthYear, "05/2027"), field("birth date", FieldKind::Date, "1990-01-01")];
        let may_2027 = unix_day(2027, 5, 15);
        // The end of May 2027, not the birth date.
        assert_eq!(expiry(&details, may_2027), Some(unix_day(2027, 6, 1) - 1));
        // A month ahead by default: not yet in March.
        assert_eq!(expiry(&details, unix_day(2027, 3, 1)), None);
        details.sections = vec![];
        details.fields.push(field("Validade", FieldKind::Date, "2026-01-10"));
        assert_eq!(expiry(&details, may_2027), Some(unix_day(2026, 1, 10) + 86_399));

        // Alerts chosen per field: any date, as far ahead as asked; never.
        use keyless_core::item::ExpiryAlert;
        let mut details = ItemDetails::default();
        let mut renewal = field("renewal", FieldKind::Date, "2027-09-01");
        renewal.extra.alert = Some(ExpiryAlert::SixMonths);
        let mut card = field("expiry date", FieldKind::MonthYear, "05/2027");
        card.extra.alert = Some(ExpiryAlert::Never);
        details.fields = vec![renewal, card];
        assert_eq!(expiry(&details, unix_day(2027, 4, 1)), Some(unix_day(2027, 9, 1) + 86_399));
        assert_eq!(expiry(&details, unix_day(2027, 2, 1)), None);
    }

    fn login(id: &str, url: &str, created_at: i64, changed_at: Option<i64>, totp: bool) -> Entry {
        let mut details = ItemDetails::default();
        details.fields = vec![Field {
            id: "p".into(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: "secret".into(),
            purpose: Some(FieldPurpose::Password),
            extra: Default::default(),
        }];
        if totp {
            details.fields.push(Field { id: "t".into(), label: "one-time password".into(), kind: FieldKind::Totp, value: "otpauth://x".into(), purpose: None, extra: Default::default() });
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
            imported_from: String::new(),
            vault_id: "v".into(),
            details,
        }
    }

    #[test]
    fn breached_websites() {
        let breaches: Vec<Breach> = serde_json::from_str(
            r#"[
              {"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165,"DataClasses":["Email addresses","Passwords"],"IsVerified":true},
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
        // "Learn more": the list's own words about the breach.
        let details = found[0].breach.as_ref().unwrap();
        assert_eq!(details.title, "Adobe");
        assert_eq!(details.data_classes, ["Email addresses", "Passwords"]);
        assert_eq!(details.accounts, 152_445_165);
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

    fn with_password(mut entry: Entry, password: &str) -> Entry {
        entry.details.fields[0].value = password.into();
        entry
    }

    fn ignoring(mut entry: Entry, alerts: &[&str]) -> Entry {
        entry.ignored = alerts.iter().map(|a| a.to_string()).collect();
        entry
    }

    /// Nothing checked online, and no lists.
    fn offline<'a>(seen: &'a dyn Fn(&str) -> Option<u64>) -> Online<'a> {
        Online { seen, checked: false, lists: HashMap::new(), off: Vec::new() }
    }

    const STRONG: &str = "8]bz-Pv&wu~AO5uEF?f{Uec>";

    #[test]
    fn stale_ignores() {
        let entries = [
            // Fixed since they were ignored.
            ignoring(with_password(login("fixed-weak", "https://a.com", 0, None, false), STRONG), &["weak"]),
            ignoring(with_password(login("https-now", "https://b.com", 0, None, false), "Zq8!vT3#mW9$kL2@"), &["unsecured"]),
            ignoring(with_password(login("clean", "https://c.com", 0, None, false), "checked-and-clean-Q7#"), &["breached"]),
            ignoring(with_password(login("alone", "https://d.com", 0, None, false), "only-here-R5$x9!Lp"), &["reused"]),
            // Still true.
            ignoring(with_password(login("still-weak", "https://e.com", 0, None, false), "password"), &["weak"]),
            ignoring(with_password(login("still-http", "http://example.com", 0, None, false), "Hn4#pX8!rT2$wQ6@"), &["unsecured"]),
            ignoring(with_password(login("shared-1", "https://f.com", 0, None, false), "shared-Pw-9#kL"), &["reused"]),
            with_password(login("shared-2", "https://g.com", 0, None, false), "shared-Pw-9#kL"),
            // Cannot be known: never checked online, list off or missing, an
            // alert this version does not know.
            ignoring(with_password(login("unchecked", "https://h.com", 0, None, false), "never-checked-W3!"), &["breached"]),
            ignoring(login("two-factor-off", "https://github.com", 0, None, false), &["two_factor"]),
            ignoring(login("passkey-missing", "https://github.com", 0, None, false), &["passkey"]),
            ignoring(login("future", "https://i.com", 0, None, false), &["something_new"]),
        ];
        let seen = |password: &str| (password == "checked-and-clean-Q7#").then_some(0);
        let online = Online { off: vec![ListKind::TwoFactor], ..offline(&seen) };
        let report = analyze(&entries, &online, 0);
        let mut stale: Vec<(&str, &str)> = report.stale.iter().map(|(id, alert)| (id.as_str(), alert.as_str())).collect();
        stale.sort();
        assert_eq!(stale, [("alone", "reused"), ("clean", "breached"), ("fixed-weak", "weak"), ("https-now", "unsecured")]);
        // Ignored alerts stay out of their lists, and all are listed as ignored.
        assert!(!report.weak.contains(&"still-weak".to_string()));
        assert!(!report.unsecured.contains(&"still-http".to_string()));
        assert_eq!(report.ignored.len(), 11);
    }

    #[test]
    fn strength_counts() {
        let in_vault = |id: &str, vault: &str, password: &str| {
            let mut entry = with_password(login(id, "https://example.com", 0, None, false), password);
            entry.vault_id = vault.into();
            entry
        };
        let mut no_password = login("note", "https://example.com", 0, None, false);
        no_password.details.fields.clear();
        let entries = [in_vault("a", "personal", "password"), in_vault("b", "personal", STRONG), in_vault("c", "work", STRONG), no_password];
        let seen = |_: &str| None;
        let report = analyze(&entries, &offline(&seen), 0);
        assert_eq!(report.strengths["personal"], [1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(report.strengths["work"], [0, 0, 0, 0, 0, 0, 1]);
        // Every password checked is counted once, in its vault.
        assert_eq!(report.checked, 3);
        assert_eq!(report.strengths.values().flatten().sum::<usize>(), report.checked);
        assert_eq!(report.levels["a"], 0);
    }

    #[test]
    fn lists_turned_off() {
        let entries = [login("plain", "https://github.com/login", 0, None, false)];
        let list: Value = serde_json::from_str(r#"[["GitHub",{"domain":"github.com"}]]"#).unwrap();
        let sites = sites_from_directory(&list);
        let seen = |_: &str| None;
        let on = Online { lists: HashMap::from([(ListKind::TwoFactor, &sites)]), ..offline(&seen) };
        let report = analyze(&entries, &on, 0);
        assert_eq!(report.two_factor.len(), 1);
        assert_eq!(report.pending, ["breached", "compromised", "passkey"]);
        assert!(report.off.is_empty());
        let off = Online { off: vec![ListKind::TwoFactor, ListKind::Passkeys], ..offline(&seen) };
        let report = analyze(&entries, &off, 0);
        assert!(report.two_factor.is_empty());
        assert_eq!(report.off, ["two_factor", "passkey"]);
        assert_eq!(report.pending, ["breached", "compromised"]);
    }

    #[test]
    fn https_rewrite() {
        assert_eq!(https_url("http://example.com/login?next=/").as_deref(), Some("https://example.com/login?next=/"));
        assert_eq!(https_url(" HTTP://Example.com ").as_deref(), Some("https://Example.com"));
        // Plain http's own port goes.
        assert_eq!(https_url("http://example.com:80/a").as_deref(), Some("https://example.com/a"));
        assert_eq!(https_url("http://example.com:/a").as_deref(), Some("https://example.com/a"));
        assert_eq!(https_url("http://user:pw@example.com:80#top").as_deref(), Some("https://user:pw@example.com#top"));
        assert_eq!(https_url("http://[2001:db8::1]:80/").as_deref(), Some("https://[2001:db8::1]/"));
        assert_eq!(https_url("http://[2001:db8::1]/").as_deref(), Some("https://[2001:db8::1]/"));
        // Another port: https is unlikely to answer there.
        for href in ["http://example.com:8080/a", "http://user:pw@example.com:8000", "http://[2001:db8::1]:8080/"] {
            assert_eq!(https_url(href), None, "{href}");
        }
        // Already secure, or on the local network: left alone.
        for href in ["https://example.com", "http://192.168.0.1", "http://router.lan", "example.com"] {
            assert_eq!(https_url(href), None, "{href}");
        }
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
        // Offered only where it can work.
        let entries = [login("plain", "http://example.com", 0, None, false), login("port", "http://example.com:8080", 0, None, false)];
        let seen = |_: &str| None;
        let report = analyze(&entries, &offline(&seen), 0);
        assert_eq!(report.unsecured, ["plain", "port"]);
        assert_eq!(report.https_ready, ["plain"]);
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

    #[test]
    fn duplicate_items() {
        let with_user = |id: &str, url: &str, user: &str| {
            let mut entry = login(id, url, 0, None, false);
            entry.details.fields.push(Field { id: "u".into(), label: "username".into(), kind: FieldKind::Text, value: user.into(), purpose: Some(FieldPurpose::Username), extra: Default::default() });
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
