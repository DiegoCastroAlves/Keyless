//! Sentinel: weak, reused and breached passwords, duplicate items, websites
//! without HTTPS, expiring cards and documents, websites breached since the
//! password was last changed, and websites that offer two-factor
//! authentication or passkeys the item does not use.
//!
//! What every app computes the same way; nothing is read, downloaded or
//! kept here. The apps bring what is known online:
//! - the public lists (Have I Been Pwned's breaches, 2fa.directory and its
//!   Passkeys Directory), which they download whole and keep, read here by
//!   [`ListKind::parse`];
//! - what Have I Been Pwned's range API answered about the passwords: a
//!   [`BreachCheck`] says what to ask (only the first 5 hex characters of
//!   each password's SHA-1 hash) and turns the answers into
//!   [`PasswordChecks`], which the apps keep encrypted with a [`ChecksKey`].

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
};

use hkdf::Hkdf;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::SymmetricKey,
    item::{Category, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl},
    site::{site_of, url_host},
};

/// Dates whose label says they expire, with no alert chosen, are reported
/// this many days ahead.
pub const DEFAULT_ALERT_DAYS: i64 = 30;
/// The public lists are a few megabytes; anything far larger is refused.
pub const MAX_LIST_BYTES: usize = 20 * 1024 * 1024;

/// Every alert, most serious first.
pub const ALERTS: [&str; 10] = ["breached", "compromised", "lastpass", "weak", "reused", "unsecured", "expiring", "two_factor", "passkey", "duplicate"];
/// The alerts that lower the score: problems with the password itself.
pub const SCORED_ALERTS: [&str; 6] = ["breached", "compromised", "lastpass", "weak", "reused", "unsecured"];

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Serialize)]
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
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BreachDetails {
    /// The breach's name ("Adobe").
    pub title: String,
    /// What leaked, as the list words it ("Email addresses", "Passwords"…).
    pub data_classes: Vec<String>,
    /// Accounts in the breach.
    pub accounts: u64,
}

impl BreachDetails {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
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

/// An active item (neither archived nor in Recently Deleted), as the checks
/// need it.
pub struct Entry {
    pub id: String,
    pub title: String,
    /// Alerts the user ignored for this item.
    pub ignored: Vec<String>,
    pub category: Category,
    pub urls: Vec<ItemUrl>,
    pub created_at: i64,
    pub imported_from: String,
    pub vault_id: String,
    pub details: ItemDetails,
}

impl Entry {
    /// An item, from its overview and its decrypted details.
    pub fn new(id: &str, vault_id: &str, overview: &ItemOverview, details: ItemDetails) -> Self {
        Self {
            id: id.to_string(),
            title: overview.title.clone(),
            ignored: overview.sentinel_ignored.clone(),
            category: overview.category,
            urls: overview.urls.clone(),
            created_at: overview.created_at,
            imported_from: overview.imported_from.clone(),
            vault_id: vault_id.to_string(),
            details,
        }
    }

    pub fn ignores(&self, alert: &str) -> bool {
        self.ignored.iter().any(|a| a == alert)
    }

    pub fn password(&self) -> Option<&str> {
        self.details.field_by_purpose(FieldPurpose::Password).map(|f| f.value.as_str()).filter(|p| !p.is_empty())
    }

    /// When the current password was set: when the previous one was
    /// replaced, or when the item was created.
    pub fn password_set_at(&self) -> i64 {
        self.details.password_history.iter().map(|h| h.changed_at).max().unwrap_or(self.created_at)
    }

    /// The user name, compared without case or surrounding spaces.
    pub fn username(&self) -> Option<String> {
        self.details
            .field_by_purpose(FieldPurpose::Username)
            .map(|f| f.value.trim().to_lowercase())
            .filter(|u| !u.is_empty())
    }

    /// Weaker when it holds the item's own words, as the editor shows it.
    pub fn strength(&self, password: &str) -> Strength {
        let username = self.username();
        let inputs: Vec<&str> = username.as_deref().into_iter().chain([self.title.as_str()]).filter(|s| !s.trim().is_empty()).collect();
        strength(password, &inputs)
    }

    pub fn is_login(&self) -> bool {
        matches!(self.category, Category::Login | Category::Password)
    }

    pub fn has_totp(&self) -> bool {
        self.details.all_fields().any(|f| f.kind == FieldKind::Totp && !f.value.trim().is_empty())
    }

    pub fn sites(&self) -> HashSet<String> {
        self.urls.iter().filter_map(|u| url_host(&u.href)).map(|h| site_of(&h)).collect()
    }
}

/// How many items other than `item_id` already use `password` (the
/// editor's check of a password being typed).
pub fn reuses(entries: &[Entry], password: &str, item_id: Option<&str>) -> usize {
    entries.iter().filter(|e| Some(e.id.as_str()) != item_id && e.password() == Some(password)).count()
}

/// What the report compares the items with online.
pub struct Online<'a> {
    /// Times a password was seen in breaches; `None` when it was never
    /// checked.
    pub seen: &'a dyn Fn(&str) -> Option<u64>,
    /// Every password was checked at least once.
    pub checked: bool,
    /// The lists turned on and downloaded.
    pub lists: HashMap<ListKind, &'a Sites>,
    /// The lists turned off.
    pub off: Vec<ListKind>,
}

/// The report, from the items and what is known online (nothing is read or
/// downloaded here).
pub fn analyze(entries: &[Entry], online: &Online, now: i64) -> HealthReport {
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

/// When the oldest of the lists turned on was downloaded (Unix seconds),
/// from each one's download time: `None` when one was never downloaded.
pub fn lists_updated_at(fetched_at: impl IntoIterator<Item = Option<i64>>) -> Option<i64> {
    fetched_at.into_iter().collect::<Option<Vec<_>>>().and_then(|at| at.into_iter().min())
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

/// Groups of logins for the same account in the same vault: the first
/// website's site and the user name (a copy in another vault, shared with
/// other people, is on purpose). Grouped even when ignored, like reused
/// passwords.
pub fn duplicate_accounts(entries: &[Entry]) -> Vec<Vec<String>> {
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
pub fn unsecured(href: &str) -> bool {
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
/// move to https. Returns whether any did (none can, otherwise). An item in
/// Recently Deleted is not to be changed this way: saving it would restore
/// it.
pub fn switch_to_https(urls: &mut [ItemUrl]) -> bool {
    let mut changed = false;
    for url in urls {
        if let Some(https) = https_url(&url.href) {
            url.href = https;
            changed = true;
        }
    }
    changed
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
pub fn expiry(details: &ItemDetails, now: i64) -> Option<i64> {
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

/// "MM/YYYY", "MM/YY", "YYYY-MM" or "MMYY" -> (month, four-digit year).
pub fn parse_expiry(text: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = text.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).collect();
    let (month, year) = match parts.as_slice() {
        [a, b] if a.len() == 4 => (b.parse().ok()?, a.parse().ok()?),
        [a, b] => (a.parse().ok()?, b.parse().ok()?),
        [ab] if ab.len() == 4 => (ab[..2].parse().ok()?, ab[2..].parse().ok()?),
        [ab] if ab.len() == 6 => (ab[..2].parse().ok()?, ab[2..].parse().ok()?),
        _ => return None,
    };
    let year: u32 = if year < 100 { 2000 + year } else { year };
    ((1..=12).contains(&month) && (2000..=2100).contains(&year)).then_some((month, year))
}

/// "2027-05-31" (as date inputs store it), at the end of that day.
pub fn parse_date(text: &str) -> Option<i64> {
    let mut parts = text.trim().splitn(3, '-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.get(..2)?.parse().ok()?;
    ((1900..=2200).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day)).then(|| unix_day(year, month, day) + 86_399)
}

/// Unix seconds at the start of a day (UTC), from Howard Hinnant's
/// days-from-civil.
pub fn unix_day(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400
}

// ----- what Sentinel shows ----------------------------------------------------

/// One alert on one item, as Sentinel's lists show it.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub id: String,
    /// Times the password was seen in breaches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen: Option<u64>,
    /// The website concerned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// When the website was breached (YYYY-MM-DD).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// When the item expires (Unix seconds), and whether it already did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    /// Other items with the same password, or for the same account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub others: Option<usize>,
    /// For a breached website: what the breach list says about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breach: Option<BreachDetails>,
}

/// Alert -> the items it applies to (each once), in the report's order.
pub type Issues = BTreeMap<&'static str, Vec<Issue>>;

impl HealthReport {
    /// The items each alert applies to, without the ones the user ignored;
    /// with `in_scope`, only the items it keeps (one vault's).
    pub fn issues(&self, in_scope: Option<&dyn Fn(&str) -> bool>) -> Issues {
        let ignored: HashSet<(&str, &str)> = self.ignored.iter().map(|(id, alert)| (id.as_str(), alert.as_str())).collect();
        let mut issues: Issues = ALERTS.into_iter().map(|alert| (alert, Vec::new())).collect();
        let mut add = |alert: &'static str, issue: Issue| {
            if !ignored.contains(&(issue.id.as_str(), alert)) && in_scope.is_none_or(|keep| keep(&issue.id)) {
                issues.entry(alert).or_default().push(issue);
            }
        };
        let item = |id: &str| Issue { id: id.to_string(), ..Default::default() };
        for id in &self.weak {
            add("weak", item(id));
        }
        for (groups, alert) in [(&self.reused, "reused"), (&self.duplicates, "duplicate")] {
            for group in groups {
                for id in group {
                    add(alert, Issue { others: Some(group.len() - 1), ..item(id) });
                }
            }
        }
        for id in &self.unsecured {
            add("unsecured", item(id));
        }
        for e in &self.expiring {
            add("expiring", Issue { expires_at: Some(e.expires_at), expired: Some(e.expired), ..item(&e.id) });
        }
        for (id, seen) in &self.breached {
            add("breached", Issue { seen: Some(*seen), ..item(id) });
        }
        for (list, alert) in [(&self.compromised, "compromised"), (&self.two_factor, "two_factor"), (&self.passkeys, "passkey")] {
            for issue in list {
                add(alert, Issue { site: Some(issue.site.clone()), date: issue.date.clone(), breach: issue.breach.clone(), ..item(&issue.id) });
            }
        }
        for id in &self.lastpass {
            add("lastpass", item(id));
        }
        issues
    }

    /// How many passwords are at each strength level (0 to 6), in one
    /// vault or (`None`) all of them.
    pub fn strength_counts(&self, vault: Option<&str>) -> [usize; 7] {
        let mut counts = [0; 7];
        for (id, levels) in &self.strengths {
            if vault.is_some_and(|vault| vault != id) {
                continue;
            }
            for (count, n) in counts.iter_mut().zip(levels) {
                *count += n;
            }
        }
        counts
    }
}

/// The score, 0 to 100: the share of the `checked` passwords without a
/// problem (an alert in `SCORED_ALERTS`).
pub fn score(issues: &Issues, checked: usize) -> u8 {
    if checked == 0 {
        return 100;
    }
    let problems: HashSet<&str> = SCORED_ALERTS.iter().filter_map(|alert| issues.get(alert)).flatten().map(|issue| issue.id.as_str()).collect();
    let share = (checked as f64 - problems.len() as f64) / checked as f64 * 100.0;
    share.round().max(0.0) as u8
}

/// What Sentinel's overview shows, for one vault or all of them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    /// The vault looked at; `None` for every vault.
    pub vault_id: Option<String>,
    /// 0 to 100, see `score`.
    pub score: u8,
    /// The passwords checked there.
    pub checked: usize,
    /// How many of them are at each strength level (0 to 6).
    pub strengths: [usize; 7],
    pub issues: Issues,
}

impl Summary {
    /// For `vault`, or every vault with `None`; `in_vault` says whether an
    /// item is in it.
    pub fn new(report: &HealthReport, vault: Option<&str>, in_vault: &dyn Fn(&str) -> bool) -> Self {
        let issues = report.issues(vault.map(|_| in_vault));
        let strengths = report.strength_counts(vault);
        let checked = strengths.iter().sum();
        Self { vault_id: vault.map(str::to_string), score: score(&issues, checked), checked, strengths, issues }
    }
}

// ----- public lists -----------------------------------------------------------

/// The public lists of websites. Each app downloads them (about once a day)
/// and keeps them, so Sentinel works offline; a new copy should replace the
/// old one only once it downloaded whole and `parse` accepts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ListKind {
    /// Have I Been Pwned's breaches.
    Breaches,
    /// 2fa.directory's websites with one-time codes.
    TwoFactor,
    /// The Passkeys Directory.
    Passkeys,
}

pub const LISTS: [ListKind; 3] = [ListKind::Breaches, ListKind::TwoFactor, ListKind::Passkeys];

/// A list that does not read as the real one.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Fewer sites than the real list has: a broken download.
    #[error("the list looks incomplete ({0} sites)")]
    Incomplete(usize),
}

impl ListKind {
    pub fn url(self) -> &'static str {
        match self {
            Self::Breaches => "https://haveibeenpwned.com/api/v3/breaches",
            Self::TwoFactor => "https://api.2fa.directory/v3/totp.json",
            Self::Passkeys => "https://passkeys-api.2fa.directory/v1/supported.json",
        }
    }

    /// The alert the list is for.
    pub fn alert(self) -> &'static str {
        match self {
            Self::Breaches => "compromised",
            Self::TwoFactor => "two_factor",
            Self::Passkeys => "passkey",
        }
    }

    /// A list with fewer sites than this is a broken download, not the real
    /// one: they have hundreds to thousands.
    pub fn min_sites(self) -> usize {
        match self {
            Self::Breaches => 100,
            Self::TwoFactor => 200,
            Self::Passkeys => 50,
        }
    }

    /// The sites in a list as downloaded.
    pub fn parse(self, body: &[u8]) -> std::result::Result<Sites, ListError> {
        let sites = match self {
            Self::Breaches => sites_from_breaches(serde_json::from_slice(body)?),
            Self::TwoFactor => sites_from_directory(&serde_json::from_slice(body)?),
            Self::Passkeys => sites_from_passkey_directory(&serde_json::from_slice(body)?),
        };
        if sites.len() < self.min_sites() {
            return Err(ListError::Incomplete(sites.len()));
        }
        Ok(sites)
    }
}

/// Site (registrable domain) -> what the list says about it.
pub type Sites = HashMap<String, SiteInfo>;

/// For breached websites, the latest breach that exposed passwords; nothing
/// for the other lists.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteInfo {
    /// The breach date (YYYY-MM-DD).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub date: String,
    #[serde(rename = "breach", skip_serializing_if = "BreachDetails::is_empty")]
    pub details: BreachDetails,
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
pub fn compromised(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
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
pub fn missing_passkeys(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    entries
        .iter()
        .filter(|e| e.is_login() && e.details.passkeys.is_empty())
        .filter_map(|e| e.sites().into_iter().find(|s| sites.contains_key(s)).map(|site| SiteIssue { id: e.id.clone(), site, date: None, breach: None }))
        .collect()
}

/// Logins without one-time codes for a website that offers them (ignored or
/// not).
pub fn missing_two_factor(entries: &[Entry], sites: &Sites) -> Vec<SiteIssue> {
    entries
        .iter()
        .filter(|e| e.is_login() && e.password().is_some() && !e.has_totp())
        .filter_map(|e| e.sites().into_iter().find(|s| sites.contains_key(s)).map(|site| SiteIssue { id: e.id.clone(), site, date: None, breach: None }))
        .collect()
}

// ----- breached passwords -----------------------------------------------------

/// What the online check found about the passwords. Kept encrypted with a
/// `ChecksKey`; passwords are named by a keyed hash, so a password that
/// changes is checked again.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PasswordChecks {
    /// When every password was last checked (Unix seconds).
    pub checked_at: Option<i64>,
    /// Keyed hash of each password checked -> times seen in breaches (0: not
    /// seen).
    pub seen: HashMap<String, u64>,
}

impl PasswordChecks {
    /// Whether the next check is of every password: the last full one is
    /// older than `max_age` seconds, or there was none.
    pub fn full_check_due(&self, max_age: i64, now: i64) -> bool {
        self.checked_at.is_none_or(|at| now - at >= max_age)
    }
}

/// The key of what Sentinel keeps about the items on a device (what the
/// online checks found, and the like), derived from the user key.
pub struct ChecksKey {
    seal: SymmetricKey,
    ids: Hkdf<Sha256>,
}

impl ChecksKey {
    /// The row of what the online checks found ([`PasswordChecks`]).
    pub const ROW: &str = "passwords";

    pub fn new(user_key: &SymmetricKey) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"keyless/sentinel/v1"), user_key.as_bytes());
        let mut seal = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"seal", seal.as_mut()).map_err(|_| Error::InvalidKey)?;
        Ok(Self { seal: SymmetricKey::from_slice(seal.as_ref())?, ids: hkdf })
    }

    /// A password's keyed hash: what names it in [`PasswordChecks`].
    pub fn id(&self, password: &str) -> String {
        let mut id = [0u8; 16];
        let _ = self.ids.expand_multi_info(&[b"password:", password.as_bytes()], &mut id);
        hex::encode(id)
    }

    fn context(row: &str) -> Vec<u8> {
        crate::crypto::context("sentinel", &[row])
    }

    /// `value` encrypted, for the row `row`.
    pub fn seal_row<T: Serialize>(&self, row: &str, value: &T) -> Result<String> {
        let plain = Zeroizing::new(serde_json::to_vec(value)?);
        self.seal.seal(&plain, &Self::context(row))
    }

    /// What `seal_row` encrypted for `row`; `None` when it does not open
    /// (another account's) or does not read.
    pub fn open_row<T: DeserializeOwned>(&self, row: &str, data: &str) -> Option<T> {
        self.seal.open(data, &Self::context(row)).ok().and_then(|plain| serde_json::from_slice(&plain).ok())
    }

    /// What the online checks found, as kept (`ROW`); nothing yet, or
    /// another account's: nothing checked.
    pub fn open_checks(&self, data: Option<&str>) -> PasswordChecks {
        data.and_then(|data| self.open_row(Self::ROW, data)).unwrap_or_default()
    }
}

/// A check of the passwords on Have I Been Pwned's range API, with
/// k-anonymity: only the first 5 characters of each password's SHA-1 hash
/// are sent, and the responses are padded, so the service never learns the
/// password or even which hash was looked up.
pub struct BreachCheck {
    /// Every password is checked again; otherwise only the ones never
    /// checked.
    pub all: bool,
    /// Keyed hash -> SHA-1, as Have I Been Pwned has it, of each password.
    current: HashMap<String, String>,
    /// The keyed hashes of the passwords to check.
    to_check: HashSet<String>,
}

impl BreachCheck {
    /// For the items' `passwords`, after the `old` checks: all of them with
    /// `all` (see `PasswordChecks::full_check_due`), otherwise only the ones
    /// never checked.
    pub fn new<'a>(key: &ChecksKey, passwords: impl IntoIterator<Item = &'a str>, old: &PasswordChecks, all: bool) -> Self {
        let mut current: HashMap<String, String> = HashMap::new();
        for password in passwords {
            current.entry(key.id(password)).or_insert_with(|| hex::encode_upper(Sha1::digest(password.as_bytes())));
        }
        let to_check = current.keys().filter(|id| all || !old.seen.contains_key(*id)).cloned().collect();
        Self { all, current, to_check }
    }

    /// Nothing to check: no new password, and no full check due.
    pub fn is_done(&self) -> bool {
        !self.all && self.to_check.is_empty()
    }

    /// The hashes to ask about (uppercase hex), by range: the first 5
    /// characters, which are all that is sent, -> the rest of each.
    pub fn ranges(&self) -> BTreeMap<&str, Vec<&str>> {
        let mut by_prefix: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for hash in self.to_check.iter().map(|id| &self.current[id]) {
            by_prefix.entry(&hash[..5]).or_default().push(&hash[5..]);
        }
        by_prefix
    }

    /// Checks only the passwords in the ranges `asked` keeps; the others
    /// (saved after the ranges were asked) stay unchecked.
    pub fn keep_ranges(&mut self, asked: impl Fn(&str) -> bool) {
        let current = &self.current;
        self.to_check.retain(|id| asked(&current[id][..5]));
    }

    /// The checks to keep, from the hashes seen in breaches (`found`, see
    /// `range_matches`): old passwords are forgotten.
    pub fn finish(self, old: PasswordChecks, found: &HashMap<String, u64>, now: i64) -> PasswordChecks {
        let mut seen: HashMap<String, u64> =
            if self.all { HashMap::new() } else { old.seen.into_iter().filter(|(id, _)| self.current.contains_key(id)).collect() };
        for id in self.to_check {
            let times = found.get(&self.current[&id]).copied().unwrap_or(0);
            seen.insert(id, times);
        }
        PasswordChecks { checked_at: if self.all { Some(now) } else { old.checked_at }, seen }
    }
}

/// The hashes (uppercase hex) a range response for `prefix` lists among
/// `suffixes`, with how often they were seen in breaches.
pub fn range_matches(prefix: &str, body: &str, suffixes: &[&str]) -> HashMap<String, u64> {
    let mut found = HashMap::new();
    for line in body.lines() {
        let Some((suffix, count)) = line.trim().split_once(':') else { continue };
        let count: u64 = count.trim().parse().unwrap_or(0);
        // Padding entries have a count of 0.
        if count > 0 && suffixes.contains(&suffix.trim()) {
            found.insert(format!("{prefix}{}", suffix.trim()), count);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::item::{Field, PasswordHistoryEntry};

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
    fn expiry_formats() {
        assert_eq!(parse_expiry("07/2029"), Some((7, 2029)));
        assert_eq!(parse_expiry("7/29"), Some((7, 2029)));
        assert_eq!(parse_expiry("2029-07"), Some((7, 2029)));
        assert_eq!(parse_expiry("0729"), Some((7, 2029)));
        assert_eq!(parse_expiry("13/29"), None);
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
        use crate::item::ExpiryAlert;
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
        assert!(matches!(ListKind::Passkeys.parse(&few), Err(ListError::Incomplete(2))));
        assert!(matches!(ListKind::Passkeys.parse(b"<html>maintenance</html>"), Err(ListError::Json(_))));
        let many: serde_json::Map<String, Value> = (0..60).map(|i| (format!("site{i}.com"), serde_json::json!({}))).collect();
        let sites = ListKind::Passkeys.parse(&serde_json::to_vec(&many).unwrap()).unwrap();
        assert_eq!(sites.len(), 60);
    }

    #[test]
    fn parsed_lists_round_trip() {
        // What an app keeps of a list once read, and reads back.
        let breaches: Vec<Breach> = serde_json::from_str(
            r#"[{"Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":3,"DataClasses":["Passwords"],"IsVerified":true}]"#,
        )
        .unwrap();
        let sites = sites_from_breaches(breaches);
        let kept = serde_json::to_value(&sites).unwrap();
        assert_eq!(kept, serde_json::json!({"adobe.com": {"date": "2013-10-04", "breach": {"title": "Adobe", "dataClasses": ["Passwords"], "accounts": 3}}}));
        assert_eq!(serde_json::from_value::<Sites>(kept).unwrap(), sites);
        let plain = Sites::from([("github.com".to_string(), SiteInfo::default())]);
        assert_eq!(serde_json::to_value(&plain).unwrap(), serde_json::json!({"github.com": {}}));
        assert_eq!(serde_json::from_value::<Sites>(serde_json::json!({"github.com": {}})).unwrap(), plain);
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
        assert_eq!(report.strength_counts(None), [1, 0, 0, 0, 0, 0, 2]);
        assert_eq!(report.strength_counts(Some("work")), [0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(report.strength_counts(Some("elsewhere")), [0; 7]);
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
    fn lists_age() {
        assert_eq!(lists_updated_at([Some(30), Some(10), Some(20)]), Some(10));
        // One never downloaded: not up to date.
        assert_eq!(lists_updated_at([Some(30), None]), None);
        assert_eq!(lists_updated_at([]), None);
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
        assert!(switch_to_https(&mut urls));
        assert_eq!(urls.map(|u| u.href), ["https://example.com/login", "http://example.com:8080/admin", "http://192.168.0.1"]);
        let mut urls = [url("http://example.com:8080")];
        assert!(!switch_to_https(&mut urls));
        assert_eq!(urls[0].href, "http://example.com:8080");
        // Offered only where it can work.
        let entries = [login("plain", "http://example.com", 0, None, false), login("port", "http://example.com:8080", 0, None, false)];
        let seen = |_: &str| None;
        let report = analyze(&entries, &offline(&seen), 0);
        assert_eq!(report.unsecured, ["plain", "port"]);
        assert_eq!(report.https_ready, ["plain"]);
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

    #[test]
    fn reused_while_typing() {
        let entries = [with_password(login("a", "https://a.com", 0, None, false), "same-one"), with_password(login("b", "https://b.com", 0, None, false), "same-one")];
        assert_eq!(reuses(&entries, "same-one", None), 2);
        // The item being edited does not count.
        assert_eq!(reuses(&entries, "same-one", Some("a")), 1);
        assert_eq!(reuses(&entries, "another", None), 0);
    }

    #[test]
    fn scoped_issues_and_score() {
        let in_vault = |id: &str, vault: &str, password: &str, url: &str| {
            let mut entry = with_password(login(id, url, 0, None, false), password);
            entry.vault_id = vault.into();
            entry
        };
        let entries = [
            // Weak, reused across vaults, and on plain http.
            in_vault("weak", "personal", "password", "http://example.com"),
            in_vault("copy", "work", "password", "https://example.org"),
            // Fine, and weak but ignored.
            in_vault("fine", "personal", STRONG, "https://a.com"),
            ignoring(in_vault("ignored", "personal", "12345678", "https://b.com"), &["weak"]),
            in_vault("strong", "work", "x$7Lq!92mZ@pR4#vN8&kT1", "https://c.com"),
        ];
        let seen = |password: &str| Some(if password == "password" { 12 } else { 0 });
        let report = analyze(&entries, &Online { checked: true, ..offline(&seen) }, 0);
        let issues = report.issues(None);
        let ids = |alert: &str| issues[alert].iter().map(|i| i.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids("weak"), ["weak", "copy"]);
        let mut reused = ids("reused");
        reused.sort();
        assert_eq!(reused, ["copy", "weak"]);
        assert!(issues["reused"].iter().all(|i| i.others == Some(1)));
        assert_eq!(issues["breached"].iter().map(|i| (i.id.as_str(), i.seen)).collect::<Vec<_>>(), [("weak", Some(12)), ("copy", Some(12))]);
        assert_eq!(ids("unsecured"), ["weak"]);
        assert!(issues["passkey"].is_empty() && issues.len() == ALERTS.len());
        // "ignored" is weak but ignored: no problem for the score. 2 of 5 have one.
        assert_eq!(score(&issues, report.checked), 60);

        // One vault: its items and its passwords only; the reused group
        // still counts the copy in the other vault.
        let in_personal = |id: &str| entries.iter().any(|e| e.id == id && e.vault_id == "personal");
        let summary = Summary::new(&report, Some("personal"), &in_personal);
        assert_eq!(summary.checked, 3);
        assert_eq!(summary.issues["reused"], [Issue { id: "weak".into(), others: Some(1), ..Default::default() }]);
        assert_eq!(summary.issues["weak"].len(), 1);
        assert_eq!(summary.score, 67);
        let all = Summary::new(&report, None, &in_personal);
        assert_eq!((all.checked, all.score, all.vault_id), (5, 60, None));

        // No password checked: nothing lowers the score.
        assert_eq!(score(&Issues::new(), 0), 100);
        // More problems than passwords (websites without one): never below 0.
        let many: Issues = BTreeMap::from([("unsecured", (0..3).map(|i| Issue { id: i.to_string(), ..Default::default() }).collect())]);
        assert_eq!(score(&many, 2), 0);
    }

    #[test]
    fn breach_checks() {
        let key = ChecksKey::new(&SymmetricKey::generate().unwrap()).unwrap();
        // The keyed hash names the password, the same each time, not readable.
        assert_eq!(key.id("hunter2"), key.id("hunter2"));
        assert_ne!(key.id("hunter2"), key.id("hunter3"));
        assert_eq!(key.id("hunter2").len(), 32);

        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        let passwords = ["password", "password", "not-in-any-breach-Q7#"];
        let check = BreachCheck::new(&key, passwords, &PasswordChecks::default(), true);
        assert!(!check.is_done());
        let ranges = check.ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges["5BAA6"], ["1E4C9B93F3F0682250B6CF8331B7EE68FD8"]);
        // Padded answer: entries with 0 are padding.
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n0000000000000000000000000000000000A:0\r\n";
        let found = range_matches("5BAA6", body, &ranges["5BAA6"]);
        assert_eq!(found, HashMap::from([("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8".to_string(), 9_545_824)]));
        let checks = check.finish(PasswordChecks::default(), &found, 1000);
        assert_eq!(checks.checked_at, Some(1000));
        assert_eq!(checks.seen[&key.id("password")], 9_545_824);
        assert_eq!(checks.seen[&key.id("not-in-any-breach-Q7#")], 0);

        // Kept encrypted; another key reads nothing.
        let sealed = key.seal_row(ChecksKey::ROW, &checks).unwrap();
        assert_eq!(key.open_checks(Some(&sealed)), checks);
        let other = ChecksKey::new(&SymmetricKey::generate().unwrap()).unwrap();
        assert_eq!(other.open_checks(Some(&sealed)), PasswordChecks::default());
        assert_eq!(key.open_row::<PasswordChecks>("notified", &sealed), None);

        // A day later: only a new password is checked; one gone is forgotten.
        assert!(!checks.full_check_due(86_400, 1000 + 3600));
        assert!(checks.full_check_due(86_400, 1000 + 86_400));
        let check = BreachCheck::new(&key, ["password", "brand-new-W4!"], &checks, false);
        assert_eq!(check.ranges().values().map(Vec::len).sum::<usize>(), 1);
        let later = check.finish(checks.clone(), &HashMap::new(), 5000);
        assert_eq!(later.checked_at, Some(1000));
        assert_eq!(later.seen.len(), 2);
        assert_eq!(later.seen[&key.id("brand-new-W4!")], 0);
        assert!(!later.seen.contains_key(&key.id("not-in-any-breach-Q7#")));
        // Nothing new: nothing to ask.
        assert!(BreachCheck::new(&key, ["password"], &later, false).is_done());

        // A range not asked (a password saved meanwhile) stays unchecked.
        let mut check = BreachCheck::new(&key, ["password", "brand-new-W4!"], &PasswordChecks::default(), true);
        check.keep_ranges(|prefix| prefix == "5BAA6");
        let partial = check.finish(PasswordChecks::default(), &HashMap::new(), 7000);
        assert_eq!(partial.seen.keys().collect::<Vec<_>>(), [&key.id("password")]);
    }
}
