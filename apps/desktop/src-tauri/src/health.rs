//! Watchtower: weak, reused and breached passwords, websites without HTTPS,
//! expiring cards and documents, websites breached since the password was
//! last changed, and websites that offer two-factor authentication the item
//! does not use.
//!
//! Everything runs on this device except the online check, which the user
//! starts:
//! - breached passwords use the Have I Been Pwned range API with k-anonymity:
//!   only the first 5 hex characters of each password's SHA-1 hash are sent,
//!   and responses are padded, so the service never learns the password or
//!   even which hash was looked up;
//! - breached websites and two-factor support come from public lists (Have I
//!   Been Pwned's breaches, 2fa.directory) downloaded whole and compared
//!   here, so nothing about the items is sent.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use keyless_core::item::{Category, FieldKind, FieldPurpose, ItemDetails, ItemUrl};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::{Digest, Sha1};

use crate::{
    api::now_secs,
    bridge::{forms::parse_expiry, handlers::{site_of, url_host}},
    error::{AppError, AppResult},
    state::AppState,
};

/// Cards and documents expiring this soon are reported.
const EXPIRING_SOON: i64 = 30 * 24 * 3600;
/// The public lists are a few megabytes; anything far larger is refused.
const MAX_LIST_BYTES: usize = 20 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
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
    /// Items with a website on plain `http`.
    pub unsecured: Vec<String>,
    pub expiring: Vec<Expiry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteIssue {
    pub id: String,
    pub site: String,
    /// The breach date (YYYY-MM-DD) for breached websites.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachReport {
    pub checked: usize,
    /// Item ids whose password appears in known breaches, with the count.
    pub breached: Vec<(String, u64)>,
    /// Websites breached after the item's password was set.
    pub compromised: Vec<SiteIssue>,
    /// Websites that offer two-factor codes the item does not have.
    pub two_factor: Vec<SiteIssue>,
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

/// An active item, as the checks need it.
struct Entry {
    id: String,
    category: Category,
    urls: Vec<ItemUrl>,
    created_at: i64,
    details: ItemDetails,
}

impl Entry {
    fn password(&self) -> Option<&str> {
        self.details.field_by_purpose(FieldPurpose::Password).map(|f| f.value.as_str()).filter(|p| !p.is_empty())
    }

    /// When the current password was set: when the previous one was
    /// replaced, or when the item was created.
    fn password_set_at(&self) -> i64 {
        self.details.password_history.iter().map(|h| h.changed_at).max().unwrap_or(self.created_at)
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
        out.push(Entry { id: id.clone(), category: o.category, urls: o.urls.clone(), created_at: o.created_at, details });
    }
    Ok(out)
}

pub async fn report(state: &AppState) -> AppResult<HealthReport> {
    let entries = entries(state).await?;
    let now = now_secs();
    let mut report = HealthReport::default();
    let mut by_password: HashMap<&str, Vec<String>> = HashMap::new();
    for entry in &entries {
        if let Some(password) = entry.password() {
            report.checked += 1;
            if strength(password, &[]).score < 3 {
                report.weak.push(entry.id.clone());
            }
            by_password.entry(password).or_default().push(entry.id.clone());
        }
        if entry.urls.iter().any(|u| unsecured(&u.href)) {
            report.unsecured.push(entry.id.clone());
        }
        if let Some(expires_at) = expiry(&entry.details)
            && expires_at - now < EXPIRING_SOON
        {
            report.expiring.push(Expiry { id: entry.id.clone(), expires_at, expired: expires_at < now });
        }
    }
    report.reused = by_password.into_values().filter(|ids| ids.len() > 1).collect();
    report.expiring.sort_by_key(|e| e.expires_at);
    Ok(report)
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
fn unix_day(year: i64, month: u32, day: u32) -> i64 {
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
        .user_agent(concat!("Keyless/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Server(e.to_string()))
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

/// The online check: breached passwords, breached websites and two-factor
/// support.
pub async fn breaches(state: &AppState) -> AppResult<BreachReport> {
    let entries = entries(state).await?;
    let client = client()?;
    let breached = breached_passwords(&client, &entries).await?;
    // Lists that cannot be loaded leave their section empty: the password
    // check above is the important one.
    let compromised = match breached_sites(&client).await {
        Ok(sites) => compromised(&entries, &sites),
        Err(err) => {
            log::warn!("breached websites list: {err}");
            Vec::new()
        }
    };
    let two_factor = match two_factor_sites(&client).await {
        Ok(sites) => missing_two_factor(&entries, &sites),
        Err(err) => {
            log::warn!("two-factor list: {err}");
            Vec::new()
        }
    };
    Ok(BreachReport { checked: entries.iter().filter(|e| e.password().is_some()).count(), breached, compromised, two_factor })
}

async fn breached_passwords(client: &reqwest::Client, entries: &[Entry]) -> AppResult<Vec<(String, u64)>> {
    let mut hashes: HashMap<String, Vec<String>> = HashMap::new();
    for entry in entries {
        if let Some(password) = entry.password() {
            let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
            hashes.entry(hash).or_default().push(entry.id.clone());
        }
    }
    let prefixes: HashSet<String> = hashes.keys().map(|h| h[..5].to_string()).collect();
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
    Ok(breached)
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

/// Site -> date of its latest verified breach that exposed passwords.
async fn breached_sites(client: &reqwest::Client) -> AppResult<HashMap<String, String>> {
    let body = get_list(client, "https://haveibeenpwned.com/api/v3/breaches").await?;
    let list: Vec<Breach> = serde_json::from_slice(&body)?;
    Ok(sites_from_breaches(list))
}

fn sites_from_breaches(list: Vec<Breach>) -> HashMap<String, String> {
    let mut sites: HashMap<String, String> = HashMap::new();
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

fn compromised(entries: &[Entry], sites: &HashMap<String, String>) -> Vec<SiteIssue> {
    let mut issues = Vec::new();
    for entry in entries.iter().filter(|e| e.password().is_some()) {
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

/// Sites (registrable domains) that offer one-time password codes, from
/// 2fa.directory: a list of `[name, {domain, additional-domains, ...}]`.
async fn two_factor_sites(client: &reqwest::Client) -> AppResult<HashSet<String>> {
    let body = get_list(client, "https://api.2fa.directory/v3/totp.json").await?;
    let list: Value = serde_json::from_slice(&body)?;
    Ok(sites_from_directory(&list))
}

fn sites_from_directory(list: &Value) -> HashSet<String> {
    let mut sites = HashSet::new();
    for entry in list.as_array().into_iter().flatten() {
        let Some(info) = entry.get(1) else { continue };
        let domains = info.get("domain").into_iter().chain(info.get("additional-domains").and_then(Value::as_array).into_iter().flatten());
        for domain in domains.filter_map(Value::as_str) {
            if let Some(host) = url_host(domain) {
                sites.insert(site_of(&host));
            }
        }
    }
    sites
}

fn missing_two_factor(entries: &[Entry], sites: &HashSet<String>) -> Vec<SiteIssue> {
    entries
        .iter()
        .filter(|e| matches!(e.category, Category::Login | Category::Password) && e.password().is_some() && !e.has_totp())
        .filter_map(|e| e.sites().into_iter().find(|s| sites.contains(s)).map(|site| SiteIssue { id: e.id.clone(), site, date: None }))
        .collect()
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
}
