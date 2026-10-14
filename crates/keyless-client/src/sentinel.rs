//! Sentinel, computed like the desktop's (`keyless_core::health`) from the
//! unlocked items: weak, reused and breached passwords, duplicates,
//! websites without HTTPS, expiring dates, breached websites, two-factor
//! and passkeys available, LastPass imports, ignored alerts and the score.
//!
//! Nothing here goes online. The host downloads the public lists
//! (`sentinelLists`, read by `sentinelParseList`) and asks Have I Been
//! Pwned's range API (`sentinelBreachQueries`, `sentinelBreachResults`);
//! what it keeps between runs it passes back to `sentinelReport`: the lists
//! as read (public data), and the breach results encrypted with a key from
//! the user key, as the desktop keeps them.

use std::collections::HashMap;

use keyless_core::{
    draft::ItemDraft,
    health::{self, BreachCheck, ChecksKey, Entry, LISTS, ListKind, MAX_LIST_BYTES, Online, Sites, Summary},
};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{Client, Failure, Outcome, args};

/// A public list the host keeps: the `sites` `sentinelParseList` read, and
/// when it was downloaded (Unix seconds).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeptList {
    sites: Sites,
    fetched_at: i64,
}

/// The public lists to download (about once a day, whole), and the alert
/// each one is for.
pub(crate) fn lists() -> Value {
    Value::Array(LISTS.iter().map(|kind| json!({ "kind": kind, "url": kind.url(), "alert": kind.alert(), "maxBytes": MAX_LIST_BYTES })).collect())
}

/// A list as downloaded (`body`, its text), read: the `sites` the host
/// keeps for `sentinelReport`. Refused when it does not read as the real
/// list (a broken download, an error page): the host then keeps its old
/// copy.
pub(crate) fn parse_list(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        kind: ListKind,
        body: String,
    }
    let a: A = args(json)?;
    if a.body.len() > MAX_LIST_BYTES {
        return Err(Failure { key: "sentinel_list_invalid", message: "list too large".into() });
    }
    let sites = a.kind.parse(a.body.as_bytes()).map_err(|err| Failure { key: "sentinel_list_invalid", message: err.to_string() })?;
    Ok(json!({ "kind": a.kind, "count": sites.len(), "sites": sites }))
}

impl Client {
    /// Every item that is neither archived nor in Recently Deleted.
    fn sentinel_entries(&self) -> Outcome<Vec<Entry>> {
        let unlocked = self.unlocked()?;
        let mut out = Vec::new();
        for (id, row) in &self.store.items {
            if row.deleted || !unlocked.vaults.contains_key(&row.vault_id) {
                continue;
            }
            let Ok((vault_id, overview, details)) = self.open_item(id) else { continue };
            if overview.trashed_at.is_some() || overview.archived {
                continue;
            }
            out.push(Entry::new(id, &vault_id, &overview, details));
        }
        Ok(out)
    }

    fn checks_key(&self) -> Outcome<ChecksKey> {
        Ok(ChecksKey::new(self.unlocked()?.account.user_key())?)
    }

    /// The report, as the desktop's: the lists the host kept (`lists`, by
    /// kind; one missing or null was never downloaded), those turned off in
    /// its settings (`off`), the breach results it kept (`checks`), and
    /// `now` (Unix seconds). Its `summary` is what Sentinel's overview shows
    /// for `vaultId` (every vault without it, or when the account no longer
    /// has it): the score, the strength levels and each alert's items,
    /// without the ignored ones.
    pub(crate) fn sentinel_report(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            #[serde(default)]
            lists: Option<HashMap<ListKind, Option<KeptList>>>,
            #[serde(default)]
            off: Vec<ListKind>,
            #[serde(default)]
            checks: Option<String>,
            #[serde(default)]
            vault_id: Option<String>,
            now: i64,
        }
        let a: A = args(json)?;
        let entries = self.sentinel_entries()?;
        let key = self.checks_key()?;
        let checks = key.open_checks(a.checks.as_deref());
        let lists: HashMap<ListKind, KeptList> = a.lists.unwrap_or_default().into_iter().filter_map(|(kind, list)| Some((kind, list?))).collect();
        let enabled = || LISTS.into_iter().filter(|kind| !a.off.contains(kind));
        let seen = |password: &str| checks.seen.get(&key.id(password)).copied();
        let online = Online {
            seen: &seen,
            checked: checks.checked_at.is_some(),
            lists: enabled().filter_map(|kind| lists.get(&kind).map(|list| (kind, &list.sites))).collect(),
            off: LISTS.into_iter().filter(|kind| a.off.contains(kind)).collect(),
        };
        let mut report = health::analyze(&entries, &online, a.now);
        report.passwords_checked_at = checks.checked_at;
        report.lists_updated_at = health::lists_updated_at(enabled().map(|kind| lists.get(&kind).map(|list| list.fetched_at)));
        let vault = a.vault_id.as_deref().filter(|id| self.unlocked().is_ok_and(|u| u.vaults.contains_key(*id)));
        let vaults: HashMap<&str, &str> = entries.iter().map(|e| (e.id.as_str(), e.vault_id.as_str())).collect();
        let in_vault = |id: &str| vaults.get(id).copied() == vault;
        let summary = Summary::new(&report, vault, &in_vault);
        let mut answer = serde_json::to_value(&report)?;
        answer["summary"] = serde_json::to_value(&summary)?;
        Ok(answer)
    }

    /// A password's strength (against `inputs`: the item's or the account's
    /// own words), and, while unlocked, how many items other than `itemId`
    /// already use it (the editor's check). Nothing leaves the device.
    pub(crate) fn strength(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            password: Zeroizing<String>,
            #[serde(default)]
            inputs: Vec<String>,
            #[serde(default)]
            item_id: Option<String>,
        }
        let a: A = args(json)?;
        let inputs: Vec<&str> = a.inputs.iter().map(String::as_str).collect();
        let mut answer = serde_json::to_value(health::strength(&a.password, &inputs))?;
        answer["reused"] = match self.unlocked {
            Some(_) => json!(health::reuses(&self.sentinel_entries()?, &a.password, a.item_id.as_deref())),
            None => Value::Null,
        };
        Ok(answer)
    }

    /// What to ask Have I Been Pwned's range API (`GET
    /// https://api.pwnedpasswords.com/range/{prefix}` with the header
    /// `Add-Padding: true`): the first 5 characters of the SHA-1 hash of
    /// each password to check, and nothing else. Every password when the
    /// last full check (in `checks`) is older than `maxAge` seconds (0: now),
    /// otherwise only the ones never checked; `upToDate` when there is
    /// nothing to ask. `all` goes back with the answers.
    pub(crate) fn sentinel_breach_queries(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            #[serde(default)]
            checks: Option<String>,
            #[serde(default)]
            max_age: i64,
            now: i64,
        }
        let a: A = args(json)?;
        let key = self.checks_key()?;
        let old = key.open_checks(a.checks.as_deref());
        let all = old.full_check_due(a.max_age, a.now);
        let entries = self.sentinel_entries()?;
        let check = BreachCheck::new(&key, entries.iter().filter_map(Entry::password), &old, all);
        Ok(json!({ "all": all, "prefixes": check.ranges().keys().collect::<Vec<_>>(), "upToDate": check.is_done() }))
    }

    /// The range API's answers (`responses`: prefix -> the response's text)
    /// turned into the results to keep: `checks`, encrypted with a key from
    /// the user key, for `sentinelReport` and the next queries. A password
    /// whose prefix has no answer (saved since the queries) stays unchecked;
    /// old passwords are forgotten.
    pub(crate) fn sentinel_breach_results(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct A {
            #[serde(default)]
            checks: Option<String>,
            all: bool,
            responses: HashMap<String, String>,
            now: i64,
        }
        let a: A = args(json)?;
        let key = self.checks_key()?;
        let old = key.open_checks(a.checks.as_deref());
        let entries = self.sentinel_entries()?;
        let mut check = BreachCheck::new(&key, entries.iter().filter_map(Entry::password), &old, a.all);
        drop(entries);
        let responses: HashMap<String, &str> = a.responses.iter().map(|(prefix, body)| (prefix.trim().to_ascii_uppercase(), body.as_str())).collect();
        check.keep_ranges(|prefix| responses.contains_key(prefix));
        let mut found = HashMap::new();
        let mut checked = 0;
        for (prefix, suffixes) in check.ranges() {
            checked += suffixes.len();
            found.extend(health::range_matches(prefix, responses[prefix], &suffixes));
        }
        let checks = check.finish(old, &found, a.now);
        let breached = checks.seen.values().filter(|&&seen| seen > 0).count();
        Ok(json!({ "checks": key.seal_row(ChecksKey::ROW, &checks)?, "checked": checked, "breached": breached, "checkedAt": checks.checked_at }))
    }

    /// Ignores `alerts` for an item, or (`ignored` false) watches them
    /// again: the write to upload, like `sealItem`.
    pub(crate) fn sentinel_ignore(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
            alerts: Vec<String>,
            ignored: bool,
            now: i64,
        }
        let a: A = args(json)?;
        if a.alerts.is_empty() || a.alerts.iter().any(|alert| !health::ALERTS.contains(&alert.as_str())) {
            return Err(Failure::new("invalid_request"));
        }
        let (vault_id, mut overview, details) = self.open_item(&a.id)?;
        overview.sentinel_ignored.retain(|alert| !a.alerts.contains(alert));
        if a.ignored {
            for alert in &a.alerts {
                if !overview.sentinel_ignored.contains(alert) {
                    overview.sentinel_ignored.push(alert.clone());
                }
            }
        }
        self.seal_item(&json!({ "vaultId": vault_id, "id": a.id, "overview": overview, "details": details, "now": a.now }).to_string())
    }

    /// "Use HTTPS": the item's websites on plain http's own port move to
    /// https, saved like any edit (`saveDraft`). Refused for an item in
    /// Recently Deleted (saving it would restore it), and when no website
    /// can simply switch.
    pub(crate) fn sentinel_use_https(&mut self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
            now: i64,
        }
        let a: A = args(json)?;
        let (_, overview, _) = self.open_item(&a.id)?;
        if overview.trashed_at.is_some() {
            return Err(Failure::new("https_trashed"));
        }
        let mut draft: ItemDraft = serde_json::from_value(self.draft_of(&json!({ "id": a.id }).to_string())?)?;
        if !health::switch_to_https(&mut draft.urls) {
            return Err(Failure::new("https_unavailable"));
        }
        self.save_draft(&json!({ "draft": draft, "now": a.now }).to_string())
    }
}
