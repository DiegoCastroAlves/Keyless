//! Importing again: which of an import's items the account already has.
//!
//! An imported item keeps where it came from (`ItemDetails::import_source`:
//! the format and its id in the file, like "1password:<uuid>"), so the next
//! import of the same file finds it. Items imported before that, and files
//! without ids (CSV), are found by what they are: the same category, title,
//! username and website.
//!
//! Each imported item is then:
//! - new: the account has nothing like it;
//! - the same: it brings nothing the account's item lacks (what only Keyless
//!   has, like a field added there, attached files, passkeys or the password
//!   history, does not count);
//! - changed: it brings something (another value, a field, a website...),
//!   and the copy in Keyless was not edited after the version in the file;
//! - kept: it brings something, but the copy in Keyless is newer than the
//!   file's: an import never overwrites it.
//!
//! An update never removes anything: what the file brings goes in, and what
//! only Keyless had stays.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use super::{ImportResult, ImportedItem};
use crate::{
    draft::MAX_HISTORY,
    item::{Category, Field, ItemDetails, ItemOverview, PasswordHistoryEntry},
};

/// An item of the account (not in Recently Deleted).
pub struct Existing<'a> {
    pub id: &'a str,
    pub vault_id: &'a str,
    pub overview: &'a ItemOverview,
    pub details: &'a ItemDetails,
}

/// What an imported item is, next to the account's items (an index into
/// the `existing` given to [`reconcile`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    New,
    Same(usize),
    Changed(usize),
    Kept(usize),
}

/// The outcome of each imported item, by vault and item.
#[derive(Debug, Default)]
pub struct Plan {
    pub outcomes: Vec<Vec<Outcome>>,
    /// For each of the import's vaults, the account's vault with most of
    /// the items it already has: where its new items belong (none when it
    /// has none of them).
    pub homes: Vec<Option<String>>,
}

/// How many of each, for the summary shown before confirming.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub new_items: usize,
    pub same_items: usize,
    pub changed_items: usize,
    pub kept_items: usize,
}

impl Plan {
    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for outcome in self.outcomes.iter().flatten() {
            match outcome {
                Outcome::New => counts.new_items += 1,
                Outcome::Same(_) => counts.same_items += 1,
                Outcome::Changed(_) => counts.changed_items += 1,
                Outcome::Kept(_) => counts.kept_items += 1,
            }
        }
        counts
    }

    /// New items in each of the import's vaults.
    pub fn new_by_vault(&self) -> Vec<usize> {
        self.outcomes.iter().map(|items| items.iter().filter(|o| **o == Outcome::New).count()).collect()
    }
}

/// Notes in each item where it came from: `origin` (the format, like
/// "1password") and its id in the file. Items without an id keep none.
pub fn mark_sources(result: &mut ImportResult, origin: &str) {
    for item in result.vaults.iter_mut().flat_map(|v| v.items.iter_mut()) {
        let id = item.source_id.trim();
        if !id.is_empty() {
            item.details.import_source = format!("{origin}:{id}");
        }
    }
}

/// The host of an item's first website, without "www.".
fn first_host(overview: &ItemOverview) -> String {
    let Some(url) = overview.urls.first() else { return String::new() };
    let href = url.href.trim();
    let parsed = url::Url::parse(href).or_else(|_| url::Url::parse(&format!("https://{href}")));
    let host = parsed.ok().and_then(|u| u.host_str().map(str::to_lowercase)).unwrap_or_default();
    host.strip_prefix("www.").map(str::to_string).unwrap_or(host)
}

/// What an item is, to find it again without its source: category, title,
/// username and website.
fn identity(overview: &ItemOverview, details: &ItemDetails) -> (Category, String, String, String) {
    (
        overview.category,
        overview.title.trim().to_lowercase(),
        details.username().unwrap_or_default().trim().to_lowercase(),
        first_host(overview),
    )
}

fn field_key(field: &Field) -> (String, String, String, String) {
    (
        field.label.trim().to_string(),
        format!("{:?}", field.kind),
        field.value.trim().to_string(),
        field.purpose.map(|p| format!("{p:?}")).unwrap_or_default(),
    )
}

/// Whether `imported` brings nothing `existing` lacks: the same title and
/// category, and every website, tag, field (name, kind and value), passkey
/// and file of it already there; its notes the same, or none.
fn same_content(existing: &Existing, imported: &ImportedItem) -> bool {
    let (old, new) = ((existing.overview, existing.details), (&imported.overview, &imported.details));
    let tag = |t: &String| t.trim().to_lowercase();
    let url = |u: &crate::item::ItemUrl| crate::draft::normalize_url(&u.href);
    let mut fields: Vec<_> = old.1.all_fields().map(field_key).collect();
    // Each of the file's fields takes one of the item's (two fields of the
    // same name and value need two).
    let fields_kept = new.1.all_fields().map(field_key).all(|key| match fields.iter().position(|k| *k == key) {
        Some(at) => {
            fields.remove(at);
            true
        }
        None => false,
    });
    let notes = new.1.notes.trim();
    old.0.title.trim() == new.0.title.trim()
        && old.0.category == new.0.category
        && new.0.urls.iter().all(|u| old.0.urls.iter().any(|o| url(o) == url(u)))
        && new.0.tags.iter().filter(|t| !t.trim().is_empty()).all(|t| old.0.tags.iter().any(|o| tag(o) == tag(t)))
        && fields_kept
        && (notes.is_empty() || notes == old.1.notes.trim())
        && new.1.passkeys.iter().all(|p| old.1.passkeys.iter().any(|q| q.credential_id == p.credential_id))
        && imported.files.iter().all(|f| old.1.attachments.iter().any(|a| a.name == f.name && a.size == f.size))
}

/// Finds each of `result`'s items among the account's `existing` ones.
pub fn reconcile(result: &ImportResult, existing: &[Existing]) -> Plan {
    let mut by_source: HashMap<String, usize> = HashMap::new();
    let mut by_identity: HashMap<(Category, String, String, String), Vec<usize>> = HashMap::new();
    for (index, item) in existing.iter().enumerate() {
        if !item.details.import_source.is_empty() {
            by_source.entry(item.details.import_source.clone()).or_insert(index);
        }
        // A Keyless backup or export, imported back into the same account.
        by_source.entry(format!("keyless:{}", item.id)).or_insert(index);
        by_identity.entry(identity(item.overview, item.details)).or_default().push(index);
    }

    let mut claimed: HashSet<usize> = HashSet::new();
    let mut plan = Plan::default();
    for vault in &result.vaults {
        let mut outcomes = Vec::with_capacity(vault.items.len());
        for item in &vault.items {
            let source = &item.details.import_source;
            let found = by_source
                .get(source)
                .copied()
                .filter(|index| !source.is_empty() && !claimed.contains(index))
                .or_else(|| {
                    let candidates = by_identity.get(&identity(&item.overview, &item.details))?;
                    let free = || candidates.iter().copied().filter(|index| !claimed.contains(index));
                    // An item whose source points elsewhere is someone else's match.
                    let unsourced = |index: &usize| {
                        let theirs = &existing[*index].details.import_source;
                        theirs.is_empty() || source.is_empty() || theirs == source
                    };
                    free()
                        .filter(unsourced)
                        .find(|index| same_content(&existing[*index], item))
                        .or_else(|| free().find(unsourced))
                });
            let outcome = match found {
                None => Outcome::New,
                Some(index) => {
                    claimed.insert(index);
                    let old = &existing[index];
                    if same_content(old, item) {
                        Outcome::Same(index)
                    } else if item.overview.updated_at > 0 && old.overview.updated_at > item.overview.updated_at {
                        Outcome::Kept(index)
                    } else {
                        Outcome::Changed(index)
                    }
                }
            };
            outcomes.push(outcome);
        }
        let mut tally: Vec<(&str, usize)> = Vec::new();
        for outcome in &outcomes {
            if let Outcome::Same(index) | Outcome::Changed(index) | Outcome::Kept(index) = outcome {
                let vault = existing[*index].vault_id;
                match tally.iter_mut().find(|(v, _)| *v == vault) {
                    Some((_, n)) => *n += 1,
                    None => tally.push((vault, 1)),
                }
            }
        }
        // On a tie, the vault found first.
        plan.homes.push(tally.iter().rev().max_by_key(|(_, n)| *n).map(|(v, _)| v.to_string()));
        plan.outcomes.push(outcomes);
    }
    plan
}

/// The new version of `existing` that a changed `imported` item makes: what
/// the file brings, over the item. Nothing goes: fields, websites, tags and
/// notes only Keyless had stay, as do its id, vault, favorite and archived
/// marks, attached files, passkeys, password history and icon. Fields keep
/// their ids where a field of the same name and kind was there, so the
/// item's history shows what changed; a password replaced goes to the
/// password history. The caller stamps the version.
pub fn merged(existing: &Existing, imported: &ImportedItem, now: i64) -> (ItemOverview, ItemDetails) {
    let (old_overview, old_details) = (existing.overview, existing.details);
    let mut overview = imported.overview.clone();
    overview.created_at = old_overview.created_at;
    overview.favorite = old_overview.favorite;
    overview.archived = old_overview.archived;
    overview.trashed_at = None;
    overview.sentinel_ignored = old_overview.sentinel_ignored.clone();
    overview.custom_icon = old_overview.custom_icon;
    overview.unknown = old_overview.unknown.clone();
    if overview.imported_from.is_empty() {
        overview.imported_from = old_overview.imported_from.clone();
    }
    if overview.updated_at == 0 {
        overview.updated_at = now;
    }
    for url in &old_overview.urls {
        let href = crate::draft::normalize_url(&url.href);
        if !overview.urls.iter().any(|u| crate::draft::normalize_url(&u.href) == href) {
            overview.urls.push(url.clone());
        }
    }
    for tag in &old_overview.tags {
        if !overview.tags.iter().any(|t| t.trim().eq_ignore_ascii_case(tag.trim())) {
            overview.tags.push(tag.clone());
        }
    }

    let mut details = imported.details.clone();
    // The item's fields by name and kind: each of the file's takes the id of
    // one; those left over stay, where they were.
    let mut left: Vec<(Option<String>, Field)> = old_details
        .fields
        .iter()
        .map(|f| (None, f.clone()))
        .chain(old_details.sections.iter().flat_map(|s| s.fields.iter().map(|f| (Some(s.title.clone()), f.clone()))))
        .collect();
    let mut reuse = |field: &mut Field| {
        if let Some(at) = left.iter().position(|(_, f)| f.label.trim() == field.label.trim() && f.kind == field.kind) {
            field.id = left.remove(at).1.id.clone();
        }
    };
    details.fields.iter_mut().for_each(&mut reuse);
    details.sections.iter_mut().flat_map(|s| s.fields.iter_mut()).for_each(&mut reuse);
    for (section, field) in left {
        match section {
            None => details.fields.push(field),
            Some(title) => match details.sections.iter_mut().find(|s| s.title.trim() == title.trim()) {
                Some(existing) => existing.fields.push(field),
                None => {
                    let old = old_details.sections.iter().find(|s| s.title == title);
                    let id = old.map(|s| s.id.clone()).unwrap_or_else(crate::item::new_field_id);
                    details.sections.push(crate::item::Section { id, title, fields: vec![field] });
                }
            },
        }
    }
    if details.notes.trim().is_empty() {
        details.notes = old_details.notes.clone();
    }

    let mut passkeys = old_details.passkeys.clone();
    for passkey in &imported.details.passkeys {
        if !passkeys.iter().any(|p| p.credential_id == passkey.credential_id) {
            passkeys.push(passkey.clone());
        }
    }
    details.passkeys = passkeys;
    details.attachments = old_details.attachments.clone();
    if details.icon.is_empty() {
        details.icon = old_details.icon.clone();
    }
    details.unknown = old_details.unknown.clone();
    details.password_history = old_details.password_history.clone();
    if let Some(old_password) = old_details.password()
        && !old_password.is_empty()
        && details.password() != Some(old_password)
    {
        details.password_history.push(PasswordHistoryEntry { value: old_password.to_string(), changed_at: now });
        let excess = details.password_history.len().saturating_sub(MAX_HISTORY);
        details.password_history.drain(..excess);
    }
    if details.import_source.is_empty() {
        details.import_source = old_details.import_source.clone();
    }
    (overview, details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attachment::Attachment,
        import::{ImportedVault, ImportWarning},
        item::{FieldKind, FieldPurpose, ItemUrl},
    };

    fn login(title: &str, user: &str, password: &str, site: &str, updated_at: i64) -> (ItemOverview, ItemDetails) {
        let overview = ItemOverview {
            title: title.into(),
            category: Category::Login,
            urls: vec![ItemUrl { href: site.into(), ..Default::default() }],
            updated_at,
            ..Default::default()
        };
        let mut details = ItemDetails::default();
        let field = |id: &str, label: &str, kind, value: &str, purpose| Field { id: id.into(), label: label.into(), kind, value: value.into(), purpose: Some(purpose), extra: Default::default() };
        details.fields.push(field("u", "username", FieldKind::Text, user, FieldPurpose::Username));
        details.fields.push(field("p", "password", FieldKind::Concealed, password, FieldPurpose::Password));
        (overview, details)
    }

    fn import(items: Vec<ImportedItem>, origin: &str) -> ImportResult {
        let mut result = ImportResult { vaults: vec![ImportedVault { name: "Personal".into(), items }], warnings: Vec::<ImportWarning>::new() };
        mark_sources(&mut result, origin);
        result
    }

    fn imported(source: &str, item: (ItemOverview, ItemDetails)) -> ImportedItem {
        let mut item = ImportedItem::new(source, item.0, item.1, Vec::new());
        // Every parse makes new field ids.
        for field in &mut item.details.fields {
            field.id = crate::item::new_field_id();
        }
        item
    }

    #[test]
    fn new_same_changed_and_kept() {
        // What the first import of a 1Password file left in the account.
        let (mut a_o, mut a_d) = login("GitHub", "me", "old-pass", "https://github.com", 100);
        a_d.import_source = "1password:aaa".into();
        a_o.favorite = true;
        let mut file = Attachment::default();
        file.name = "codes.txt".into();
        file.size = 10;
        a_d.attachments.push(file);
        let (b_o, mut b_d) = login("Bank", "me", "bank-pass", "https://bank.example", 100);
        b_d.import_source = "1password:bbb".into();
        // Edited in Keyless after that import.
        let (c_o, mut c_d) = login("Mail", "me", "edited-in-keyless", "https://mail.example", 900);
        c_d.import_source = "1password:ccc".into();
        let existing = [
            Existing { id: "ka", vault_id: "v", overview: &a_o, details: &a_d },
            Existing { id: "kb", vault_id: "v", overview: &b_o, details: &b_d },
            Existing { id: "kc", vault_id: "v", overview: &c_o, details: &c_d },
        ];

        let result = import(
            vec![
                imported("aaa", login("GitHub", "me", "new-pass", "https://github.com", 500)),
                imported("bbb", login("Bank", "me", "bank-pass", "https://bank.example", 100)),
                imported("ccc", login("Mail", "me", "from-1password", "https://mail.example", 300)),
                imported("ddd", login("Shop", "me", "shop-pass", "https://shop.example", 100)),
            ],
            "1password",
        );
        let plan = reconcile(&result, &existing);
        assert_eq!(plan.outcomes[0], vec![Outcome::Changed(0), Outcome::Same(1), Outcome::Kept(2), Outcome::New]);
        assert_eq!(plan.counts(), Counts { new_items: 1, same_items: 1, changed_items: 1, kept_items: 1 });
        assert_eq!(plan.new_by_vault(), vec![1]);
        // Shop goes where the file's other items are.
        assert_eq!(plan.homes, vec![Some("v".to_string())]);

        // The update keeps what only Keyless has, and the field ids.
        let (overview, details) = merged(&existing[0], &result.vaults[0].items[0], 1_000);
        assert!(overview.favorite);
        assert_eq!(details.password(), Some("new-pass"));
        assert_eq!(details.fields.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["u", "p"]);
        assert_eq!(details.password_history.last().map(|h| h.value.as_str()), Some("old-pass"));
        assert_eq!(details.attachments.len(), 1);
        assert_eq!(details.import_source, "1password:aaa");
    }

    #[test]
    fn found_by_what_it_is_without_a_source() {
        // Imported before items kept their source; a CSV has no ids.
        let (o, d) = login("GitHub", "Me", "pass", "https://www.github.com/login", 100);
        let existing = [Existing { id: "k1", vault_id: "v", overview: &o, details: &d }];
        let result = import(
            vec![
                imported("", login("github", "me", "pass", "https://www.github.com/login", 0)),
                // The same again in the file: the account has one, so it is new.
                imported("", login("GitHub", "me", "pass", "https://github.com/login", 0)),
            ],
            "csv",
        );
        let plan = reconcile(&result, &existing);
        assert_eq!(plan.outcomes[0][1], Outcome::New);
        // Same title (any case), username and site: the same item. The
        // title's case differs, so it changed; without dates, it updates.
        assert_eq!(plan.outcomes[0][0], Outcome::Changed(0));
        assert!(result.vaults[0].items.iter().all(|i| i.details.import_source.is_empty()));
    }

    #[test]
    fn what_only_keyless_has_is_not_a_change_and_stays() {
        // A two-factor code added in Keyless; the CSV has no such column.
        let (o, mut d) = login("GitHub", "me", "pass", "https://github.com", 100);
        d.fields.push(Field { id: "t".into(), label: "one-time password".into(), kind: FieldKind::Totp, value: "otpauth://x".into(), purpose: None, extra: Default::default() });
        d.notes = "kept".into();
        let existing = [Existing { id: "k1", vault_id: "v", overview: &o, details: &d }];
        let same = import(vec![imported("", login("GitHub", "me", "pass", "https://github.com", 0))], "csv");
        assert_eq!(reconcile(&same, &existing).outcomes[0], vec![Outcome::Same(0)]);

        let changed = import(vec![imported("", login("GitHub", "me", "new", "https://github.com", 0))], "csv");
        assert_eq!(reconcile(&changed, &existing).outcomes[0], vec![Outcome::Changed(0)]);
        let (_, details) = merged(&existing[0], &changed.vaults[0].items[0], 1_000);
        assert_eq!(details.password(), Some("new"));
        assert_eq!(details.fields.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["u", "p", "t"]);
        assert_eq!(details.notes, "kept");
    }

    #[test]
    fn a_keyless_backup_finds_its_items_by_id() {
        let (o, mut d) = login("GitHub", "me", "pass", "https://github.com", 100);
        d.fields[0].id = "kept".into();
        let existing = [Existing { id: "item-1", vault_id: "v", overview: &o, details: &d }];
        let result = import(vec![imported("item-1", login("GitHub", "me", "pass", "https://github.com", 100))], "keyless");
        assert_eq!(reconcile(&result, &existing).outcomes[0], vec![Outcome::Same(0)]);
    }

    #[test]
    fn another_source_is_not_matched_by_name() {
        // Two logins with the same name from two different sources.
        let (o, mut d) = login("Router", "admin", "one", "", 100);
        d.import_source = "1password:xyz".into();
        let existing = [Existing { id: "k1", vault_id: "v", overview: &o, details: &d }];
        let result = import(vec![imported("other", login("Router", "admin", "two", "", 100))], "1password");
        assert_eq!(reconcile(&result, &existing).outcomes[0], vec![Outcome::New]);
    }
}
