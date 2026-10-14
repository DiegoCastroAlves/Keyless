//! What the item editor sends, and the item a save makes of it: the rules
//! every app follows when saving (limits, the list's subtitle, the
//! password's history, websites without a scheme, and what an edit never
//! changes: passkeys, attachments, ignored alerts and what newer versions
//! added).

use serde::{Deserialize, Serialize};

use crate::item::{
    Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, PasswordHistoryEntry, Section, new_field_id,
};

pub const MAX_TITLE: usize = 512;
pub const MAX_FIELDS: usize = 200;
pub const MAX_VALUE: usize = 64 * 1024;
pub const MAX_NOTES: usize = 64 * 1024;
/// Serialized details must fit the server's 256 KiB ciphertext limit.
pub const MAX_DETAILS_JSON: usize = 180 * 1024;
pub const MAX_HISTORY: usize = 30;
/// Item icons: PNG data URLs.
pub const ICON_PREFIX: &str = "data:image/png;base64,";
pub const MAX_ICON: usize = 96 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub title: String,
    pub category: Category,
    #[serde(default)]
    pub urls: Vec<ItemUrl>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub notes: String,
    /// The item's own icon (a PNG data URL), or empty.
    #[serde(default)]
    pub icon: String,
}

/// Why a draft cannot be saved: a key the apps translate, and the field's
/// label when it is about one field.
#[derive(Debug, PartialEq, Eq)]
pub struct DraftError {
    pub key: &'static str,
    pub label: Option<String>,
}

impl DraftError {
    fn new(key: &'static str) -> Self {
        Self { key, label: None }
    }
}

pub fn validate(draft: &ItemDraft) -> Result<(), DraftError> {
    let total_fields = draft.fields.len() + draft.sections.iter().map(|s| s.fields.len()).sum::<usize>();
    if draft.title.len() > MAX_TITLE {
        return Err(DraftError::new("title_too_long"));
    }
    if total_fields > MAX_FIELDS || draft.sections.len() > 50 || draft.urls.len() > 50 || draft.tags.len() > 50 {
        return Err(DraftError::new("too_many_fields"));
    }
    if draft.notes.len() > MAX_NOTES {
        return Err(DraftError::new("notes_too_long"));
    }
    for field in draft.fields.iter().chain(draft.sections.iter().flat_map(|s| s.fields.iter())) {
        if field.value.len() > MAX_VALUE || field.label.len() > 256 {
            return Err(DraftError { key: "field_too_long", label: Some(field.label.clone()) });
        }
    }
    if !draft.icon.is_empty() && (draft.icon.len() > MAX_ICON || !draft.icon.starts_with(ICON_PREFIX)) {
        return Err(DraftError::new("icon_invalid"));
    }
    Ok(())
}

/// A website as typed: without a scheme, it is https.
pub fn normalize_url(href: &str) -> String {
    let href = href.trim();
    if href.is_empty() || href.contains("://") { href.to_string() } else { format!("https://{href}") }
}

/// The line the item list shows under the title.
pub fn subtitle(category: Category, details: &ItemDetails) -> String {
    let first_text = || {
        details
            .all_fields()
            .find(|f| !f.value.is_empty() && !f.kind.is_secret() && f.purpose != Some(FieldPurpose::Password))
            .map(|f| f.value.chars().take(80).collect::<String>())
            .unwrap_or_default()
    };
    match category {
        Category::CreditCard => details
            .all_fields()
            .find(|f| f.kind == FieldKind::CardNumber && !f.value.is_empty())
            .map(|f| {
                let digits: String = f.value.chars().filter(char::is_ascii_digit).collect();
                let last4 = &digits[digits.len().saturating_sub(4)..];
                format!("•••• {last4}")
            })
            .unwrap_or_default(),
        Category::SecureNote => details.notes.lines().next().unwrap_or("").chars().take(80).collect(),
        Category::Login | Category::Password | Category::EmailAccount | Category::Database | Category::Server => {
            details.username().map(String::from).unwrap_or_else(first_text)
        }
        _ => first_text(),
    }
}

/// Field ids, one-time password setups trimmed, addresses kept as text too,
/// expiry alerts only on dates, and sections that are left empty dropped.
pub fn normalize(draft: &mut ItemDraft) {
    for field in draft.fields.iter_mut().chain(draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut())) {
        if field.id.is_empty() {
            field.id = new_field_id();
        }
        if field.kind == FieldKind::Totp {
            field.value = field.value.trim().to_string();
        }
        // An address is kept as its parts and as text (for search, the list
        // and versions that do not know addresses).
        if field.kind == FieldKind::Address
            && let Some(address) = &field.extra.address
        {
            field.value = address.formatted();
        }
        if !field.kind.is_date() {
            field.extra.alert = None;
        }
    }
    for section in draft.sections.iter_mut() {
        if section.id.is_empty() {
            section.id = new_field_id();
        }
    }
    draft.sections.retain(|s| !s.fields.is_empty() || !s.title.trim().is_empty());
}

/// The item a save makes of a normalized `draft`, over the `existing` one
/// (`None` for a new item). Versions and content ids are stamped later.
pub fn build(mut draft: ItemDraft, existing: Option<(&ItemOverview, &ItemDetails)>, now: i64) -> Result<(ItemOverview, ItemDetails), DraftError> {
    let mut details = ItemDetails::default();
    details.fields = std::mem::take(&mut draft.fields);
    details.sections = std::mem::take(&mut draft.sections);
    details.notes = std::mem::take(&mut draft.notes);
    details.icon = std::mem::take(&mut draft.icon);
    let mut created_at = now;
    let mut archived = false;
    let mut sentinel_ignored = Vec::new();
    let mut imported_from = String::new();
    let mut unknown = Default::default();
    if let Some((old_overview, old_details)) = existing {
        created_at = old_overview.created_at;
        archived = old_overview.archived;
        sentinel_ignored = old_overview.sentinel_ignored.clone();
        imported_from = old_overview.imported_from.clone();
        // What a later version added to the item stays.
        unknown = old_overview.unknown.clone();
        details.passkeys = old_details.passkeys.clone();
        details.attachments = old_details.attachments.clone();
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
    }
    if serde_json::to_vec(&details).map(|j| j.len()).unwrap_or(usize::MAX) > MAX_DETAILS_JSON {
        return Err(DraftError::new("item_too_large"));
    }

    let mut tags: Vec<String> = draft.tags.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    tags.sort_by_key(|t| t.to_lowercase());
    tags.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

    let overview = ItemOverview {
        title: if draft.title.trim().is_empty() { "Untitled".into() } else { draft.title.trim().to_string() },
        subtitle: subtitle(draft.category, &details),
        category: draft.category,
        urls: draft
            .urls
            .iter()
            .filter(|u| !u.href.trim().is_empty())
            .map(|u| ItemUrl { href: normalize_url(&u.href), label: u.label.trim().to_string(), fill: u.fill, submit: u.submit, unknown: u.unknown.clone() })
            .collect(),
        tags,
        favorite: draft.favorite,
        archived,
        trashed_at: None,
        created_at,
        updated_at: now,
        sentinel_ignored,
        custom_icon: !details.icon.is_empty(),
        imported_from,
        unknown,
        ..Default::default()
    };
    Ok((overview, details))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(label: &str, kind: FieldKind, value: &str, purpose: Option<FieldPurpose>) -> Field {
        Field { id: String::new(), label: label.into(), kind, value: value.into(), purpose, extra: Default::default() }
    }

    fn login_draft(password: &str) -> ItemDraft {
        ItemDraft {
            vault_id: "v".into(),
            title: "  Bank ".into(),
            category: Category::Login,
            urls: vec![ItemUrl { href: "bank.example".into(), ..Default::default() }, ItemUrl { href: " ".into(), ..Default::default() }],
            tags: vec!["Money".into(), " money ".into(), "".into(), "bills".into()],
            fields: vec![
                field("username", FieldKind::Text, "me", Some(FieldPurpose::Username)),
                field("password", FieldKind::Concealed, password, Some(FieldPurpose::Password)),
                field("code", FieldKind::Totp, "  otpauth://totp/x?secret=JBSWY3DPEHPK3PXP  ", None),
            ],
            sections: vec![Section { id: String::new(), title: "  ".into(), fields: Vec::new() }],
            ..Default::default()
        }
    }

    #[test]
    fn builds_a_new_item() {
        let mut draft = login_draft("one");
        validate(&draft).unwrap();
        normalize(&mut draft);
        assert!(draft.fields.iter().all(|f| f.id.len() == 12));
        assert!(draft.sections.is_empty());
        assert_eq!(draft.fields[2].value, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
        let (overview, details) = build(draft, None, 100).unwrap();
        assert_eq!(overview.title, "Bank");
        assert_eq!(overview.subtitle, "me");
        assert_eq!(overview.urls.len(), 1);
        assert_eq!(overview.urls[0].href, "https://bank.example");
        assert_eq!(overview.tags, vec!["bills", "Money"]);
        assert_eq!((overview.created_at, overview.updated_at), (100, 100));
        assert!(details.password_history.is_empty());
    }

    #[test]
    fn an_edit_keeps_what_the_editor_does_not_show() {
        let mut first = login_draft("one");
        normalize(&mut first);
        let (mut old_overview, mut old_details) = build(first, None, 100).unwrap();
        old_overview.archived = true;
        old_overview.sentinel_ignored = vec!["weak".into()];
        old_details.unknown.0.insert("later".into(), serde_json::json!(1));
        old_details.attachments.push(Default::default());
        let mut edit = login_draft("two");
        normalize(&mut edit);
        let (overview, details) = build(edit, Some((&old_overview, &old_details)), 200).unwrap();
        assert_eq!(overview.created_at, 100);
        assert!(overview.archived);
        assert_eq!(overview.sentinel_ignored, vec!["weak"]);
        assert_eq!(details.unknown.0.get("later"), Some(&serde_json::json!(1)));
        assert_eq!(details.attachments.len(), 1);
        assert_eq!(details.password_history.len(), 1);
        assert_eq!(details.password_history[0].value, "one");
        // The same password again adds nothing.
        let mut same = login_draft("two");
        normalize(&mut same);
        let (_, again) = build(same, Some((&overview, &details)), 300).unwrap();
        assert_eq!(again.password_history.len(), 1);
    }

    #[test]
    fn subtitles_and_limits() {
        let mut card = ItemDetails::default();
        card.fields.push(field("number", FieldKind::CardNumber, "4111 1111 1111 1234", None));
        assert_eq!(subtitle(Category::CreditCard, &card), "•••• 1234");
        let mut note = ItemDetails::default();
        note.notes = "first line\nsecond".into();
        assert_eq!(subtitle(Category::SecureNote, &note), "first line");
        let mut long = login_draft("x");
        long.title = "t".repeat(MAX_TITLE + 1);
        assert_eq!(validate(&long).unwrap_err().key, "title_too_long");
        let mut big = login_draft("x");
        big.fields[0].value = "v".repeat(MAX_VALUE + 1);
        assert_eq!(validate(&big).unwrap_err(), DraftError { key: "field_too_long", label: Some("username".into()) });
        assert_eq!(normalize_url("example.com/a"), "https://example.com/a");
        assert_eq!(normalize_url("ssh://host"), "ssh://host");
    }
}
