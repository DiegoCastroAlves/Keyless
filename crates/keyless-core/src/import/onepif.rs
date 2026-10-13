//! 1Password Interchange Format (`.1pif`), from 1Password 4 to 7: one JSON
//! object per item, with a separator line between them. `typeName` says the
//! kind of item; `secureContents` holds the login fields, the sections, the
//! notes and the websites.

use serde_json::Value;

use super::{ImportResult, ImportWarning, ImportedItem, ImportedVault};
use crate::{
    Result,
    item::{
        Address, Category, Field, FieldExtra, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, PasswordHistoryEntry, Section,
        new_field_id,
    },
};

/// The line between items.
const SEPARATOR: &str = "***5642bee8-a5ff-11dc-8314-0800200c9a66***";

/// Whether `text` looks like a 1PIF file.
pub fn detect(text: &str) -> bool {
    text.contains(SEPARATOR)
}

fn category(type_name: &str) -> Option<Category> {
    Some(match type_name {
        "webforms.WebForm" => Category::Login,
        "securenotes.SecureNote" => Category::SecureNote,
        "wallet.financial.CreditCard" => Category::CreditCard,
        "identities.Identity" => Category::Identity,
        "passwords.Password" => Category::Password,
        "wallet.financial.BankAccountUS" => Category::BankAccount,
        "wallet.computer.Database" => Category::Database,
        "wallet.government.DriversLicense" => Category::DriverLicense,
        "wallet.onlineservices.Email.v2" | "wallet.onlineservices.Email" => Category::EmailAccount,
        "wallet.membership.Membership" | "wallet.membership.RewardProgram" => Category::Membership,
        "wallet.government.Passport" => Category::Passport,
        "wallet.computer.Router" => Category::WirelessRouter,
        "wallet.computer.UnixServer" => Category::Server,
        "wallet.computer.License" => Category::SoftwareLicense,
        // Folders, saved searches and the like are not items.
        name if name.starts_with("system.") => return None,
        _ => Category::Other,
    })
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// A section field: `k` its kind, `t` its title, `v` its value.
fn section_field(raw: &Value) -> Option<Field> {
    let label = text(raw.get("t"));
    let value = raw.get("v")?;
    let (kind, text_value, extra) = match raw.get("k").and_then(Value::as_str).unwrap_or("string") {
        "concealed" => {
            let v = text(Some(value));
            (if v.starts_with("otpauth://") { FieldKind::Totp } else { FieldKind::Concealed }, v, FieldExtra::default())
        }
        "email" => (FieldKind::Email, text(Some(value)), FieldExtra::default()),
        "URL" => (FieldKind::Url, text(Some(value)), FieldExtra::default()),
        "phone" => (FieldKind::Phone, text(Some(value)), FieldExtra::default()),
        "date" => (FieldKind::Date, value.as_i64().map(super::onepux::format_unix_date).unwrap_or_default(), FieldExtra::default()),
        "monthYear" => (FieldKind::MonthYear, value.as_i64().map(|v| format!("{:02}/{}", v % 100, v / 100)).unwrap_or_default(), FieldExtra::default()),
        "address" => {
            let part = |k: &str| text(value.get(k));
            let address = Address { street: part("street"), city: part("city"), state: part("state"), zip: part("zip"), country: part("country"), ..Default::default() };
            (FieldKind::Address, address.formatted(), FieldExtra { address: Some(address), ..Default::default() })
        }
        _ => (FieldKind::Text, text(Some(value)), FieldExtra::default()),
    };
    (!text_value.is_empty()).then(|| Field { id: new_field_id(), label, kind, value: text_value, purpose: None, extra })
}

pub fn parse_1pif(text_data: &str, vault_name: &str) -> Result<ImportResult> {
    let mut items = Vec::new();
    let mut skipped = 0;
    for chunk in text_data.split(SEPARATOR) {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<Value>(chunk) else {
            skipped += 1;
            continue;
        };
        if raw.get("trashed").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(category) = category(raw.get("typeName").and_then(Value::as_str).unwrap_or("")) else { continue };
        let secure = raw.get("secureContents").cloned().unwrap_or(Value::Null);
        let mut details = ItemDetails::default();
        details.notes = secure.get("notesPlain").and_then(Value::as_str).unwrap_or("").to_string();
        for login in secure.get("fields").and_then(Value::as_array).into_iter().flatten() {
            let (purpose, kind, label) = match login.get("designation").and_then(Value::as_str) {
                Some("username") => (FieldPurpose::Username, FieldKind::Text, "username"),
                Some("password") => (FieldPurpose::Password, FieldKind::Concealed, "password"),
                _ => continue,
            };
            let value = login.get("value").and_then(Value::as_str).unwrap_or("");
            if !value.is_empty() && details.field_by_purpose(purpose).is_none() {
                details.fields.push(Field { id: new_field_id(), label: label.into(), kind, value: value.into(), purpose: Some(purpose), extra: Default::default() });
            }
        }
        // "Password" items keep it here.
        if let Some(password) = secure.get("password").and_then(Value::as_str).filter(|p| !p.is_empty())
            && details.password().is_none()
        {
            details.fields.push(Field {
                id: new_field_id(),
                label: "password".into(),
                kind: FieldKind::Concealed,
                value: password.into(),
                purpose: Some(FieldPurpose::Password),
                extra: Default::default(),
            });
        }
        for section in secure.get("sections").and_then(Value::as_array).into_iter().flatten() {
            let fields: Vec<Field> = section.get("fields").and_then(Value::as_array).into_iter().flatten().filter_map(section_field).collect();
            if fields.is_empty() {
                continue;
            }
            let title = text(section.get("title"));
            if title.is_empty() {
                details.fields.extend(fields);
            } else {
                details.sections.push(Section { id: new_field_id(), title, fields });
            }
        }
        for entry in secure.get("passwordHistory").and_then(Value::as_array).into_iter().flatten() {
            if let Some(value) = entry.get("value").and_then(Value::as_str) {
                details.password_history.push(PasswordHistoryEntry { value: value.into(), changed_at: entry.get("time").and_then(Value::as_i64).unwrap_or(0) });
            }
        }
        details.sort_main_fields();
        let mut urls: Vec<ItemUrl> = secure
            .get("URLs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|u| {
                let href = text(u.get("url"));
                (!href.is_empty()).then(|| ItemUrl { href, label: text(u.get("label")), ..Default::default() })
            })
            .collect();
        let location = text(raw.get("location"));
        if urls.is_empty() && !location.is_empty() {
            urls.push(ItemUrl { href: location, ..Default::default() });
        }
        let title = text(raw.get("title"));
        let overview = ItemOverview {
            title: if title.is_empty() { "Untitled".into() } else { title },
            subtitle: details.username().unwrap_or("").to_string(),
            category,
            urls,
            tags: raw
                .get("openContents")
                .and_then(|o| o.get("tags"))
                .and_then(Value::as_array)
                .map(|t| t.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default(),
            favorite: raw.get("faveIndex").and_then(Value::as_i64).unwrap_or(0) > 0,
            created_at: raw.get("createdAt").and_then(Value::as_i64).unwrap_or(0),
            updated_at: raw.get("updatedAt").and_then(Value::as_i64).unwrap_or(0),
            ..Default::default()
        };
        items.push(ImportedItem::new(text(raw.get("uuid")), overview, details, Vec::new()));
    }
    let mut warnings = Vec::new();
    if skipped > 0 {
        warnings.push(ImportWarning::new("item_skipped", skipped));
    }
    Ok(ImportResult { vaults: vec![ImportedVault { name: vault_name.to_string(), items }], warnings }.link())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_items() {
        let data = format!(
            "{}\n{SEPARATOR}\n{}\n{SEPARATOR}\n{}\n{SEPARATOR}\n",
            r#"{"uuid":"a","title":"Mail","typeName":"webforms.WebForm","location":"https://mail.example","openContents":{"tags":["Work"]},
               "secureContents":{"fields":[{"value":"me","name":"u","type":"T","designation":"username"},{"value":"pw","name":"p","type":"P","designation":"password"}],
               "sections":[{"title":"","fields":[{"k":"concealed","t":"one-time password","v":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}]}],
               "passwordHistory":[{"value":"old","time":1600000000}],"notesPlain":"hi"}}"#,
            r#"{"uuid":"b","title":"Me","typeName":"identities.Identity","secureContents":{"sections":[{"title":"Address","fields":[{"k":"address","t":"home","v":{"street":"Rua A","city":"Recife","country":"br"}}]}]}}"#,
            r#"{"uuid":"c","title":"Folder","typeName":"system.folder.Regular"}"#,
        );
        assert!(detect(&data));
        let result = parse_1pif(&data, "1Password").unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].details.password(), Some("pw"));
        assert!(items[0].details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert_eq!(items[0].overview.tags, vec!["Work"]);
        assert_eq!(items[0].details.password_history.len(), 1);
        assert_eq!(items[1].details.sections[0].fields[0].kind, FieldKind::Address);
    }
}
