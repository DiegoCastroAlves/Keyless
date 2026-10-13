//! Keeper's JSON export: `records[]` with a title, login, password, website
//! (`login_url`), notes, custom fields and the folders they are in. The
//! one-time password is a custom field ("TFC:Keeper", or "$oneTimeCode"),
//! and newer record types keep their typed fields there too ("$name::1").

use serde_json::Value;

use super::{ImportResult, ImportWarning, ImportedItem, ImportedVault};
use crate::{
    Result,
    item::{Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, new_field_id},
};

/// Custom fields with these words in their name are imported hidden.
const SECRET_LABEL: [&str; 12] = ["password", "senha", "contraseña", "secret", "pin", "code", "código", "key", "token", "number", "cvv", "cvc"];

/// Whether `json` looks like a Keeper export.
pub fn detect(json: &Value) -> bool {
    json.get("records").is_some_and(Value::is_array)
}

fn text(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").trim().to_string()
}

fn field(label: &str, kind: FieldKind, value: String, purpose: Option<FieldPurpose>) -> Field {
    Field { id: new_field_id(), label: label.into(), kind, value, purpose, extra: Default::default() }
}

/// A custom field's name without Keeper's markers ("$pinCode::1" is "pinCode").
fn clean_label(name: &str) -> String {
    let name = name.trim_start_matches('$');
    name.split("::").next().unwrap_or(name).to_string()
}

/// A custom field's value, as one field or several (an object, such as a
/// payment card, gives one per part).
fn custom_fields(name: &str, value: &Value, details: &mut ItemDetails) {
    match value {
        Value::String(text) if text.trim().is_empty() => {}
        Value::String(text) => {
            let text = text.trim().to_string();
            if name == "TFC:Keeper" || name.starts_with("$oneTimeCode") || text.starts_with("otpauth://") {
                details.fields.push(field("one-time password", FieldKind::Totp, text, None));
            } else {
                let label = clean_label(name);
                let secret = SECRET_LABEL.iter().any(|word| label.to_lowercase().contains(word));
                details.fields.push(field(&label, if secret { FieldKind::Concealed } else { FieldKind::Text }, text, None));
            }
        }
        Value::Number(_) | Value::Bool(_) => details.fields.push(field(&clean_label(name), FieldKind::Text, value.to_string(), None)),
        Value::Object(parts) => {
            for (part, inner) in parts {
                custom_fields(part, inner, details);
            }
        }
        Value::Array(list) => {
            for inner in list {
                custom_fields(name, inner, details);
            }
        }
        Value::Null => {}
    }
}

pub fn parse_keeper_json(json: &Value, vault_name: &str) -> Result<ImportResult> {
    let mut items = Vec::new();
    let mut skipped = 0;
    for raw in json.get("records").and_then(Value::as_array).into_iter().flatten() {
        let mut details = ItemDetails::default();
        details.notes = raw.get("notes").and_then(Value::as_str).unwrap_or("").to_string();
        let username = text(raw.get("login"));
        if !username.is_empty() {
            details.fields.push(field("username", FieldKind::Text, username.clone(), Some(FieldPurpose::Username)));
        }
        if let Some(password) = raw.get("password").and_then(Value::as_str).filter(|p| !p.is_empty()) {
            details.fields.push(field("password", FieldKind::Concealed, password.to_string(), Some(FieldPurpose::Password)));
        }
        if let Some(custom) = raw.get("custom_fields").and_then(Value::as_object) {
            for (name, value) in custom {
                custom_fields(name, value, &mut details);
            }
        }
        let url = text(raw.get("login_url"));
        let title = text(raw.get("title"));
        if title.is_empty() && url.is_empty() && details.fields.is_empty() && details.notes.is_empty() {
            skipped += 1;
            continue;
        }
        let record_type = text(raw.get("$type"));
        let category = match record_type.as_str() {
            "bankCard" => Category::CreditCard,
            "bankAccount" => Category::BankAccount,
            "address" | "contact" => Category::Identity,
            "encryptedNotes" => Category::SecureNote,
            "databaseCredentials" => Category::Database,
            "serverCredentials" | "sshKeys" => Category::Server,
            "softwareLicense" => Category::SoftwareLicense,
            "wifiCredentials" => Category::WirelessRouter,
            "driverLicense" => Category::DriverLicense,
            "passport" => Category::Passport,
            "membership" => Category::Membership,
            _ if username.is_empty() && details.password().is_none() && url.is_empty() => Category::SecureNote,
            _ => Category::Login,
        };
        // Folders: {"folder": "A\\B"} or {"shared_folder": "Team", "folder": "…"}.
        let mut tags: Vec<String> = Vec::new();
        for folder in raw.get("folders").and_then(Value::as_array).into_iter().flatten() {
            for key in ["shared_folder", "folder"] {
                for part in text(folder.get(key)).split('\\') {
                    let part = part.trim();
                    if !part.is_empty() && !tags.iter().any(|t| t == part) {
                        tags.push(part.to_string());
                    }
                }
            }
        }
        details.sort_main_fields();
        let overview = ItemOverview {
            title: if title.is_empty() { "Untitled".into() } else { title },
            subtitle: username,
            category,
            urls: Some(url).filter(|u| !u.is_empty()).map(|href| ItemUrl { href, ..Default::default() }).into_iter().collect(),
            tags,
            ..Default::default()
        };
        items.push(ImportedItem::new(text(raw.get("uid")), overview, details, Vec::new()));
    }
    let mut warnings = Vec::new();
    if skipped > 0 {
        warnings.push(ImportWarning::new("item_skipped", skipped));
    }
    Ok(ImportResult { vaults: vec![ImportedVault { name: vault_name.to_string(), items }], warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_records() {
        let json: Value = serde_json::from_str(
            r#"{"shared_folders": [], "records": [
              {"uid": "r1", "title": "VPN", "login": "me", "password": "pw", "login_url": "https://vpn.example", "notes": "n",
               "custom_fields": {"TFC:Keeper": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "$pinCode::1": "1234", "Region": "BR"},
               "folders": [{"folder": "Work\\Infra"}, {"shared_folder": "Team"}]},
              {"uid": "r2", "title": "Visa", "$type": "bankCard",
               "custom_fields": {"$paymentCard::1": {"cardNumber": "4111111111111111", "cardSecurityCode": "123"}}},
              {"uid": "r3"}
            ]}"#,
        )
        .unwrap();
        assert!(detect(&json));
        let result = parse_keeper_json(&json, "Keeper").unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), 2);
        let vpn = &items[0];
        assert_eq!(vpn.overview.tags, vec!["Work", "Infra", "Team"]);
        assert!(vpn.details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert!(vpn.details.fields.iter().any(|f| f.label == "pinCode" && f.kind == FieldKind::Concealed));
        assert!(vpn.details.fields.iter().any(|f| f.label == "Region" && f.kind == FieldKind::Text));
        assert_eq!(items[1].overview.category, Category::CreditCard);
        assert!(items[1].details.fields.iter().any(|f| f.label == "cardSecurityCode" && f.kind == FieldKind::Concealed));
        assert_eq!(result.warnings, vec![ImportWarning::new("item_skipped", 1)]);
    }
}
