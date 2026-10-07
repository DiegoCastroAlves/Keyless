//! 1Password `.1pux` import.
//!
//! A 1PUX file is an (unencrypted) zip archive whose `export.data` entry is a
//! JSON document: `accounts[].vaults[].items[]`. Attachments live in `files/`
//! and are not imported yet.

use std::io::{Read, Seek};

use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{ImportResult, ImportedItem, ImportedVault};
use crate::{
    Error, Result,
    item::{
        Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, UrlMatch,
        PasswordHistoryEntry, Section, new_field_id,
    },
};

/// Refuse to inflate more than this (zip bomb protection).
const MAX_EXPORT_DATA_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
struct Account {
    #[serde(default)]
    vaults: Vec<Vault>,
}

#[derive(Deserialize)]
struct Vault {
    #[serde(default)]
    attrs: VaultAttrs,
    #[serde(default)]
    items: Vec<Value>,
}

#[derive(Deserialize, Default)]
struct VaultAttrs {
    #[serde(default)]
    name: String,
}

pub fn parse_1pux<R: Read + Seek>(reader: R) -> Result<ImportResult> {
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| Error::Import(format!("not a valid .1pux file: {e}")))?;
    let entry = archive
        .by_name("export.data")
        .map_err(|_| Error::Import("export.data not found; is this a .1pux file?".into()))?;
    let mut json = Zeroizing::new(Vec::new());
    entry
        .take(MAX_EXPORT_DATA_BYTES + 1)
        .read_to_end(&mut json)
        .map_err(|e| Error::Import(e.to_string()))?;
    if json.len() as u64 > MAX_EXPORT_DATA_BYTES {
        return Err(Error::Import("export is too large".into()));
    }
    parse_export_data(&json)
}

pub fn parse_export_data(json: &[u8]) -> Result<ImportResult> {
    let export: Export = serde_json::from_slice(json).map_err(|e| Error::Import(format!("invalid export.data: {e}")))?;
    let mut result = ImportResult { vaults: Vec::new(), warnings: Vec::new() };
    let mut attachments = 0usize;

    for account in export.accounts {
        for vault in account.vaults {
            let mut items = Vec::new();
            for raw in &vault.items {
                match convert_item(raw, &mut attachments) {
                    Some(item) => items.push(item),
                    None => result.warnings.push("An item could not be read and was skipped.".into()),
                }
            }
            let name = if vault.attrs.name.trim().is_empty() { "Imported".to_string() } else { vault.attrs.name.clone() };
            result.vaults.push(ImportedVault { name, items });
        }
    }
    if attachments > 0 {
        result.warnings.push(format!(
            "{attachments} attachment(s) were not imported. Keep the original files until attachments are supported."
        ));
    }
    Ok(result)
}

fn convert_item(raw: &Value, attachments: &mut usize) -> Option<ImportedItem> {
    let state = raw.get("state").and_then(Value::as_str).unwrap_or("active");
    if state == "deleted" {
        return None;
    }
    let overview_raw = raw.get("overview")?;
    let details_raw = raw.get("details").cloned().unwrap_or(Value::Null);
    let category = map_category(raw.get("categoryUuid").and_then(Value::as_str).unwrap_or(""));

    let mut details = ItemDetails::default();

    // Login fields: only the designated username/password are meaningful.
    if let Some(login_fields) = details_raw.get("loginFields").and_then(Value::as_array) {
        for lf in login_fields {
            let value = lf.get("value").and_then(Value::as_str).unwrap_or("");
            let designation = lf.get("designation").and_then(Value::as_str).unwrap_or("");
            let (purpose, kind, label) = match designation {
                "username" => (FieldPurpose::Username, FieldKind::Text, "username"),
                "password" => (FieldPurpose::Password, FieldKind::Concealed, "password"),
                _ => continue,
            };
            if details.field_by_purpose(purpose).is_some() {
                continue;
            }
            details.fields.push(Field {
                id: new_field_id(),
                label: label.into(),
                kind,
                value: value.into(),
                purpose: Some(purpose),
            });
        }
    }

    details.sort_main_fields();

    // "Password" items keep their value in details.password.
    if let Some(pw) = details_raw.get("password").and_then(Value::as_str)
        && details.password().is_none()
    {
        details.fields.push(Field {
            id: new_field_id(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: pw.into(),
            purpose: Some(FieldPurpose::Password),
        });
    }

    if let Some(sections) = details_raw.get("sections").and_then(Value::as_array) {
        for section in sections {
            let title = section.get("title").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let mut fields = Vec::new();
            for f in section.get("fields").and_then(Value::as_array).into_iter().flatten() {
                if let Some(field) = convert_field(f, attachments) {
                    fields.push(field);
                }
            }
            if fields.is_empty() {
                continue;
            }
            if title.is_empty() {
                details.fields.extend(fields);
            } else {
                details.sections.push(Section { id: new_field_id(), title, fields });
            }
        }
    }

    details.notes = details_raw.get("notesPlain").and_then(Value::as_str).unwrap_or("").to_string();

    if let Some(history) = details_raw.get("passwordHistory").and_then(Value::as_array) {
        for entry in history {
            if let Some(value) = entry.get("value").and_then(Value::as_str) {
                details.password_history.push(PasswordHistoryEntry {
                    value: value.into(),
                    changed_at: entry.get("time").and_then(Value::as_i64).unwrap_or(0),
                });
            }
        }
    }
    if details_raw.get("documentAttributes").is_some() {
        *attachments += 1;
    }

    let mut urls = Vec::new();
    if let Some(list) = overview_raw.get("urls").and_then(Value::as_array) {
        for u in list {
            if let Some(href) = u.get("url").and_then(Value::as_str).filter(|h| !h.is_empty()) {
                // 1Password's "autofill behavior" for the address.
                let fill = match u.get("mode").and_then(Value::as_str).unwrap_or("") {
                    "never" => UrlMatch::Never,
                    "exact" | "host" => UrlMatch::Host,
                    _ => UrlMatch::Domain,
                };
                urls.push(ItemUrl { href: href.into(), label: u.get("label").and_then(Value::as_str).unwrap_or("").into(), fill, ..Default::default() });
            }
        }
    }
    if urls.is_empty()
        && let Some(href) = overview_raw.get("url").and_then(Value::as_str).filter(|h| !h.is_empty())
    {
        urls.push(ItemUrl { href: href.into(), ..Default::default() });
    }

    let tags = overview_raw
        .get("tags")
        .and_then(Value::as_array)
        .map(|t| t.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();

    let title = overview_raw.get("title").and_then(Value::as_str).unwrap_or("").to_string();
    let mut subtitle = overview_raw.get("subtitle").and_then(Value::as_str).unwrap_or("").to_string();
    if subtitle.is_empty()
        && let Some(username) = details.username()
    {
        subtitle = username.to_string();
    }

    let overview = ItemOverview {
        title: if title.is_empty() { "Untitled".into() } else { title },
        subtitle,
        category,
        urls,
        tags,
        favorite: raw.get("favIndex").and_then(Value::as_i64).unwrap_or(0) > 0,
        archived: state == "archived",
        trashed_at: None,
        created_at: raw.get("createdAt").and_then(Value::as_i64).unwrap_or(0),
        updated_at: raw.get("updatedAt").and_then(Value::as_i64).unwrap_or(0),
        ..Default::default()
    };
    Some(ImportedItem { overview, details })
}

fn convert_field(raw: &Value, attachments: &mut usize) -> Option<Field> {
    let label = raw.get("title").and_then(Value::as_str).unwrap_or("").to_string();
    let value_obj = raw.get("value")?.as_object()?;
    let (kind_name, value) = value_obj.iter().next()?;
    let multiline = raw.get("multiline").and_then(Value::as_bool).unwrap_or(false);

    let (kind, text) = match kind_name.as_str() {
        "concealed" => (FieldKind::Concealed, as_text(value)),
        "string" => (if multiline { FieldKind::Multiline } else { FieldKind::Text }, as_text(value)),
        "email" => (
            FieldKind::Email,
            value
                .get("email_address")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| as_text(value)),
        ),
        "phone" => (FieldKind::Phone, as_text(value)),
        "url" => (FieldKind::Url, as_text(value)),
        "totp" => (FieldKind::Totp, as_text(value)),
        "creditCardNumber" => (FieldKind::CardNumber, as_text(value)),
        "date" => (FieldKind::Date, value.as_i64().map(format_unix_date).unwrap_or_default()),
        "monthYear" => (FieldKind::MonthYear, value.as_i64().map(format_month_year).unwrap_or_default()),
        "address" => (FieldKind::Multiline, format_address(value)),
        "sshKey" => (
            FieldKind::Concealed,
            value.get("privateKey").and_then(Value::as_str).unwrap_or("").to_string(),
        ),
        "file" => {
            *attachments += 1;
            return None;
        }
        "reference" => return None,
        // creditCardType, menu, gender, and anything newer: keep as text.
        _ => (FieldKind::Text, as_text(value)),
    };
    if text.is_empty() {
        return None;
    }
    Some(Field { id: new_field_id(), label, kind, value: text, purpose: None })
}

fn as_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn format_address(value: &Value) -> String {
    ["street", "city", "state", "zip", "country"]
        .iter()
        .filter_map(|k| value.get(k).and_then(Value::as_str))
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// 1PUX `monthYear` values are `YYYYMM` integers.
fn format_month_year(v: i64) -> String {
    if v <= 0 {
        return String::new();
    }
    format!("{:02}/{}", v % 100, v / 100)
}

/// Formats unix seconds as `YYYY-MM-DD` (UTC) without pulling in a date crate.
fn format_unix_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    // Civil-from-days algorithm (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn map_category(uuid: &str) -> Category {
    match uuid {
        "001" => Category::Login,
        "002" => Category::CreditCard,
        "003" => Category::SecureNote,
        "004" => Category::Identity,
        "005" => Category::Password,
        "006" => Category::Document,
        "100" => Category::SoftwareLicense,
        "101" => Category::BankAccount,
        "102" => Category::Database,
        "103" => Category::DriverLicense,
        "105" | "107" => Category::Membership,
        "106" => Category::Passport,
        "109" => Category::WirelessRouter,
        "110" => Category::Server,
        "111" => Category::EmailAccount,
        "112" => Category::ApiCredential,
        "113" => Category::MedicalRecord,
        "114" => Category::SshKey,
        "115" => Category::CryptoWallet,
        _ => Category::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    const SAMPLE: &str = r#"{
      "accounts": [{
        "attrs": {"name": "Me"},
        "vaults": [{
          "attrs": {"uuid": "v", "name": "Personal"},
          "items": [
            {
              "uuid": "a", "favIndex": 1, "createdAt": 1614298956, "updatedAt": 1635346445,
              "state": "active", "categoryUuid": "001",
              "details": {
                "loginFields": [
                  {"value": "me@example.com", "name": "email", "fieldType": "E", "designation": "username"},
                  {"value": "s3cret", "name": "password", "fieldType": "P", "designation": "password"},
                  {"value": "", "name": "remember", "fieldType": "C"}
                ],
                "notesPlain": "hello",
                "sections": [
                  {"title": "", "fields": [
                    {"title": "one-time password", "id": "TOTP_x", "value": {"totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}}
                  ]},
                  {"title": "Security", "fields": [
                    {"title": "PIN", "id": "pin", "value": {"concealed": "1234"}},
                    {"title": "Birthday", "id": "bd", "value": {"date": 0}},
                    {"title": "Expires", "id": "ex", "value": {"monthYear": 202712}},
                    {"title": "Scan", "id": "f", "value": {"file": {"fileName": "x.png"}}}
                  ]}
                ],
                "passwordHistory": [{"value": "old", "time": 1600000000}]
              },
              "overview": {
                "title": "Example", "subtitle": "",
                "urls": [{"label": "website", "url": "https://example.com/login"}],
                "tags": ["work"]
              }
            },
            {
              "uuid": "b", "state": "archived", "categoryUuid": "002",
              "details": {"sections": [{"title": "", "fields": [
                {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
                {"title": "type", "id": "type", "value": {"creditCardType": "visa"}}
              ]}]},
              "overview": {"title": "Visa"}
            },
            {"uuid": "c", "state": "active", "categoryUuid": "005", "details": {"password": "pw"}, "overview": {"title": "Wifi"}},
            {"uuid": "d", "categoryUuid": "001"}
          ]
        }]
      }]
    }"#;

    #[test]
    fn parses_sample_export() {
        let result = parse_export_data(SAMPLE.as_bytes()).unwrap();
        assert_eq!(result.vaults.len(), 1);
        let vault = &result.vaults[0];
        assert_eq!(vault.name, "Personal");
        assert_eq!(vault.items.len(), 3);
        assert_eq!(result.warnings.len(), 2); // skipped item + attachment

        let login = &vault.items[0];
        assert_eq!(login.overview.title, "Example");
        assert_eq!(login.overview.subtitle, "me@example.com");
        assert!(login.overview.favorite);
        assert_eq!(login.overview.urls[0].href, "https://example.com/login");
        assert_eq!(login.overview.tags, vec!["work"]);
        assert_eq!(login.details.username(), Some("me@example.com"));
        assert_eq!(login.details.password(), Some("s3cret"));
        assert_eq!(login.details.notes, "hello");
        assert!(login.details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        let security = &login.details.sections[0];
        assert_eq!(security.title, "Security");
        assert_eq!(security.fields.len(), 3);
        assert_eq!(security.fields[1].value, "1970-01-01");
        assert_eq!(security.fields[2].value, "12/2027");
        assert_eq!(login.details.password_history[0].value, "old");

        let card = &vault.items[1];
        assert!(card.overview.archived);
        assert_eq!(card.overview.category, Category::CreditCard);
        assert_eq!(card.details.fields[0].kind, FieldKind::CardNumber);

        assert_eq!(vault.items[2].details.password(), Some("pw"));
    }

    #[test]
    fn parses_zip_container() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            zip.start_file("export.attributes", zip::write::SimpleFileOptions::default()).unwrap();
            zip.write_all(b"{}").unwrap();
            zip.start_file("export.data", zip::write::SimpleFileOptions::default()).unwrap();
            zip.write_all(SAMPLE.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        buf.set_position(0);
        let result = parse_1pux(buf).unwrap();
        assert_eq!(result.summary().total_items, 3);
    }

    #[test]
    fn rejects_non_zip() {
        assert!(parse_1pux(Cursor::new(b"not a zip".to_vec())).is_err());
    }

    #[test]
    fn date_formatting() {
        assert_eq!(format_unix_date(0), "1970-01-01");
        assert_eq!(format_unix_date(951_782_400), "2000-02-29");
        assert_eq!(format_unix_date(-86_400), "1969-12-31");
    }
}
