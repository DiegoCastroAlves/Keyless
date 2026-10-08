//! Keyless's own unencrypted exports (see `export`): the JSON, or the zip
//! archive with the JSON (`keyless-export.json`) and the attached files.
//! Attachments name their file in the archive; those without one (a JSON
//! export has no files) are left out, with a warning.

use std::{
    collections::HashMap,
    io::{Read, Seek},
};

use serde_json::Value;
use zeroize::Zeroizing;

use super::{ImportResult, ImportWarning, ImportedFile, ImportedItem, ImportedVault};
use crate::{
    Error, Result,
    attachment::clean_name,
    item::{ItemDetails, ItemOverview},
};

/// The JSON inside the zip archive.
const JSON_ENTRY: &str = "keyless-export.json";
/// Refuse a larger JSON.
const MAX_JSON_BYTES: u64 = 512 * 1024 * 1024;

fn not_export() -> Error {
    Error::Import("this is not a Keyless export".into())
}

/// Parses a Keyless export, the JSON alone or the zip archive.
pub fn parse_keyless_export<R: Read + Seek>(mut reader: R) -> Result<ImportResult> {
    let mut magic = [0u8; 4];
    let is_zip = reader.read_exact(&mut magic).is_ok() && magic == *b"PK\x03\x04";
    reader.rewind().map_err(|e| Error::Import(e.to_string()))?;
    let mut json = Zeroizing::new(Vec::new());
    let mut files = HashMap::new();
    if is_zip {
        let mut archive = zip::ZipArchive::new(reader).map_err(|_| not_export())?;
        for index in 0..archive.len() {
            if let Ok(file) = archive.by_index_raw(index)
                && file.is_file()
                && file.name().starts_with("attachments/")
            {
                files.insert(file.name().to_string(), file.size());
            }
        }
        let entry = archive.by_name(JSON_ENTRY).map_err(|_| not_export())?;
        entry
            .take(MAX_JSON_BYTES + 1)
            .read_to_end(&mut json)
            .map_err(|e| Error::Import(e.to_string()))?;
    } else {
        reader
            .take(MAX_JSON_BYTES + 1)
            .read_to_end(&mut json)
            .map_err(|e| Error::Import(e.to_string()))?;
    }
    if json.len() as u64 > MAX_JSON_BYTES {
        return Err(Error::Import("the export is too large".into()));
    }
    parse_export_json(&json, &files)
}

/// Parses the JSON; `files` are the archive's entries under `attachments/`
/// and their sizes.
pub fn parse_export_json(json: &[u8], files: &HashMap<String, u64>) -> Result<ImportResult> {
    let mut export: Value = serde_json::from_slice(json).map_err(|_| not_export())?;
    if export.get("format").and_then(Value::as_str) != Some("keyless-export") {
        return Err(not_export());
    }
    if export.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(Error::Import("unsupported export version".into()));
    }
    let mut result = ImportResult { vaults: Vec::new(), warnings: Vec::new() };
    let mut missing = 0;
    let mut skipped = 0;
    let vaults = match export.get_mut("vaults").map(Value::take) {
        Some(Value::Array(vaults)) => vaults,
        _ => return Err(not_export()),
    };
    for mut vault in vaults {
        let name = vault.get("name").and_then(Value::as_str).filter(|n| !n.trim().is_empty()).unwrap_or("Imported").to_string();
        let mut items = Vec::new();
        let raw_items = match vault.get_mut("items").map(Value::take) {
            Some(Value::Array(items)) => items,
            _ => Vec::new(),
        };
        for mut raw in raw_items {
            // The attachments, without keys: their files come from the archive.
            let attachments = raw
                .get_mut("details")
                .and_then(|d| d.as_object_mut())
                .and_then(|d| d.remove("attachments"))
                .and_then(|a| match a {
                    Value::Array(list) => Some(list),
                    _ => None,
                })
                .unwrap_or_default();
            let (Some(overview), Some(details)) = (raw.get_mut("overview").map(Value::take), raw.get_mut("details").map(Value::take)) else {
                skipped += 1;
                continue;
            };
            let (Ok(overview), Ok(details)) = (serde_json::from_value::<ItemOverview>(overview), serde_json::from_value::<ItemDetails>(details)) else {
                skipped += 1;
                continue;
            };
            let mut item_files = Vec::new();
            for attachment in attachments {
                let entry = attachment.get("file").and_then(Value::as_str).and_then(|path| files.get_key_value(path));
                match entry {
                    Some((path, size)) => item_files.push(ImportedFile {
                        name: clean_name(attachment.get("name").and_then(Value::as_str).unwrap_or("file")),
                        size: *size,
                        entry: path.clone(),
                        sealed: None,
                    }),
                    None => missing += 1,
                }
            }
            items.push(ImportedItem { overview, details, files: item_files });
        }
        result.vaults.push(ImportedVault { name, items });
    }
    if skipped > 0 {
        result.warnings.push(ImportWarning::new("item_skipped", skipped));
    }
    if missing > 0 {
        result.warnings.push(ImportWarning::new("files_missing", missing));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use crate::{
        attachment::Attachment,
        backup::{BackupData, BackupItem, BackupVault},
        export::{ExportZip, to_json},
        import::ImportArchive,
        item::{Category, Field, FieldKind, FieldPurpose},
    };

    fn sample() -> BackupData {
        let mut details = ItemDetails::default();
        details.fields.push(Field {
            id: "p".into(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: "s3cret".into(),
            purpose: Some(FieldPurpose::Password),
        });
        details.notes = "hello".into();
        BackupData {
            exported_at: 1,
            vaults: vec![BackupVault {
                name: "Work".into(),
                description: String::new(),
                items: vec![BackupItem {
                    overview: ItemOverview { title: "Mail".into(), category: Category::Login, favorite: true, ..Default::default() },
                    details,
                }],
            }],
        }
    }

    #[test]
    fn reads_the_json_export() {
        let mut data = sample();
        data.vaults[0].items[0].details.attachments.push(Attachment::new("scan.pdf", 3, 1).unwrap());
        let json = to_json(&data).unwrap();
        let result = parse_keyless_export(Cursor::new(json)).unwrap();
        let item = &result.vaults[0].items[0];
        assert_eq!(result.vaults[0].name, "Work");
        assert_eq!(item.overview.title, "Mail");
        assert!(item.overview.favorite);
        assert_eq!(item.details.password(), Some("s3cret"));
        assert_eq!(item.details.notes, "hello");
        // A JSON export has no files.
        assert!(item.files.is_empty() && item.details.attachments.is_empty());
        assert_eq!(result.warnings, vec![ImportWarning::new("files_missing", 1)]);
    }

    #[test]
    fn reads_the_zip_export_with_its_files() {
        let mut data = sample();
        let scan = Attachment::new("scan.pdf", 4, 1).unwrap();
        data.vaults[0].items[0].details.attachments.push(scan.clone());
        let mut export = ExportZip::new(Cursor::new(Vec::new()));
        export.start_file(&scan).unwrap();
        export.write(b"%PDF").unwrap();
        export.end_file();
        let file = export.finish(&data).unwrap().into_inner();

        let result = parse_keyless_export(Cursor::new(file.clone())).unwrap();
        assert!(result.warnings.is_empty());
        let item = &result.vaults[0].items[0];
        assert_eq!(item.files.len(), 1);
        assert_eq!((item.files[0].name.as_str(), item.files[0].size), ("scan.pdf", 4));
        let mut archive = ImportArchive::open(Cursor::new(file)).unwrap();
        let mut read = Vec::new();
        archive
            .read_file(&item.files[0], |chunk| {
                read.extend_from_slice(&chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(read, b"%PDF");
    }

    #[test]
    fn refuses_other_files() {
        assert!(parse_keyless_export(Cursor::new(b"{\"format\":\"other\"}".to_vec())).is_err());
        assert!(parse_keyless_export(Cursor::new(b"not json".to_vec())).is_err());
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            zip.start_file("export.data", zip::write::SimpleFileOptions::default()).unwrap();
            zip.write_all(b"{}").unwrap();
            zip.finish().unwrap();
        }
        assert!(parse_keyless_export(Cursor::new(buf.into_inner())).is_err());
    }
}
