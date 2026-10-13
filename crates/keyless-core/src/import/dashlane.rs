//! Dashlane's CSV export: a zip archive with a file per kind of item
//! (`credentials.csv`, `securenotes.csv`, `payments.csv`; the others, such
//! as IDs and personal details, are read as notes).

use std::io::{Read, Seek};

use super::{ImportResult, ImportWarning, ImportedItem, ImportedVault, csv::parse_csv};
use crate::{
    Error, Result,
    item::{Category, Field, FieldKind, ItemDetails, ItemOverview, new_field_id},
};

/// Refuse to inflate more than this for one file of the archive.
const MAX_CSV_BYTES: u64 = 64 * 1024 * 1024;

fn read(archive: &mut zip::ZipArchive<impl Read + Seek>, name: &str) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let Ok(file) = archive.by_name(name) else { return Ok(None) };
    let mut out = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CSV_BYTES).read_to_end(&mut out).map_err(|e| Error::Import(e.to_string()))?;
    Ok(Some(out))
}

/// `payments.csv`: cards (and bank accounts) with their own columns.
fn payments(contents: &[u8]) -> Result<Vec<ImportedItem>> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(contents);
    let headers: Vec<String> = rdr.headers().map_err(|e| Error::Import(e.to_string()))?.iter().map(|h| h.trim().to_ascii_lowercase()).collect();
    let col = |name: &str| headers.iter().position(|h| h == name);
    let mut items = Vec::new();
    for record in rdr.records().flatten() {
        let get = |name: &str| col(name).and_then(|i| record.get(i)).unwrap_or("").trim().to_string();
        let kind = get("type");
        let mut details = ItemDetails::default();
        details.notes = get("note");
        let mut push = |label: &str, kind: FieldKind, value: String| {
            if !value.is_empty() {
                details.fields.push(Field { id: new_field_id(), label: label.into(), kind, value, purpose: None, extra: Default::default() });
            }
        };
        let category = if kind.contains("bank") {
            push("name on account", FieldKind::Text, get("account_holder"));
            push("bank name", FieldKind::Text, get("issuing_bank"));
            push("account number", FieldKind::Concealed, get("account_number"));
            push("routing number", FieldKind::Text, get("routing_number"));
            Category::BankAccount
        } else {
            push("cardholder name", FieldKind::Text, get("account_holder"));
            push("number", FieldKind::CardNumber, get("cc_number"));
            let (month, year) = (get("expiration_month"), get("expiration_year"));
            if !month.is_empty() && !year.is_empty() {
                push("expiry date", FieldKind::MonthYear, format!("{month:0>2}/{year}"));
            }
            push("verification number", FieldKind::Concealed, get("code"));
            push("bank name", FieldKind::Text, get("issuing_bank"));
            Category::CreditCard
        };
        let mut title = get("account_name");
        if title.is_empty() {
            title = get("name");
        }
        if details.fields.is_empty() && details.notes.is_empty() {
            continue;
        }
        let overview = ItemOverview { title: if title.is_empty() { "Untitled".into() } else { title }, category, ..Default::default() };
        items.push(ImportedItem::new("", overview, details, Vec::new()));
    }
    Ok(items)
}

pub fn parse_dashlane_zip<R: Read + Seek>(reader: R, vault_name: &str) -> Result<ImportResult> {
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| Error::Import(format!("not a valid archive: {e}")))?;
    let mut items = Vec::new();
    let mut warnings: Vec<ImportWarning> = Vec::new();
    let mut found = false;
    for name in ["credentials.csv", "securenotes.csv"] {
        if let Some(contents) = read(&mut archive, name)? {
            found = true;
            let mut result = parse_csv(contents.as_slice(), vault_name)?;
            warnings.append(&mut result.warnings);
            items.extend(result.vaults.into_iter().flat_map(|v| v.items));
        }
    }
    if let Some(contents) = read(&mut archive, "payments.csv")? {
        found = true;
        items.extend(payments(&contents)?);
    }
    if !found {
        return Err(Error::Import("credentials.csv not found; is this Dashlane's CSV export?".into()));
    }
    Ok(ImportResult { vaults: vec![ImportedVault { name: vault_name.to_string(), items }], warnings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    #[test]
    fn reads_the_archive() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("credentials.csv", options).unwrap();
            zip.write_all(b"username,username2,username3,title,password,note,url,category,otpSecret\nme,,,Mail,pw,,https://mail.example,Email,\n").unwrap();
            zip.start_file("securenotes.csv", options).unwrap();
            zip.write_all(b"title,note\nWi-Fi,in the hall\n").unwrap();
            zip.start_file("payments.csv", options).unwrap();
            zip.write_all(b"type,account_name,account_holder,cc_number,code,expiration_month,expiration_year,routing_number,account_number,country,issuing_bank,note,name\npayment_card,Visa,Ana,4111111111111111,123,7,2029,,,BR,Bank,,\n").unwrap();
            zip.finish().unwrap();
        }
        let result = parse_dashlane_zip(Cursor::new(buf.into_inner()), "Dashlane").unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].details.password(), Some("pw"));
        assert_eq!(items[1].overview.category, Category::SecureNote);
        assert_eq!(items[2].overview.category, Category::CreditCard);
        assert!(items[2].details.fields.iter().any(|f| f.kind == FieldKind::MonthYear && f.value == "07/2029"));
    }
}
