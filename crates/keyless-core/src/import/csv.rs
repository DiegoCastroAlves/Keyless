//! CSV import for browser and password manager exports (Chrome, Edge,
//! Firefox, Bitwarden, 1Password CSV, generic "title,url,username,password").

use std::io::Read;

use super::{ImportResult, ImportWarning, ImportedItem, ImportedVault};
use crate::{
    Error, Result,
    item::{Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, new_field_id},
};

const MAX_ROWS: usize = 100_000;

#[derive(Default)]
struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    favorite: Option<usize>,
    tags: Option<usize>,
    kind: Option<usize>,
    /// Bitwarden's custom fields: one "name: value" per line.
    fields: Option<usize>,
}

/// Custom fields with these words in their name are imported hidden.
const SECRET_LABEL: [&str; 14] =
    ["password", "senha", "contraseña", "secret", "pin", "code", "código", "key", "token", "recovery", "number", "número", "cvv", "cvc"];

fn find(headers: &[String], names: &[&str]) -> Option<usize> {
    names
        .iter()
        .find_map(|name| headers.iter().position(|h| h == name))
}

pub fn parse_csv<R: Read>(reader: R, vault_name: &str) -> Result<ImportResult> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(reader);
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| Error::Import(format!("invalid CSV: {e}")))?
        .iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_ascii_lowercase())
        .collect();

    let cols = Columns {
        title: find(&headers, &["title", "name"]),
        url: find(&headers, &["url", "login_uri", "website", "uri", "web site", "login url"]),
        username: find(&headers, &["username", "login_username", "user name", "email", "login"]),
        password: find(&headers, &["password", "login_password"]),
        notes: find(&headers, &["notes", "note", "extra", "comments"]),
        totp: find(&headers, &["otpauth", "totp", "login_totp", "one-time password"]),
        favorite: find(&headers, &["favorite"]),
        tags: find(&headers, &["tags", "folder", "grouping"]),
        kind: find(&headers, &["type"]),
        fields: find(&headers, &["fields"]),
    };
    // Bitwarden puts every address of an item in `login_uri`, separated by
    // commas; a plain `url` column holds one address (which may contain
    // commas).
    let url_list = cols.url.is_some_and(|i| headers[i] == "login_uri");
    if cols.password.is_none() && cols.notes.is_none() {
        return Err(Error::Import(
            "could not find a password column; supported: Chrome, Edge, Firefox, Bitwarden and 1Password CSV".into(),
        ));
    }

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for (index, record) in rdr.records().enumerate() {
        if index >= MAX_ROWS {
            warnings.push(ImportWarning::new("rows_limited", MAX_ROWS));
            break;
        }
        let record = match record {
            Ok(r) => r,
            Err(_) => {
                warnings.push(ImportWarning::new("row_skipped", index + 2));
                continue;
            }
        };
        let get = |col: Option<usize>| col.and_then(|i| record.get(i)).unwrap_or("").trim().to_string();
        // Cells Keyless's own export kept from running as formulas.
        let cell = |col: Option<usize>| crate::export::from_spreadsheet(get(col));

        let urls: Vec<String> = if url_list {
            cell(cols.url).split(',').map(str::trim).filter(|u| !u.is_empty()).map(String::from).collect()
        } else {
            Some(cell(cols.url)).filter(|u| !u.is_empty()).into_iter().collect()
        };
        let url = urls.first().cloned().unwrap_or_default();
        let username = cell(cols.username);
        // Spaces can be part of a password.
        let password = cols.password.and_then(|i| record.get(i)).unwrap_or("").to_string();
        let extra: Vec<(String, String)> = cell(cols.fields)
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(label, value)| (label.trim().to_string(), value.trim().to_string()))
            .filter(|(label, value)| !label.is_empty() && !value.is_empty())
            .collect();
        let notes = get(cols.notes);
        let totp = get(cols.totp);
        let kind = get(cols.kind).to_ascii_lowercase();
        let mut title = cell(cols.title);
        if title.is_empty() {
            title = host_of(&url).unwrap_or_else(|| "Untitled".into());
        }
        if url.is_empty() && username.is_empty() && password.is_empty() && notes.is_empty() && extra.is_empty() {
            continue;
        }

        let category = match kind.as_str() {
            "note" | "securenote" | "secure note" => Category::SecureNote,
            "card" => Category::CreditCard,
            "identity" => Category::Identity,
            _ if password.is_empty() && username.is_empty() && (!notes.is_empty() || !extra.is_empty()) => Category::SecureNote,
            _ => Category::Login,
        };

        let mut details = ItemDetails::default();
        details.notes = notes;
        if !username.is_empty() {
            details.fields.push(Field {
                id: new_field_id(),
                label: "username".into(),
                kind: FieldKind::Text,
                value: username.clone(),
                purpose: Some(FieldPurpose::Username),
            });
        }
        if !password.is_empty() {
            details.fields.push(Field {
                id: new_field_id(),
                label: "password".into(),
                kind: FieldKind::Concealed,
                value: password,
                purpose: Some(FieldPurpose::Password),
            });
        }
        if !totp.is_empty() {
            details.fields.push(Field {
                id: new_field_id(),
                label: "one-time password".into(),
                kind: FieldKind::Totp,
                value: totp,
                purpose: None,
            });
        }

        for (label, value) in extra {
            // The CSV does not say which fields are secret: guess from the name.
            let secret = SECRET_LABEL.iter().any(|word| label.to_lowercase().contains(word));
            details.fields.push(Field {
                id: new_field_id(),
                label,
                kind: if secret { FieldKind::Concealed } else { FieldKind::Text },
                value,
                purpose: None,
            });
        }

        let favorite = matches!(get(cols.favorite).to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        let tags = cell(cols.tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();

        items.push(ImportedItem {
            overview: ItemOverview {
                title,
                subtitle: username,
                category,
                urls: urls.into_iter().map(|href| ItemUrl { href, ..Default::default() }).collect(),
                tags,
                favorite,
                ..Default::default()
            },
            details,
            files: Vec::new(),
        });
    }

    Ok(ImportResult {
        vaults: vec![ImportedVault { name: vault_name.to_string(), items }],
        warnings,
    })
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.split(':').next()?.trim_start_matches("www.");
    (!host.is_empty()).then(|| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_export() {
        let csv = "name,url,username,password,note\nGitHub,https://github.com/login,me,pw1,\n,https://www.example.com:8443/a,you,pw2,hi\n";
        let result = parse_csv(csv.as_bytes(), "Imported").unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].overview.title, "GitHub");
        assert_eq!(items[0].details.password(), Some("pw1"));
        assert_eq!(items[1].overview.title, "example.com");
        assert_eq!(items[1].details.notes, "hi");
    }

    #[test]
    fn bitwarden_export() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,Mail,,,,https://mail.example.com,me,pw,JBSWY3DPEHPK3PXP\n\
                   ,,note,Recipe,secret sauce,,,,,,\n";
        let result = parse_csv(csv.as_bytes(), "Imported").unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), 2);
        assert!(items[0].overview.favorite);
        assert_eq!(items[0].overview.tags, vec!["Work"]);
        assert!(items[0].details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert_eq!(items[1].overview.category, Category::SecureNote);
    }

    #[test]
    fn rejects_unknown_layout() {
        assert!(parse_csv("a,b,c\n1,2,3\n".as_bytes(), "x").is_err());
    }
}
