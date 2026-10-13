//! CSV import for browser and password manager exports (Chrome, Edge,
//! Firefox, Safari and iCloud, Bitwarden, LastPass, 1Password, Dashlane,
//! RoboForm, KeePassXC, Dropbox Passwords, generic
//! "title,url,username,password"), and Keeper's, which has no header row
//! (`parse_keeper_csv`).

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
        // RoboForm: "pwd".
        password: find(&headers, &["password", "login_password", "pwd"]),
        notes: find(&headers, &["notes", "note", "extra", "comments"]),
        // Safari: "otpauth"; Dashlane: "otpsecret".
        totp: find(&headers, &["otpauth", "totp", "login_totp", "one-time password", "otpsecret", "otp"]),
        favorite: find(&headers, &["favorite", "fav"]),
        // KeePassXC: "group"; Dashlane: "category".
        tags: find(&headers, &["tags", "folder", "grouping", "group", "category"]),
        kind: find(&headers, &["type"]),
        fields: find(&headers, &["fields"]),
    };
    // Bitwarden puts every address of an item in `login_uri`, separated by
    // commas; a plain `url` column holds one address (which may contain
    // commas).
    let url_list = cols.url.is_some_and(|i| headers[i] == "login_uri");
    // LastPass's export ("url,username,password,totp,extra,name,grouping,fav").
    let lastpass = ["url", "username", "password", "extra", "name", "grouping"].iter().all(|h| headers.iter().any(|x| x == h));
    if cols.password.is_none() && cols.notes.is_none() {
        return Err(Error::Import(
            "could not find a password column; supported: Chrome, Edge, Firefox, Safari, Bitwarden, LastPass, 1Password, Dashlane, RoboForm and KeePassXC CSV".into(),
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
            // LastPass gives secure notes the address "http://sn".
            Some(cell(cols.url)).filter(|u| !u.is_empty() && !(lastpass && u == "http://sn")).into_iter().collect()
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
                extra: Default::default(),
            });
        }
        if !password.is_empty() {
            details.fields.push(Field {
                id: new_field_id(),
                label: "password".into(),
                kind: FieldKind::Concealed,
                value: password,
                purpose: Some(FieldPurpose::Password),
                extra: Default::default(),
            });
        }
        if !totp.is_empty() {
            details.fields.push(Field {
                id: new_field_id(),
                label: "one-time password".into(),
                kind: FieldKind::Totp,
                value: totp,
                purpose: None,
                extra: Default::default(),
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
                extra: Default::default(),
            });
        }

        let favorite = matches!(get(cols.favorite).to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        // KeePassXC's groups are paths from its root group ("Root/Email").
        let tags = cell(cols.tags)
            .split([',', ';'])
            .map(|t| t.trim().trim_start_matches("Root/").trim())
            .filter(|t| !t.is_empty() && *t != "Root")
            .map(String::from)
            .collect();

        items.push(ImportedItem::new(
            "",
            ItemOverview {
                title,
                subtitle: username,
                category,
                urls: urls.into_iter().map(|href| ItemUrl { href, ..Default::default() }).collect(),
                tags,
                favorite,
                imported_from: if lastpass { "lastpass".into() } else { String::new() },
                ..Default::default()
            },
            details,
            Vec::new(),
        ));
    }

    Ok(ImportResult {
        vaults: vec![ImportedVault { name: vault_name.to_string(), items }],
        warnings,
    })
}

/// Keeper's CSV export: no header row; each row is folder, title, login,
/// password, website, notes, shared folder, then custom fields as name and
/// value pairs (the one-time password among them, as "TFC:Keeper").
pub fn parse_keeper_csv<R: Read>(reader: R, vault_name: &str) -> Result<ImportResult> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(reader);
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for (index, record) in rdr.records().enumerate() {
        if index >= MAX_ROWS {
            warnings.push(ImportWarning::new("rows_limited", MAX_ROWS));
            break;
        }
        let Ok(record) = record else {
            warnings.push(ImportWarning::new("row_skipped", index + 1));
            continue;
        };
        if record.len() < 6 {
            return Err(Error::Import("not a Keeper CSV export: too few columns".into()));
        }
        let get = |i: usize| record.get(i).unwrap_or("").trim().to_string();
        let (folder, mut title, username, url, notes) = (get(0), get(1), get(2), get(4), get(5));
        let password = record.get(3).unwrap_or("").to_string();
        let mut details = ItemDetails::default();
        details.notes = notes;
        let mut field = |label: &str, kind: FieldKind, value: String, purpose: Option<FieldPurpose>| {
            details.fields.push(Field { id: new_field_id(), label: label.into(), kind, value, purpose, extra: Default::default() });
        };
        if !username.is_empty() {
            field("username", FieldKind::Text, username.clone(), Some(FieldPurpose::Username));
        }
        if !password.is_empty() {
            field("password", FieldKind::Concealed, password.clone(), Some(FieldPurpose::Password));
        }
        let custom: Vec<String> = record.iter().skip(7).map(str::to_string).collect();
        for pair in custom.chunks(2) {
            let (name, value) = (pair[0].trim(), pair.get(1).map(|v| v.trim()).unwrap_or(""));
            if name.is_empty() || value.is_empty() {
                continue;
            }
            if name == "TFC:Keeper" || value.starts_with("otpauth://") {
                field("one-time password", FieldKind::Totp, value.to_string(), None);
            } else {
                let secret = SECRET_LABEL.iter().any(|word| name.to_lowercase().contains(word));
                field(name, if secret { FieldKind::Concealed } else { FieldKind::Text }, value.to_string(), None);
            }
        }
        if url.is_empty() && username.is_empty() && password.is_empty() && details.notes.is_empty() && details.fields.is_empty() {
            continue;
        }
        if title.is_empty() {
            title = host_of(&url).unwrap_or_else(|| "Untitled".into());
        }
        let category = if username.is_empty() && password.is_empty() && url.is_empty() { Category::SecureNote } else { Category::Login };
        items.push(ImportedItem::new(
            "",
            ItemOverview {
                title,
                subtitle: username,
                category,
                urls: Some(url).filter(|u| !u.is_empty()).map(|href| ItemUrl { href, ..Default::default() }).into_iter().collect(),
                tags: folder.split('\\').map(str::trim).filter(|f| !f.is_empty()).map(String::from).collect(),
                ..Default::default()
            },
            details,
            Vec::new(),
        ));
    }
    Ok(ImportResult { vaults: vec![ImportedVault { name: vault_name.to_string(), items }], warnings })
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
    fn lastpass_export() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   https://shop.example.com,me@example.com,pw,,,Shop,Personal,1\n\
                   http://sn,,,,The wifi is in the hall,Home notes,,0\n";
        let result = parse_csv(csv.as_bytes(), "Imported").unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].overview.title, "Shop");
        assert!(items[0].overview.favorite);
        assert_eq!(items[0].overview.imported_from, "lastpass");
        assert_eq!(items[1].overview.category, Category::SecureNote);
        assert!(items[1].overview.urls.is_empty());
        // Other exports are not marked.
        let chrome = parse_csv("name,url,username,password\nA,https://a.example,me,pw\n".as_bytes(), "x").unwrap();
        assert_eq!(chrome.vaults[0].items[0].overview.imported_from, "");
    }

    #[test]
    fn other_managers() {
        // RoboForm.
        let robo = parse_csv("Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2\nBank,https://bank.example,,me,pw,,/Money,\n".as_bytes(), "x").unwrap();
        assert_eq!(robo.vaults[0].items[0].details.password(), Some("pw"));
        // Dashlane.
        let dash = parse_csv(
            "username,username2,username3,title,password,note,url,category,otpSecret\nme,,,Mail,pw,,https://mail.example,Email,JBSWY3DPEHPK3PXP\n".as_bytes(),
            "x",
        )
        .unwrap();
        let mail = &dash.vaults[0].items[0];
        assert!(mail.details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert_eq!(mail.overview.tags, vec!["Email"]);
        // KeePassXC.
        let kp = parse_csv("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\"Root/Email\",\"Mail\",\"me\",\"pw\",\"\",\"\",\"\"\n".as_bytes(), "x").unwrap();
        assert_eq!(kp.vaults[0].items[0].overview.tags, vec!["Email"]);
        // Safari and iCloud.
        let safari = parse_csv("Title,URL,Username,Password,Notes,OTPAuth\nShop,https://shop.example,me,pw,,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n".as_bytes(), "x").unwrap();
        assert!(safari.vaults[0].items[0].details.fields.iter().any(|f| f.kind == FieldKind::Totp));
    }

    #[test]
    fn keeper_export() {
        let csv = "Work\\Team,VPN,me,pw,https://vpn.example,note,,TFC:Keeper,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,PIN,1234\n";
        let result = parse_keeper_csv(csv.as_bytes(), "Keeper").unwrap();
        let item = &result.vaults[0].items[0];
        assert_eq!(item.overview.tags, vec!["Work", "Team"]);
        assert_eq!(item.details.password(), Some("pw"));
        assert!(item.details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert!(item.details.fields.iter().any(|f| f.label == "PIN" && f.kind == FieldKind::Concealed));
        assert!(parse_keeper_csv("a,b\n".as_bytes(), "x").is_err());
    }

    #[test]
    fn rejects_unknown_layout() {
        assert!(parse_csv("a,b,c\n1,2,3\n".as_bytes(), "x").is_err());
    }
}
