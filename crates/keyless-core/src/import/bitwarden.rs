//! Bitwarden's JSON export, plain or protected by a password ("encrypted
//! export" with "password protected"). An "account restricted" export is
//! encrypted with the Bitwarden account's own key and cannot be read
//! outside Bitwarden.
//!
//! A password-protected file holds `data`, an encrypted plain export: the
//! password and the file's `salt` give a key (PBKDF2-SHA256, or Argon2id
//! over the salt's SHA-256), which HKDF-Expand turns into an AES-256-CBC key
//! and an HMAC-SHA256 key ("enc" and "mac").

use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{ImportResult, ImportWarning, ImportedItem, ImportedVault, decrypt};
use crate::{
    Error, Result,
    item::{
        Address, Category, Field, FieldExtra, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, PasswordHistoryEntry, UrlMatch,
        new_field_id,
    },
};

/// Whether `json` looks like a Bitwarden export.
pub fn detect(json: &Value) -> bool {
    json.get("encrypted").is_some() && (json.get("items").is_some() || json.get("data").is_some() || json.get("passwordProtected").is_some())
}

pub fn parse_bitwarden_json(json: &Value, password: Option<&str>, vault_name: &str) -> Result<ImportResult> {
    if json.get("encrypted").and_then(Value::as_bool) == Some(true) {
        if json.get("passwordProtected").and_then(Value::as_bool) != Some(true) {
            return Err(Error::Import(
                "this Bitwarden export is encrypted with the Bitwarden account's key; export it again as \"password protected\" or unencrypted".into(),
            ));
        }
        let password = password.filter(|p| !p.is_empty()).ok_or(Error::PasswordRequired)?;
        let plain = open_protected(json, password)?;
        let inner: Value = serde_json::from_slice(&plain).map_err(|e| Error::Import(format!("invalid Bitwarden export: {e}")))?;
        return convert(&inner, vault_name);
    }
    convert(json, vault_name)
}

/// The keys of a password-protected export.
struct Keys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

fn keys(json: &Value, password: &str) -> Result<Keys> {
    let salt = json.get("salt").and_then(Value::as_str).ok_or_else(|| Error::Import("Bitwarden export without salt".into()))?;
    let iterations = json.get("kdfIterations").and_then(Value::as_u64).unwrap_or(600_000);
    let master: Zeroizing<[u8; 32]> = match json.get("kdfType").and_then(Value::as_u64).unwrap_or(0) {
        0 => {
            if !(5_000..=10_000_000).contains(&iterations) {
                return Err(Error::UnsafeKdfParams);
            }
            decrypt::pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), iterations as u32)
        }
        1 => {
            let memory_mib = json.get("kdfMemory").and_then(Value::as_u64).unwrap_or(64);
            let parallelism = json.get("kdfParallelism").and_then(Value::as_u64).unwrap_or(4);
            if !(1..=10).contains(&iterations) || !(15..=1024).contains(&memory_mib) || !(1..=16).contains(&parallelism) {
                return Err(Error::UnsafeKdfParams);
            }
            let params = argon2::Params::new((memory_mib * 1024) as u32, iterations as u32, parallelism as u32, Some(32)).map_err(|_| Error::Kdf)?;
            let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let salt_hash = Sha256::digest(salt.as_bytes());
            let mut out = Zeroizing::new([0u8; 32]);
            argon.hash_password_into(password.as_bytes(), &salt_hash, out.as_mut()).map_err(|_| Error::Kdf)?;
            out
        }
        _ => return Err(Error::Import("unknown Bitwarden key derivation".into())),
    };
    let hk = Hkdf::<Sha256>::from_prk(master.as_ref()).map_err(|_| Error::Kdf)?;
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    hk.expand(b"enc", enc.as_mut()).map_err(|_| Error::Kdf)?;
    hk.expand(b"mac", mac.as_mut()).map_err(|_| Error::Kdf)?;
    Ok(Keys { enc, mac })
}

/// Opens a Bitwarden "EncString" of type 2 ("2.iv|data|mac", base64): the
/// HMAC first, then AES-CBC.
fn open_enc_string(keys: &Keys, text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let body = text.strip_prefix("2.").ok_or(Error::InvalidEnvelope)?;
    let parts: Vec<&str> = body.split('|').collect();
    let [iv, data, mac] = parts.as_slice() else { return Err(Error::InvalidEnvelope) };
    let decode = |s: &str| STANDARD.decode(s).map_err(|_| Error::InvalidEnvelope);
    let (iv, data, mac) = (decode(iv)?, decode(data)?, decode(mac)?);
    let mut check = Hmac::<Sha256>::new_from_slice(keys.mac.as_ref()).map_err(|_| Error::InvalidKey)?;
    check.update(&iv);
    check.update(&data);
    check.verify_slice(&mac).map_err(|_| Error::Decryption)?;
    decrypt::aes256_cbc_decrypt(keys.enc.as_ref(), &iv, &data)
}

fn open_protected(json: &Value, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let keys = keys(json, password)?;
    // A value the file holds only to tell a wrong password at once.
    if let Some(check) = json.get("encKeyValidation_DO_NOT_EDIT").and_then(Value::as_str) {
        open_enc_string(&keys, check)?;
    }
    let data = json.get("data").and_then(Value::as_str).ok_or_else(|| Error::Import("Bitwarden export without data".into()))?;
    open_enc_string(&keys, data)
}

fn text(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").trim().to_string()
}

fn field(label: &str, kind: FieldKind, value: String, purpose: Option<FieldPurpose>) -> Field {
    Field { id: new_field_id(), label: label.into(), kind, value, purpose, extra: Default::default() }
}

fn convert(json: &Value, vault_name: &str) -> Result<ImportResult> {
    let folders: std::collections::HashMap<&str, &str> = json
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| Some((f.get("id")?.as_str()?, f.get("name")?.as_str()?)))
        .collect();
    let mut items = Vec::new();
    let mut skipped = 0;
    for raw in json.get("items").and_then(Value::as_array).into_iter().flatten() {
        if raw.get("deletedDate").is_some_and(|d| !d.is_null()) {
            continue;
        }
        match convert_item(raw, &folders) {
            Some(item) => items.push(item),
            None => skipped += 1,
        }
    }
    let mut warnings = Vec::new();
    if skipped > 0 {
        warnings.push(ImportWarning::new("item_skipped", skipped));
    }
    Ok(ImportResult { vaults: vec![ImportedVault { name: vault_name.to_string(), items }], warnings }.link())
}

fn convert_item(raw: &Value, folders: &std::collections::HashMap<&str, &str>) -> Option<ImportedItem> {
    let mut details = ItemDetails::default();
    details.notes = raw.get("notes").and_then(Value::as_str).unwrap_or("").to_string();
    let mut urls = Vec::new();
    let category = match raw.get("type").and_then(Value::as_u64)? {
        1 => {
            let login = raw.get("login").cloned().unwrap_or(Value::Null);
            let username = text(login.get("username"));
            if !username.is_empty() {
                details.fields.push(field("username", FieldKind::Text, username, Some(FieldPurpose::Username)));
            }
            if let Some(password) = login.get("password").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                details.fields.push(field("password", FieldKind::Concealed, password.to_string(), Some(FieldPurpose::Password)));
            }
            let totp = text(login.get("totp"));
            if !totp.is_empty() {
                details.fields.push(field("one-time password", FieldKind::Totp, totp, None));
            }
            for uri in login.get("uris").and_then(Value::as_array).into_iter().flatten() {
                let href = text(uri.get("uri"));
                if href.is_empty() {
                    continue;
                }
                // Bitwarden's match detection: 0 base domain, 1 host, 2 starts
                // with, 3 exact, 4 regular expression, 5 never.
                let fill = match uri.get("match").and_then(Value::as_u64) {
                    Some(1) | Some(2) | Some(3) => UrlMatch::Host,
                    Some(5) => UrlMatch::Never,
                    _ => UrlMatch::Domain,
                };
                urls.push(ItemUrl { href, fill, ..Default::default() });
            }
            Category::Login
        }
        2 => Category::SecureNote,
        3 => {
            let card = raw.get("card").cloned().unwrap_or(Value::Null);
            let holder = text(card.get("cardholderName"));
            if !holder.is_empty() {
                details.fields.push(field("cardholder name", FieldKind::Text, holder, None));
            }
            let number = text(card.get("number"));
            if !number.is_empty() {
                details.fields.push(field("number", FieldKind::CardNumber, number, None));
            }
            let (month, year) = (text(card.get("expMonth")), text(card.get("expYear")));
            if !month.is_empty() && !year.is_empty() {
                details.fields.push(field("expiry date", FieldKind::MonthYear, format!("{:0>2}/{year}", month), None));
            }
            let code = text(card.get("code"));
            if !code.is_empty() {
                details.fields.push(field("verification number", FieldKind::Concealed, code, None));
            }
            let brand = text(card.get("brand"));
            if !brand.is_empty() {
                details.fields.push(field("type", FieldKind::Text, brand, None));
            }
            Category::CreditCard
        }
        4 => {
            let id = raw.get("identity").cloned().unwrap_or(Value::Null);
            let name = ["title", "firstName", "middleName", "lastName"].iter().map(|k| text(id.get(*k))).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
            for (label, key, kind) in [
                ("first name", "firstName", FieldKind::Text),
                ("last name", "lastName", FieldKind::Text),
                ("email", "email", FieldKind::Email),
                ("phone", "phone", FieldKind::Phone),
                ("username", "username", FieldKind::Text),
                ("company", "company", FieldKind::Text),
                ("document number", "ssn", FieldKind::Concealed),
                ("passport number", "passportNumber", FieldKind::Concealed),
                ("license number", "licenseNumber", FieldKind::Concealed),
            ] {
                let value = text(id.get(key));
                if !value.is_empty() {
                    details.fields.push(field(label, kind, value, None));
                }
            }
            let street = ["address1", "address2", "address3"].iter().map(|k| text(id.get(*k))).filter(|s| !s.is_empty()).collect::<Vec<_>>();
            let address = Address {
                street: street.first().cloned().unwrap_or_default(),
                line2: street.get(1..).map(|rest| rest.join(", ")).unwrap_or_default(),
                city: text(id.get("city")),
                state: text(id.get("state")),
                zip: text(id.get("postalCode")),
                country: text(id.get("country")),
                ..Default::default()
            };
            let formatted = address.formatted();
            if !formatted.is_empty() {
                details.fields.push(Field {
                    id: new_field_id(),
                    label: "address".into(),
                    kind: FieldKind::Address,
                    value: formatted,
                    purpose: None,
                    extra: FieldExtra { address: Some(address), ..Default::default() },
                });
            }
            if details.fields.is_empty() && !name.is_empty() {
                details.fields.push(field("full name", FieldKind::Text, name, None));
            }
            Category::Identity
        }
        5 => {
            let key = raw.get("sshKey").cloned().unwrap_or(Value::Null);
            for (label, value_key, kind) in
                [("private key", "privateKey", FieldKind::Concealed), ("public key", "publicKey", FieldKind::Multiline), ("fingerprint", "keyFingerprint", FieldKind::Text)]
            {
                let value = text(key.get(value_key));
                if !value.is_empty() {
                    details.fields.push(field(label, kind, value, None));
                }
            }
            Category::SshKey
        }
        _ => return None,
    };
    // Custom fields: 0 text, 1 hidden, 2 a checkbox, 3 linked to another field.
    for custom in raw.get("fields").and_then(Value::as_array).into_iter().flatten() {
        let (name, value) = (text(custom.get("name")), custom.get("value").and_then(Value::as_str).unwrap_or("").to_string());
        if name.is_empty() && value.is_empty() {
            continue;
        }
        let kind = match custom.get("type").and_then(Value::as_u64) {
            Some(1) => FieldKind::Concealed,
            Some(3) => continue,
            _ => FieldKind::Text,
        };
        details.fields.push(field(if name.is_empty() { "field" } else { &name }, kind, value, None));
    }
    for entry in raw.get("passwordHistory").and_then(Value::as_array).into_iter().flatten() {
        if let Some(value) = entry.get("password").and_then(Value::as_str) {
            details.password_history.push(PasswordHistoryEntry { value: value.into(), changed_at: date(entry.get("lastUsedDate")) });
        }
    }
    details.sort_main_fields();
    let title = text(raw.get("name"));
    let folder = raw.get("folderId").and_then(Value::as_str).and_then(|id| folders.get(id)).map(|name| name.to_string());
    let overview = ItemOverview {
        title: if title.is_empty() { "Untitled".into() } else { title },
        subtitle: details.username().unwrap_or("").to_string(),
        category,
        urls,
        tags: folder.into_iter().collect(),
        favorite: raw.get("favorite").and_then(Value::as_bool).unwrap_or(false),
        created_at: date(raw.get("creationDate")),
        updated_at: date(raw.get("revisionDate")),
        ..Default::default()
    };
    Some(ImportedItem::new(text(raw.get("id")), overview, details, Vec::new()))
}

/// An ISO 8601 date ("2024-05-01T12:00:00.000Z") as Unix seconds; 0 when
/// it is not one.
pub(crate) fn date(value: Option<&Value>) -> i64 {
    let Some(text) = value.and_then(Value::as_str) else { return 0 };
    let num = |range: std::ops::Range<usize>| text.get(range).and_then(|s| s.parse::<i64>().ok());
    let (Some(y), Some(m), Some(d)) = (num(0..4), num(5..7), num(8..10)) else { return 0 };
    let (h, min, s) = (num(11..13).unwrap_or(0), num(14..16).unwrap_or(0), num(17..19).unwrap_or(0));
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + h * 3_600 + min * 60 + s
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

    const PLAIN: &str = r#"{"encrypted": false,
      "folders": [{"id": "f1", "name": "Work"}],
      "items": [
        {"id": "a", "type": 1, "name": "Mail", "favorite": true, "folderId": "f1", "notes": null,
         "login": {"username": "me", "password": "pw", "totp": "JBSWY3DPEHPK3PXP", "uris": [{"uri": "https://mail.example", "match": null}]},
         "fields": [{"name": "PIN", "value": "1234", "type": 1}],
         "passwordHistory": [{"lastUsedDate": "2024-05-01T12:00:00.000Z", "password": "old"}],
         "creationDate": "2024-01-01T00:00:00.000Z", "revisionDate": "2024-05-01T12:00:00.000Z"},
        {"id": "b", "type": 3, "name": "Visa", "card": {"cardholderName": "Ana", "number": "4111111111111111", "expMonth": "7", "expYear": "2029", "code": "123", "brand": "Visa"}},
        {"id": "c", "type": 4, "name": "Me", "identity": {"firstName": "Ana", "address1": "Rua A, 10", "city": "Recife", "postalCode": "50000-000", "country": "BR"}},
        {"id": "d", "type": 2, "name": "Recipe", "notes": "secret sauce", "deletedDate": "2024-01-01T00:00:00Z"}
      ]}"#;

    #[test]
    fn reads_a_plain_export() {
        let json: Value = serde_json::from_str(PLAIN).unwrap();
        assert!(detect(&json));
        let result = parse_bitwarden_json(&json, None, "Bitwarden").unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(items.len(), 3);
        let mail = &items[0];
        assert!(mail.overview.favorite);
        assert_eq!(mail.overview.tags, vec!["Work"]);
        assert_eq!(mail.details.password(), Some("pw"));
        assert!(mail.details.fields.iter().any(|f| f.kind == FieldKind::Totp));
        assert!(mail.details.fields.iter().any(|f| f.label == "PIN" && f.kind == FieldKind::Concealed));
        assert_eq!(mail.details.password_history[0].changed_at, 1_714_564_800);
        assert_eq!(items[1].overview.category, Category::CreditCard);
        assert!(items[1].details.fields.iter().any(|f| f.kind == FieldKind::MonthYear && f.value == "07/2029"));
        let address = items[2].details.fields.iter().find(|f| f.kind == FieldKind::Address).unwrap();
        assert_eq!(address.extra.address.as_ref().unwrap().city, "Recife");
    }

    /// Seals `data` as Bitwarden does: "2.iv|data|mac".
    fn seal(keys: &Keys, data: &[u8]) -> String {
        let iv = [5u8; 16];
        let sealed = cbc::Encryptor::<aes::Aes256>::new_from_slices(keys.enc.as_ref(), &iv).unwrap().encrypt_padded_vec::<Pkcs7>(data);
        let mut mac = Hmac::<Sha256>::new_from_slice(keys.mac.as_ref()).unwrap();
        mac.update(&iv);
        mac.update(&sealed);
        format!("2.{}|{}|{}", STANDARD.encode(iv), STANDARD.encode(&sealed), STANDARD.encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn opens_a_password_protected_export() {
        for kdf in [serde_json::json!({"kdfType": 0, "kdfIterations": 5000}), serde_json::json!({"kdfType": 1, "kdfIterations": 3, "kdfMemory": 16, "kdfParallelism": 1})] {
            let mut file = serde_json::json!({"encrypted": true, "passwordProtected": true, "salt": "c2FsdHNhbHRzYWx0c2FsdA=="});
            file.as_object_mut().unwrap().extend(kdf.as_object().unwrap().clone());
            let keys = keys(&file, "correct horse").unwrap();
            file["encKeyValidation_DO_NOT_EDIT"] = seal(&keys, b"a2f7e0a8-validation").into();
            file["data"] = seal(&keys, PLAIN.as_bytes()).into();
            assert!(matches!(parse_bitwarden_json(&file, None, "x"), Err(Error::PasswordRequired)));
            assert!(matches!(parse_bitwarden_json(&file, Some("wrong"), "x"), Err(Error::Decryption)));
            let result = parse_bitwarden_json(&file, Some("correct horse"), "x").unwrap();
            assert_eq!(result.vaults[0].items.len(), 3);
        }
        // Encrypted with the Bitwarden account's key: explained, not tried.
        let account = serde_json::json!({"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.x|y|z", "data": "2.x|y|z"});
        assert!(matches!(parse_bitwarden_json(&account, Some("pw"), "x"), Err(Error::Import(_))));
    }
}
