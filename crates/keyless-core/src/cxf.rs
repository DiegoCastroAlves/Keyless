//! The Credential Exchange Format (CXF, FIDO Alliance): the JSON that
//! password managers write and read to move credentials between one another.
//! A document holds accounts; an account, items and collections; an item,
//! its websites (`scope`) and its credentials, each of a known `type`
//! ("basic-auth", "totp", "passkey", "credit-card", "address", "note",
//! "wifi", "api-key", "custom-fields"…) whose values say how to show them
//! (`fieldType`).
//!
//! Keyless reads what it can keep (passkeys too) and turns the rest into
//! fields; it writes each item's login, codes, card, address, notes and other
//! fields. Passkeys stay out of what it writes, as from every unencrypted
//! export (see `export`); attached files and password history have no place
//! in the JSON.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};

use crate::{
    Error, Result,
    backup::BackupData,
    import::{ImportResult, ImportWarning, ImportedItem, ImportedVault},
    item::{
        Address, Category, Field, FieldExtra, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, Section, new_field_id,
    },
    passkey::Passkey,
};

/// Whether `json` looks like a CXF document.
pub fn detect(json: &Value) -> bool {
    json.get("version").and_then(|v| v.get("major")).is_some() && json.get("accounts").is_some_and(Value::is_array)
}

// ----- reading ----------------------------------------------------------------------

/// A value as CXF writes them: `{"fieldType": …, "value": …}` (or, in
/// places, the value itself).
fn value(raw: Option<&Value>) -> String {
    let inner = raw.map(|v| v.get("value").unwrap_or(v));
    match inner {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn field(label: &str, kind: FieldKind, value: String, purpose: Option<FieldPurpose>) -> Field {
    Field { id: new_field_id(), label: label.into(), kind, value, purpose, extra: Default::default() }
}

/// The field kind for a CXF `fieldType`.
fn kind_of(raw: &Value) -> FieldKind {
    match raw.get("fieldType").and_then(Value::as_str).unwrap_or("string") {
        "concealed-string" => FieldKind::Concealed,
        "email" => FieldKind::Email,
        "date" => FieldKind::Date,
        "year-month" => FieldKind::MonthYear,
        _ => FieldKind::Text,
    }
}

/// "2029-07" as Keyless's month and year ("07/2029").
fn month_year(text: &str) -> String {
    match text.split_once('-') {
        Some((year, month)) if year.len() == 4 => format!("{month:0>2}/{year}"),
        _ => text.to_string(),
    }
}

/// A one-time password credential as an `otpauth://` address.
fn otpauth(raw: &Value) -> String {
    let secret = value(raw.get("secret")).replace(' ', "").to_uppercase();
    if secret.is_empty() {
        return String::new();
    }
    let algorithm = value(raw.get("algorithm")).to_uppercase();
    let issuer = value(raw.get("issuer"));
    let account = value(raw.get("username"));
    let label = [issuer.as_str(), account.as_str()].iter().filter(|s| !s.is_empty()).map(|s| encode(s)).collect::<Vec<_>>().join(":");
    let mut uri = format!("otpauth://totp/{}?secret={secret}", if label.is_empty() { "Keyless".to_string() } else { label });
    if let Some(period) = raw.get("period").and_then(Value::as_u64) {
        uri.push_str(&format!("&period={period}"));
    }
    if let Some(digits) = raw.get("digits").and_then(Value::as_u64) {
        uri.push_str(&format!("&digits={digits}"));
    }
    if matches!(algorithm.as_str(), "SHA1" | "SHA256" | "SHA512") {
        uri.push_str(&format!("&algorithm={algorithm}"));
    }
    if !issuer.is_empty() {
        uri.push_str(&format!("&issuer={}", encode(&issuer)));
    }
    uri
}

/// Percent-encodes everything but unreserved characters.
fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads one credential into the item; returns the kind of item it says
/// the item is.
fn read_credential(raw: &Value, details: &mut ItemDetails) -> Option<Category> {
    let kind = raw.get("type").and_then(Value::as_str).unwrap_or("");
    match kind {
        "basic-auth" => {
            let username = value(raw.get("username"));
            if !username.is_empty() && details.username().is_none() {
                details.fields.push(field("username", FieldKind::Text, username, Some(FieldPurpose::Username)));
            }
            let password = raw.get("password").and_then(|p| p.get("value").unwrap_or(p).as_str()).unwrap_or("").to_string();
            if !password.is_empty() && details.password().is_none() {
                details.fields.push(field("password", FieldKind::Concealed, password, Some(FieldPurpose::Password)));
            }
            Some(Category::Login)
        }
        "totp" => {
            let uri = otpauth(raw);
            if !uri.is_empty() {
                details.fields.push(field("one-time password", FieldKind::Totp, uri, None));
            }
            None
        }
        "note" => {
            let text = value(raw.get("content"));
            if !text.is_empty() {
                if !details.notes.is_empty() {
                    details.notes.push_str("\n\n");
                }
                details.notes.push_str(&text);
            }
            Some(Category::SecureNote)
        }
        "passkey" => {
            let passkey = Passkey {
                credential_id: value(raw.get("credentialId")),
                rp_id: value(raw.get("rpId")),
                rp_name: String::new(),
                user_handle: value(raw.get("userHandle")),
                user_name: value(raw.get("username")),
                user_display_name: value(raw.get("userDisplayName")),
                key: value(raw.get("key")),
                created_at: 0,
            };
            if !passkey.credential_id.is_empty() && !passkey.rp_id.is_empty() && !passkey.key.is_empty() {
                details.passkeys.push(passkey);
            }
            Some(Category::Login)
        }
        "credit-card" => {
            for (label, key, kind) in [
                ("cardholder name", "fullName", FieldKind::Text),
                ("number", "number", FieldKind::CardNumber),
                ("verification number", "verificationNumber", FieldKind::Concealed),
                ("PIN", "pin", FieldKind::Pin),
                ("type", "cardType", FieldKind::Text),
            ] {
                let text = value(raw.get(key));
                if !text.is_empty() {
                    details.fields.push(field(label, kind, text, None));
                }
            }
            let expiry = value(raw.get("expiryDate"));
            if !expiry.is_empty() {
                details.fields.push(field("expiry date", FieldKind::MonthYear, month_year(&expiry), None));
            }
            Some(Category::CreditCard)
        }
        "address" => {
            let address = Address {
                street: value(raw.get("streetAddress")),
                city: value(raw.get("city")),
                state: value(raw.get("territory")),
                zip: value(raw.get("postalCode")),
                country: value(raw.get("country")),
                ..Default::default()
            };
            let text = address.formatted();
            if !text.is_empty() {
                details.fields.push(Field {
                    id: new_field_id(),
                    label: "address".into(),
                    kind: FieldKind::Address,
                    value: text,
                    purpose: None,
                    extra: FieldExtra { address: Some(address), ..Default::default() },
                });
            }
            let phone = value(raw.get("tel"));
            if !phone.is_empty() {
                details.fields.push(field("phone", FieldKind::Phone, phone, None));
            }
            Some(Category::Identity)
        }
        "wifi" => {
            for (label, key, kind) in [
                ("network name", "ssid", FieldKind::Text),
                ("wireless password", "passphrase", FieldKind::Concealed),
                ("security", "networkSecurityType", FieldKind::Text),
            ] {
                let text = value(raw.get(key));
                if !text.is_empty() {
                    details.fields.push(field(label, kind, text, None));
                }
            }
            Some(Category::WirelessRouter)
        }
        "api-key" => {
            let key = value(raw.get("key"));
            if !key.is_empty() {
                details.fields.push(field("credential", FieldKind::Concealed, key, Some(FieldPurpose::Password)));
            }
            for (label, name, kind) in [("username", "username", FieldKind::Text), ("type", "keyType", FieldKind::Text), ("URL", "url", FieldKind::Url)] {
                let text = value(raw.get(name));
                if !text.is_empty() {
                    details.fields.push(field(label, kind, text, None));
                }
            }
            Some(Category::ApiCredential)
        }
        "custom-fields" => {
            let fields: Vec<Field> = raw
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|f| {
                    let text = value(Some(f));
                    (!text.is_empty()).then(|| field(&value(f.get("label")), kind_of(f), text, None))
                })
                .collect();
            let title = value(raw.get("label"));
            if title.is_empty() {
                details.fields.extend(fields);
            } else if !fields.is_empty() {
                details.sections.push(Section { id: new_field_id(), title, fields });
            }
            None
        }
        // Anything else (newer kinds): its plain values, as fields.
        _ => {
            let mut fields = Vec::new();
            if let Some(object) = raw.as_object() {
                for (name, inner) in object {
                    if name == "type" || name == "id" {
                        continue;
                    }
                    let text = value(Some(inner));
                    if !text.is_empty() {
                        fields.push(field(name, kind_of(inner), text, None));
                    }
                }
            }
            if !fields.is_empty() {
                details.sections.push(Section { id: new_field_id(), title: kind.to_string(), fields });
            }
            None
        }
    }
}

pub fn parse_cxf(json: &Value) -> Result<ImportResult> {
    let major = json.get("version").and_then(|v| v.get("major")).and_then(Value::as_u64).unwrap_or(0);
    if major != 1 {
        return Err(Error::Import(format!("unsupported Credential Exchange Format version {major}")));
    }
    let mut vaults = Vec::new();
    let mut skipped = 0;
    for account in json.get("accounts").and_then(Value::as_array).into_iter().flatten() {
        // Collections: tags for the items in them.
        let mut tags: HashMap<String, Vec<String>> = HashMap::new();
        fn collect(collection: &Value, tags: &mut HashMap<String, Vec<String>>) {
            let title = value(collection.get("title"));
            for entry in collection.get("items").and_then(Value::as_array).into_iter().flatten() {
                let id = value(entry.get("item"));
                if !title.is_empty() && !id.is_empty() {
                    tags.entry(id).or_default().push(title.clone());
                }
            }
            for sub in collection.get("subCollections").and_then(Value::as_array).into_iter().flatten() {
                collect(sub, tags);
            }
        }
        for collection in account.get("collections").and_then(Value::as_array).into_iter().flatten() {
            collect(collection, &mut tags);
        }
        let mut items = Vec::new();
        for raw in account.get("items").and_then(Value::as_array).into_iter().flatten() {
            let mut details = ItemDetails::default();
            let mut kinds = Vec::new();
            for credential in raw.get("credentials").and_then(Value::as_array).into_iter().flatten() {
                kinds.extend(read_credential(credential, &mut details));
            }
            let title = value(raw.get("title"));
            let urls: Vec<ItemUrl> = raw
                .get("scope")
                .and_then(|s| s.get("urls"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|u| !u.trim().is_empty())
                .map(|u| ItemUrl { href: u.trim().into(), ..Default::default() })
                .collect();
            if title.is_empty() && urls.is_empty() && details.fields.is_empty() && details.notes.is_empty() && details.passkeys.is_empty() {
                skipped += 1;
                continue;
            }
            // The item's kind: the first credential that tells one, a note
            // only when there is nothing else.
            let category = kinds.iter().copied().find(|k| *k != Category::SecureNote).or(kinds.first().copied()).unwrap_or(Category::Other);
            details.sort_main_fields();
            let id = value(raw.get("id"));
            let mut item_tags: Vec<String> = raw.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
            item_tags.extend(tags.get(&id).cloned().unwrap_or_default());
            item_tags.dedup();
            let overview = ItemOverview {
                title: if title.is_empty() { "Untitled".into() } else { title },
                subtitle: details.username().unwrap_or("").to_string(),
                category,
                urls,
                tags: item_tags,
                favorite: raw.get("favorite").and_then(Value::as_bool).unwrap_or(false),
                created_at: raw.get("creationAt").and_then(Value::as_i64).unwrap_or(0),
                updated_at: raw.get("modifiedAt").and_then(Value::as_i64).unwrap_or(0),
                ..Default::default()
            };
            items.push(ImportedItem::new(id, overview, details, Vec::new()));
        }
        let name = [value(account.get("username")), value(account.get("email"))].into_iter().find(|n| !n.is_empty()).unwrap_or_else(|| "Imported".into());
        vaults.push(ImportedVault { name, items });
    }
    let mut warnings = Vec::new();
    if skipped > 0 {
        warnings.push(ImportWarning::new("item_skipped", skipped));
    }
    Ok(ImportResult { vaults, warnings }.link())
}

// ----- writing ----------------------------------------------------------------------

fn editable(field_type: &str, value: &str) -> Value {
    json!({ "fieldType": field_type, "value": value })
}

/// The parts of an `otpauth://` address CXF keeps apart.
fn totp_credential(uri: &str) -> Value {
    let uri = uri.trim();
    let Some(rest) = uri.strip_prefix("otpauth://totp/") else {
        // A bare secret.
        return json!({ "type": "totp", "secret": uri.replace(' ', "").to_uppercase(), "period": 30, "digits": 6, "algorithm": "sha1" });
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let params: HashMap<String, String> = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_ascii_lowercase(), decode(v)))
        .collect();
    let label = decode(label);
    let (label_issuer, account) = label.split_once(':').map(|(i, a)| (i.to_string(), a.trim().to_string())).unwrap_or((String::new(), label));
    let mut credential = Map::new();
    credential.insert("type".into(), "totp".into());
    credential.insert("secret".into(), params.get("secret").cloned().unwrap_or_default().to_uppercase().into());
    credential.insert("period".into(), params.get("period").and_then(|p| p.parse::<u64>().ok()).unwrap_or(30).into());
    credential.insert("digits".into(), params.get("digits").and_then(|d| d.parse::<u64>().ok()).unwrap_or(6).into());
    credential.insert("algorithm".into(), params.get("algorithm").map(|a| a.to_ascii_lowercase()).unwrap_or_else(|| "sha1".into()).into());
    let issuer = params.get("issuer").cloned().unwrap_or(label_issuer);
    if !issuer.is_empty() {
        credential.insert("issuer".into(), issuer.into());
    }
    if !account.is_empty() {
        credential.insert("username".into(), account.into());
    }
    Value::Object(credential)
}

/// "07/2029" (or "2029-07") as CXF's "2029-07".
fn year_month(text: &str) -> String {
    let digits: Vec<&str> = text.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).collect();
    match digits.as_slice() {
        [month, year] if month.len() <= 2 && year.len() == 4 => format!("{year}-{month:0>2}"),
        [year, month] if year.len() == 4 => format!("{year}-{month:0>2}"),
        _ => text.to_string(),
    }
}

fn label_is(field: &Field, words: &[&str]) -> bool {
    let label = field.label.to_lowercase();
    words.iter().any(|w| label.contains(w))
}

fn field_type(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Concealed | FieldKind::Pin | FieldKind::CardNumber | FieldKind::SecurityQuestion => "concealed-string",
        FieldKind::Email => "email",
        FieldKind::Date => "date",
        _ => "string",
    }
}

/// One item's credentials.
fn credentials(category: Category, details: &ItemDetails) -> Vec<Value> {
    let mut out = Vec::new();
    let mut used: Vec<&str> = Vec::new();
    let username = details.field_by_purpose(FieldPurpose::Username);
    let password = details.field_by_purpose(FieldPurpose::Password);
    if category == Category::ApiCredential {
        if let Some(key) = password {
            used.push(&key.id);
            let mut credential = json!({ "type": "api-key", "key": editable("concealed-string", &key.value) });
            if let Some(user) = username {
                used.push(&user.id);
                credential["username"] = editable("string", &user.value);
            }
            out.push(credential);
        }
    } else if username.is_some() || password.is_some() {
        let mut credential = json!({ "type": "basic-auth" });
        if let Some(user) = username {
            used.push(&user.id);
            credential["username"] = editable("string", &user.value);
        }
        if let Some(pass) = password {
            used.push(&pass.id);
            credential["password"] = editable("concealed-string", &pass.value);
        }
        out.push(credential);
    }
    for field in details.all_fields().filter(|f| f.kind == FieldKind::Totp && !f.value.trim().is_empty()) {
        used.push(&field.id);
        out.push(totp_credential(&field.value));
    }
    if category == Category::CreditCard {
        let mut card = Map::new();
        card.insert("type".into(), "credit-card".into());
        for field in details.all_fields().filter(|f| !f.value.trim().is_empty()) {
            let key = match field.kind {
                FieldKind::CardNumber => "number",
                FieldKind::MonthYear if label_is(field, &["expir", "valid", "venc"]) => "expiryDate",
                _ if label_is(field, &["holder", "titular", "nombre", "name on"]) => "fullName",
                _ if label_is(field, &["verification", "cvv", "cvc", "security", "segurança", "seguridad"]) => "verificationNumber",
                FieldKind::Pin => "pin",
                _ if label_is(field, &["type", "tipo", "brand", "bandeira"]) => "cardType",
                _ => continue,
            };
            if card.contains_key(key) {
                continue;
            }
            used.push(&field.id);
            let value = if key == "expiryDate" { editable("year-month", &year_month(&field.value)) } else { editable(field_type(field.kind), &field.value) };
            card.insert(key.into(), value);
        }
        if card.len() > 1 {
            out.push(Value::Object(card));
        }
    }
    if category == Category::WirelessRouter {
        let mut wifi = Map::new();
        wifi.insert("type".into(), "wifi".into());
        for field in details.all_fields().filter(|f| !f.value.trim().is_empty()) {
            let key = if label_is(field, &["network name", "ssid", "nome da rede", "nombre de la red"]) {
                "ssid"
            } else if field.kind == FieldKind::Concealed && label_is(field, &["wireless", "wi-fi", "wifi", "red"]) {
                "passphrase"
            } else {
                continue;
            };
            if !wifi.contains_key(key) {
                used.push(&field.id);
                wifi.insert(key.into(), editable(if key == "passphrase" { "concealed-string" } else { "string" }, &field.value));
            }
        }
        if wifi.len() > 1 {
            out.push(Value::Object(wifi));
        }
    }
    for field in details.all_fields().filter(|f| f.kind == FieldKind::Address) {
        let Some(address) = &field.extra.address else { continue };
        used.push(&field.id);
        out.push(json!({
            "type": "address",
            "streetAddress": editable("string", &[address.street.as_str(), address.line2.as_str()].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join("\n")),
            "city": editable("string", &address.city),
            "territory": editable("subdivision-code", &address.state),
            "postalCode": editable("string", &address.zip),
            "country": editable("country-code", &address.country),
        }));
    }
    if !details.notes.trim().is_empty() {
        out.push(json!({ "type": "note", "content": editable("string", &details.notes) }));
    }
    // What is left, as custom fields: the main ones, then a group per section.
    let rest = |fields: &[Field]| -> Vec<Value> {
        fields
            .iter()
            .filter(|f| !used.contains(&f.id.as_str()) && !f.value.trim().is_empty() && f.kind != FieldKind::Reference && f.kind != FieldKind::File)
            .map(|f| json!({ "id": f.id, "label": f.label, "fieldType": field_type(f.kind), "value": f.value }))
            .collect()
    };
    let main = rest(&details.fields);
    if !main.is_empty() {
        out.push(json!({ "type": "custom-fields", "fields": main }));
    }
    for section in &details.sections {
        let fields = rest(&section.fields);
        if !fields.is_empty() {
            out.push(json!({ "type": "custom-fields", "id": section.id, "label": section.title, "fields": fields }));
        }
    }
    out
}

/// The export as a CXF document: an account for the user, the vaults as
/// collections.
pub fn to_cxf(data: &BackupData, email: &str) -> Result<Vec<u8>> {
    let id = |text: &str| URL_SAFE_NO_PAD.encode(text.as_bytes());
    let mut items = Vec::new();
    let mut collections = Vec::new();
    for vault in &data.vaults {
        let mut members = Vec::new();
        for item in &vault.items {
            // Older backups have no ids: one from the position.
            let item_id = if item.id.is_empty() { id(&format!("{}-{}", vault.name, items.len())) } else { id(&item.id) };
            members.push(json!({ "item": item_id }));
            let o = &item.overview;
            items.push(json!({
                "id": item_id,
                "creationAt": o.created_at,
                "modifiedAt": o.updated_at,
                "title": o.title,
                "subtitle": o.subtitle,
                "favorite": o.favorite,
                "scope": { "urls": o.urls.iter().map(|u| u.href.clone()).collect::<Vec<_>>(), "androidApps": [] },
                "credentials": credentials(o.category, &item.details),
                "tags": o.tags,
            }));
        }
        collections.push(json!({ "id": id(&format!("vault-{}", collections.len())), "title": vault.name, "items": members }));
    }
    let document = json!({
        "version": { "major": 1, "minor": 0 },
        "exporterRpId": "keyless.diegoalves.dev",
        "exporterDisplayName": "Keyless",
        "timestamp": data.exported_at,
        "accounts": [{
            "id": id(email),
            "username": "",
            "email": email,
            "items": items,
            "collections": collections,
        }],
    });
    serde_json::to_vec_pretty(&document).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{BackupItem, BackupVault};

    fn sample() -> BackupData {
        let mut login = ItemDetails::default();
        login.fields.push(field("username", FieldKind::Text, "me".into(), Some(FieldPurpose::Username)));
        login.fields.push(field("password", FieldKind::Concealed, "pw".into(), Some(FieldPurpose::Password)));
        login.fields.push(field("one-time password", FieldKind::Totp, "otpauth://totp/Mail:me?secret=JBSWY3DPEHPK3PXP&issuer=Mail".into(), None));
        login.notes = "remember".into();
        login.sections.push(Section { id: "s".into(), title: "Extra".into(), fields: vec![field("PIN", FieldKind::Pin, "1234".into(), None)] });
        let mut card = ItemDetails::default();
        card.fields.push(field("cardholder name", FieldKind::Text, "Ana".into(), None));
        card.fields.push(field("number", FieldKind::CardNumber, "4111111111111111".into(), None));
        card.fields.push(field("expiry date", FieldKind::MonthYear, "07/2029".into(), None));
        let address = Address { street: "Rua A, 10".into(), city: "Recife".into(), zip: "50000-000".into(), country: "BR".into(), ..Default::default() };
        let mut me = ItemDetails::default();
        me.fields.push(Field { id: new_field_id(), label: "address".into(), kind: FieldKind::Address, value: address.formatted(), purpose: None, extra: FieldExtra { address: Some(address), ..Default::default() } });
        BackupData {
            exported_at: 1_700_000_000,
            vaults: vec![BackupVault {
                name: "Personal".into(),
                description: String::new(),
                items: vec![
                    BackupItem {
                        id: "i1".into(),
                        overview: ItemOverview { title: "Mail".into(), category: Category::Login, urls: vec![ItemUrl { href: "https://mail.example".into(), ..Default::default() }], favorite: true, ..Default::default() },
                        details: login,
                    },
                    BackupItem { id: "i2".into(), overview: ItemOverview { title: "Visa".into(), category: Category::CreditCard, ..Default::default() }, details: card },
                    BackupItem { id: "i3".into(), overview: ItemOverview { title: "Me".into(), category: Category::Identity, ..Default::default() }, details: me },
                ],
            }],
        }
    }

    #[test]
    fn round_trips_through_cxf() {
        let bytes = to_cxf(&sample(), "me@example.com").unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(detect(&json));
        let mail_credentials = &json["accounts"][0]["items"][0]["credentials"];
        let types: Vec<&str> = mail_credentials.as_array().unwrap().iter().map(|c| c["type"].as_str().unwrap()).collect();
        assert_eq!(types, vec!["basic-auth", "totp", "note", "custom-fields"]);
        assert_eq!(mail_credentials[1]["secret"], "JBSWY3DPEHPK3PXP");
        assert_eq!(mail_credentials[1]["issuer"], "Mail");

        let result = parse_cxf(&json).unwrap();
        let items = &result.vaults[0].items;
        assert_eq!(result.vaults[0].name, "me@example.com");
        let mail = &items[0];
        assert_eq!(mail.overview.category, Category::Login);
        assert_eq!(mail.overview.tags, vec!["Personal"]);
        assert!(mail.overview.favorite);
        assert_eq!(mail.details.password(), Some("pw"));
        assert_eq!(mail.details.notes, "remember");
        let totp = mail.details.fields.iter().find(|f| f.kind == FieldKind::Totp).unwrap();
        assert!(totp.value.starts_with("otpauth://totp/Mail:me?secret=JBSWY3DPEHPK3PXP"));
        crate::totp::Totp::parse(&totp.value).unwrap();
        assert_eq!(mail.details.sections[0].fields[0].value, "1234");
        let visa = &items[1];
        assert_eq!(visa.overview.category, Category::CreditCard);
        assert!(visa.details.fields.iter().any(|f| f.kind == FieldKind::MonthYear && f.value == "07/2029"));
        let me = &items[2];
        assert_eq!(me.overview.category, Category::Identity);
        assert_eq!(me.details.fields[0].extra.address.as_ref().unwrap().city, "Recife");
    }

    #[test]
    fn refuses_other_versions() {
        assert!(parse_cxf(&json!({"version": {"major": 2, "minor": 0}, "accounts": []})).is_err());
    }

    #[test]
    fn imports_passkeys() {
        let document = json!({"version": {"major": 1, "minor": 0}, "accounts": [{"id": "a", "items": [{"id": "i", "title": "Example",
            "scope": {"urls": ["https://example.com"]},
            "credentials": [{"type": "passkey", "credentialId": "Y3JlZA", "rpId": "example.com", "username": "me", "userDisplayName": "Me", "userHandle": "dQ", "key": "a2V5"}]}]}]});
        let result = parse_cxf(&document).unwrap();
        let item = &result.vaults[0].items[0];
        assert_eq!(item.overview.category, Category::Login);
        assert_eq!(item.details.passkeys.len(), 1);
        assert_eq!(item.details.passkeys[0].rp_id, "example.com");
    }
}
