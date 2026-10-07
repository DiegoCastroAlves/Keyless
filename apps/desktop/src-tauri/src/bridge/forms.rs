//! Credit cards and identities, for filling payment and address forms.
//!
//! Field labels are free text (they come from templates and imports, in
//! English mostly but also Portuguese and Spanish), so fields are found by
//! kind and by words in their label.

use keyless_core::item::{Category, Field, FieldKind, ItemDetails};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};

use crate::{items, state::AppState};

fn label_has(field: &Field, words: &[&str]) -> bool {
    let label = field.label.to_lowercase();
    words.iter().any(|word| label.contains(word))
}

fn find(details: &ItemDetails, test: impl Fn(&Field) -> bool) -> Option<&str> {
    details.all_fields().find(|f| !f.value.trim().is_empty() && test(f)).map(|f| f.value.trim())
}

// ----- cards ----------------------------------------------------------------------

const HOLDER: &[&str] = &["holder", "name", "titular", "nome", "nombre"];
const NUMBER: &[&str] = &["number", "número", "numero"];
const EXPIRY: &[&str] = &["expir", "valid", "validade", "vencim", "venc"];
const CODE: &[&str] = &["verification", "cvv", "cvc", "csc", "security", "segurança", "seguridad"];
const BRAND: &[&str] = &["type", "tipo", "brand", "bandeira", "marca"];

fn card_number(details: &ItemDetails) -> Option<String> {
    let raw = find(details, |f| f.kind == FieldKind::CardNumber).or_else(|| find(details, |f| label_has(f, NUMBER)))?;
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    (12..=19).contains(&digits.len()).then_some(digits)
}

/// "MM/YYYY", "MM/YY", "YYYY-MM" or "MMYY" -> (month, four-digit year).
pub(crate) fn parse_expiry(text: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = text.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).collect();
    let (month, year) = match parts.as_slice() {
        [a, b] if a.len() == 4 => (b.parse().ok()?, a.parse().ok()?),
        [a, b] => (a.parse().ok()?, b.parse().ok()?),
        [ab] if ab.len() == 4 => (ab[..2].parse().ok()?, ab[2..].parse().ok()?),
        [ab] if ab.len() == 6 => (ab[..2].parse().ok()?, ab[2..].parse().ok()?),
        _ => return None,
    };
    let year: u32 = if year < 100 { 2000 + year } else { year };
    ((1..=12).contains(&month) && (2000..=2100).contains(&year)).then_some((month, year))
}

fn brand(number: &str) -> &'static str {
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| number.starts_with(p));
    if number.starts_with('4') {
        "visa"
    } else if starts(&["51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27"]) {
        "mastercard"
    } else if starts(&["34", "37"]) {
        "amex"
    } else if starts(&["4011", "4312", "4389", "4514", "4576", "5041", "5066", "5067", "509", "6277", "6362", "6363", "650", "6516", "6550"]) {
        "elo"
    } else if starts(&["6011", "65", "644", "645", "646", "647", "648", "649"]) {
        "discover"
    } else if starts(&["606282", "3841"]) {
        "hipercard"
    } else {
        ""
    }
}

fn card(details: &ItemDetails) -> Option<Value> {
    let number = card_number(details)?;
    let holder = find(details, |f| f.kind == FieldKind::Text && label_has(f, HOLDER)).unwrap_or("");
    let expiry = find(details, |f| f.kind == FieldKind::MonthYear)
        .or_else(|| find(details, |f| label_has(f, EXPIRY)))
        .and_then(parse_expiry);
    let code = find(details, |f| label_has(f, CODE) && !label_has(f, &["pin"])).unwrap_or("");
    let kind = find(details, |f| label_has(f, BRAND)).map(str::to_lowercase).unwrap_or_else(|| brand(&number).to_string());
    Some(json!({
        "holder": holder,
        "number": number,
        "expMonth": expiry.map(|(m, _)| m),
        "expYear": expiry.map(|(_, y)| y),
        "code": code,
        "brand": kind,
    }))
}

// ----- identities -------------------------------------------------------------------

/// Address parts; imported addresses are one field with a line per part.
#[derive(Default)]
struct Address {
    street: String,
    line2: String,
    city: String,
    state: String,
    zip: String,
    country: String,
}

fn looks_like_zip(line: &str) -> bool {
    let line = line.trim();
    (3..=10).contains(&line.len()) && line.chars().any(|c| c.is_ascii_digit()) && line.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ')
}

fn address(details: &ItemDetails) -> Address {
    let field = |words: &[&str]| find(details, |f| label_has(f, words) && !matches!(f.kind, FieldKind::Multiline | FieldKind::Email)).unwrap_or("").to_string();
    let mut parts = Address {
        street: field(&["street", "address", "rua", "logradouro", "endereço", "calle", "dirección"]),
        line2: field(&["line 2", "complemento", "apartment", "apto"]),
        city: field(&["city", "cidade", "ciudad", "town"]),
        state: field(&["state", "estado", "province", "provincia", "region", "uf"]),
        zip: field(&["zip", "postal", "cep", "código postal"]),
        country: field(&["country", "país", "pais"]),
    };
    // One multiline field: street, city, state, zip, country (as imported).
    if parts.street.is_empty()
        && let Some(text) = find(details, |f| f.kind == FieldKind::Multiline && label_has(f, &["address", "endereço", "dirección"]))
    {
        let mut lines: Vec<String> = text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        if let Some(zip) = lines.iter().position(|l| looks_like_zip(l)) {
            parts.zip = lines.remove(zip);
            if zip < lines.len() {
                parts.country = lines.split_off(zip).join(", ");
            }
        }
        let mut lines = lines.into_iter();
        parts.street = lines.next().unwrap_or_default();
        parts.city = lines.next().unwrap_or_default();
        parts.state = lines.collect::<Vec<_>>().join(", ");
    }
    parts
}

fn identity(details: &ItemDetails) -> Value {
    let text = |words: &[&str]| find(details, |f| label_has(f, words)).unwrap_or("").to_string();
    let first = text(&["first name", "given name", "primeiro nome", "nome", "nombre"]);
    let last = text(&["last name", "surname", "family name", "sobrenome", "apellido"]);
    let (first, last) = if last.is_empty() || first.ends_with(&last) {
        let full = first.clone();
        let mut words = full.split_whitespace();
        let first_word = words.next().unwrap_or("").to_string();
        let rest: Vec<&str> = words.collect();
        if last.is_empty() && !rest.is_empty() { (first_word, rest.join(" ")) } else { (first, last) }
    } else {
        (first, last)
    };
    let address = address(details);
    json!({
        "firstName": first,
        "lastName": last,
        "name": format!("{first} {last}").trim(),
        "email": find(details, |f| f.kind == FieldKind::Email).map(str::to_string).unwrap_or_else(|| text(&["email", "e-mail", "correo"])),
        "phone": find(details, |f| f.kind == FieldKind::Phone).map(str::to_string).unwrap_or_else(|| text(&["phone", "telefone", "teléfono", "celular", "mobile"])),
        "company": text(&["company", "empresa", "organization", "organização"]),
        "birthDate": find(details, |f| f.kind == FieldKind::Date && label_has(f, &["birth", "nascimento", "nacimiento"])).unwrap_or(""),
        "street": address.street,
        "line2": address.line2,
        "city": address.city,
        "state": address.state,
        "zip": address.zip,
        "country": address.country,
    })
}

// ----- commands ---------------------------------------------------------------------

/// Cards and identities to choose from: no card number, only its end.
pub async fn list(app: &AppHandle) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let mut cards = Vec::new();
    let mut identities = Vec::new();
    for (id, item) in &session.items {
        let o = &item.overview;
        if o.trashed_at.is_some() || o.archived || !matches!(o.category, Category::CreditCard | Category::Identity) {
            continue;
        }
        let Ok((_, details)) = items::load_details(&state, session, id) else { continue };
        if o.category == Category::CreditCard {
            if let Some(card) = card(&details) {
                let number = card["number"].as_str().unwrap_or("");
                cards.push(json!({ "id": id, "title": o.title, "holder": card["holder"], "last4": &number[number.len().saturating_sub(4)..], "brand": card["brand"] }));
            }
        } else {
            let person = identity(&details);
            identities.push(json!({ "id": id, "title": o.title, "name": person["name"], "email": person["email"], "city": person["city"] }));
        }
    }
    let by_title = |a: &Value, b: &Value| a["title"].as_str().unwrap_or("").to_lowercase().cmp(&b["title"].as_str().unwrap_or("").to_lowercase());
    cards.sort_by(by_title);
    identities.sort_by(by_title);
    Ok(json!({ "cards": cards, "identities": identities }))
}

/// One card or identity, chosen by the user, to fill.
pub async fn details(app: &AppHandle, id: &str) -> Result<Value, &'static str> {
    let state = app.state::<AppState>();
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or("locked")?;
    let item = session.items.get(id).ok_or("not_found")?;
    let (_, details) = items::load_details(&state, session, id).map_err(|_| "not_found")?;
    let data = match item.overview.category {
        Category::CreditCard => json!({ "kind": "card", "card": card(&details).ok_or("not_found")? }),
        Category::Identity => json!({ "kind": "identity", "identity": identity(&details) }),
        _ => return Err("not_found"),
    };
    crate::commands::record_use(&state, id);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyless_core::item::{FieldPurpose, new_field_id};

    fn details(fields: &[(&str, FieldKind, &str)]) -> ItemDetails {
        let mut details = ItemDetails::default();
        details.fields = fields
            .iter()
            .map(|(label, kind, value)| Field { id: new_field_id(), label: (*label).into(), kind: *kind, value: (*value).into(), purpose: None::<FieldPurpose> })
            .collect();
        details
    }

    #[test]
    fn reads_cards() {
        let card = card(&details(&[
            ("cardholder name", FieldKind::Text, "DIEGO C ALVES"),
            ("number", FieldKind::CardNumber, "4111 1111 1111 1111"),
            ("expiry date", FieldKind::MonthYear, "07/2029"),
            ("verification number", FieldKind::Pin, "123"),
            ("PIN", FieldKind::Pin, "9999"),
        ]))
        .unwrap();
        assert_eq!(card["number"], "4111111111111111");
        assert_eq!(card["holder"], "DIEGO C ALVES");
        assert_eq!((card["expMonth"].as_u64(), card["expYear"].as_u64()), (Some(7), Some(2029)));
        assert_eq!(card["code"], "123");
        assert_eq!(card["brand"], "visa");
    }

    #[test]
    fn expiry_formats() {
        assert_eq!(parse_expiry("07/2029"), Some((7, 2029)));
        assert_eq!(parse_expiry("7/29"), Some((7, 2029)));
        assert_eq!(parse_expiry("2029-07"), Some((7, 2029)));
        assert_eq!(parse_expiry("0729"), Some((7, 2029)));
        assert_eq!(parse_expiry("13/29"), None);
    }

    #[test]
    fn reads_identities_and_imported_addresses() {
        let person = identity(&details(&[
            ("first name", FieldKind::Text, "Diego"),
            ("last name", FieldKind::Text, "Castro Alves"),
            ("email", FieldKind::Email, "diego@example.com"),
            ("phone", FieldKind::Phone, "+55 11 99999-0000"),
            ("address", FieldKind::Multiline, "Rua das Flores, 123\nSão Paulo\nSP\n01234-567\nBrasil"),
        ]));
        assert_eq!(person["name"], "Diego Castro Alves");
        assert_eq!(person["street"], "Rua das Flores, 123");
        assert_eq!(person["city"], "São Paulo");
        assert_eq!(person["state"], "SP");
        assert_eq!(person["zip"], "01234-567");
        assert_eq!(person["country"], "Brasil");

        let split = identity(&details(&[("first name", FieldKind::Text, "Ana Maria Souza"), ("city", FieldKind::Text, "Recife")]));
        assert_eq!((split["firstName"].as_str(), split["lastName"].as_str()), (Some("Ana"), Some("Maria Souza")));
        assert_eq!(split["city"], "Recife");
    }
}
