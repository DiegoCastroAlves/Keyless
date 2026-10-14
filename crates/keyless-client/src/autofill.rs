//! Credit cards and identities for Android's autofill.
//!
//! First, what each field of a form asks for: from the hints apps give
//! (`View.AUTOFILL_HINT_*` and androidx's), the HTML of web pages (the
//! `autocomplete` attribute and the types Chrome predicts), then the
//! field's id, name, placeholder and label, in English, Portuguese and
//! Spanish. A form must ask for two such things (or mark one explicitly)
//! before cards or identities are offered in it.
//!
//! Then the user's cards and identities with the value for each field,
//! formatted for it: an expiry as "MM/YY", "MM/YYYY" or a date, a month or
//! a year picked from a list, and so on. Item fields are found by kind and
//! by words in their label, which are English keys ("cardholder name",
//! "expiry date"...) or the label as typed in another language.

use std::collections::{BTreeMap, BTreeSet};

use keyless_core::item::{Category, Field, FieldKind, ItemDetails, ItemOverview};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Client, Outcome, args};

/// What a form field asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Part {
    CardNumber,
    CardHolder,
    CardExpiry,
    CardExpMonth,
    CardExpYear,
    CardCode,
    Name,
    FirstName,
    LastName,
    Email,
    Phone,
    Street,
    Line2,
    City,
    State,
    Zip,
    Country,
    Company,
}

use Part::*;

impl Part {
    fn name(self) -> &'static str {
        match self {
            CardNumber => "cardNumber",
            CardHolder => "cardHolder",
            CardExpiry => "cardExpiry",
            CardExpMonth => "cardExpMonth",
            CardExpYear => "cardExpYear",
            CardCode => "cardCode",
            Name => "name",
            FirstName => "firstName",
            LastName => "lastName",
            Email => "email",
            Phone => "phone",
            Street => "street",
            Line2 => "line2",
            City => "city",
            State => "state",
            Zip => "zip",
            Country => "country",
            Company => "company",
        }
    }

    fn is_card(self) -> bool {
        matches!(self, CardNumber | CardHolder | CardExpiry | CardExpMonth | CardExpYear | CardCode)
    }
}

/// A field as the host sees it.
#[derive(Deserialize, Default, Debug)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct FormField {
    /// The app's autofill hints.
    hints: Vec<String>,
    /// A web page's field: its tag ("input", "select") and attributes.
    html_tag: String,
    html: BTreeMap<String, String>,
    /// The view's resource id ("card_number").
    id_entry: String,
    /// Its hint (placeholder) text.
    hint: String,
    /// Text next to it, or its content description.
    label: String,
    /// Android's input type (`InputType`).
    input_type: u32,
    /// "text", "list" or "date" (`View.AUTOFILL_TYPE_*`).
    autofill_type: String,
    /// A list's choices.
    options: Vec<String>,
    max_length: Option<u32>,
}

impl FormField {
    fn attr(&self, name: &str) -> &str {
        self.html.get(name).map(String::as_str).unwrap_or("")
    }

    /// A limit that says something about the format (EditText has 5000 by default).
    fn max_length(&self) -> Option<u32> {
        self.max_length.or_else(|| self.attr("maxlength").trim().parse().ok()).filter(|n| (1..=64).contains(n))
    }

    /// Text that may say how a value is written ("MM/YY").
    fn format_hint(&self) -> String {
        [self.hint.as_str(), self.attr("placeholder"), self.attr("name"), self.attr("id"), self.id_entry.as_str(), self.label.as_str()].join(" ").to_lowercase()
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Form {
    fields: Vec<FormField>,
}

// ----- words --------------------------------------------------------------------------

fn fold(c: char) -> char {
    match c {
        'á' | 'à' | 'â' | 'ã' | 'ä' => 'a',
        'é' | 'è' | 'ê' | 'ë' => 'e',
        'í' | 'ì' | 'î' | 'ï' => 'i',
        'ó' | 'ò' | 'ô' | 'õ' | 'ö' => 'o',
        'ú' | 'ù' | 'û' | 'ü' => 'u',
        'ç' => 'c',
        'ñ' => 'n',
        c => c,
    }
}

/// Text as lowercase words without accents, split at punctuation and at
/// camelCase: "cardNumber" and "card-number" are both ["card", "number"].
struct Words {
    words: Vec<String>,
    compact: String,
}

impl Words {
    fn new(text: &str) -> Self {
        let mut words = Vec::new();
        let mut current = String::new();
        let mut previous_lower = false;
        for c in text.chars() {
            if c.is_alphanumeric() {
                if c.is_uppercase() && previous_lower && !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
                previous_lower = c.is_lowercase() || c.is_ascii_digit();
                current.extend(c.to_lowercase().map(fold));
            } else {
                previous_lower = false;
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
        }
        if !current.is_empty() {
            words.push(current);
        }
        let compact = words.concat();
        Self { words, compact }
    }

    fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// One of the words is one of these.
    fn word(&self, any: &[&str]) -> bool {
        self.words.iter().any(|w| any.contains(&w.as_str()))
    }

    /// One of the words starts with one of these.
    fn prefix(&self, any: &[&str]) -> bool {
        self.words.iter().any(|w| any.iter().any(|p| w.starts_with(p)))
    }

    /// The words, run together, contain one of these.
    fn has(&self, any: &[&str]) -> bool {
        any.iter().any(|s| self.compact.contains(s))
    }
}

// ----- what a field asks for ---------------------------------------------------------------

/// Hints apps and pages give, without dashes or underscores: Android's,
/// androidx's, HTML's `autocomplete` and Chrome's predicted types. `None`
/// marks a login's field (not a card's or an identity's).
const EXPLICIT: &[(&str, Option<Part>)] = &[
    ("creditcardnumber", Some(CardNumber)),
    ("creditcardsecuritycode", Some(CardCode)),
    ("creditcardexpirationdate", Some(CardExpiry)),
    ("creditcardexpirationmonth", Some(CardExpMonth)),
    ("creditcardexpirationyear", Some(CardExpYear)),
    ("name", Some(Name)),
    ("personname", Some(Name)),
    ("persongivenname", Some(FirstName)),
    ("personfamilyname", Some(LastName)),
    ("emailaddress", Some(Email)),
    ("email", Some(Email)),
    ("phone", Some(Phone)),
    ("phonenumber", Some(Phone)),
    ("phonenational", Some(Phone)),
    ("postaladdress", Some(Street)),
    ("streetaddress", Some(Street)),
    ("extendedaddress", Some(Line2)),
    ("aptnumber", Some(Line2)),
    ("postalcode", Some(Zip)),
    ("addresscountry", Some(Country)),
    ("addressregion", Some(State)),
    ("addresslocality", Some(City)),
    ("ccnumber", Some(CardNumber)),
    ("ccname", Some(CardHolder)),
    ("cccsc", Some(CardCode)),
    ("ccexp", Some(CardExpiry)),
    ("ccexpmonth", Some(CardExpMonth)),
    ("ccexpyear", Some(CardExpYear)),
    ("givenname", Some(FirstName)),
    ("familyname", Some(LastName)),
    ("tel", Some(Phone)),
    ("telnational", Some(Phone)),
    ("addressline1", Some(Street)),
    ("addressline2", Some(Line2)),
    ("addresslevel2", Some(City)),
    ("addresslevel1", Some(State)),
    ("country", Some(Country)),
    ("countryname", Some(Country)),
    ("organization", Some(Company)),
    ("creditcardnamefull", Some(CardHolder)),
    ("creditcardexpmonth", Some(CardExpMonth)),
    ("creditcardexp2digityear", Some(CardExpYear)),
    ("creditcardexp4digityear", Some(CardExpYear)),
    ("creditcardexpdate2digityear", Some(CardExpiry)),
    ("creditcardexpdate4digityear", Some(CardExpiry)),
    ("creditcardverificationcode", Some(CardCode)),
    ("namefirst", Some(FirstName)),
    ("namelast", Some(LastName)),
    ("namefull", Some(Name)),
    ("phonehomewholenumber", Some(Phone)),
    ("phonehomecityandnumber", Some(Phone)),
    ("phonehomenumber", Some(Phone)),
    ("addresshomeline1", Some(Street)),
    ("addresshomeline2", Some(Line2)),
    ("addresshomestreetaddress", Some(Street)),
    ("addresshomecity", Some(City)),
    ("addresshomestate", Some(State)),
    ("addresshomezip", Some(Zip)),
    ("addresshomecountry", Some(Country)),
    ("companyname", Some(Company)),
    ("username", None),
    ("newusername", None),
    ("password", None),
    ("newpassword", None),
    ("currentpassword", None),
    ("accountcreationpassword", None),
    ("onetimecode", None),
    ("smsotpcode", None),
    ("2faappotpcode", None),
];

/// What the hints say: a part, a login's field (`Some(None)`), or nothing
/// known (`None`).
fn explicit(field: &FormField) -> Option<Option<Part>> {
    let lists = [
        field.hints.join(" "),
        field.attr("autocomplete").to_string(),
        field.attr("computed-autofill-hints").to_string(),
        field.attr("crowdsourcing-autofill-hints").to_string(),
        field.attr("ua-autofill-hints").to_string(),
    ];
    for list in lists {
        for token in list.split(|c: char| c.is_whitespace() || c == ',') {
            let key: String = token.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
            if let Some((_, part)) = EXPLICIT.iter().find(|(name, _)| *name == key) {
                return Some(*part);
            }
        }
    }
    None
}

const TYPE_CLASS_MASK: u32 = 0x0f;
const TYPE_VARIATION_MASK: u32 = 0xff0;
const TYPE_CLASS_TEXT: u32 = 1;
const TYPE_CLASS_NUMBER: u32 = 2;
const TYPE_CLASS_PHONE: u32 = 3;

/// A field for a secret (a password, a PIN): only a card's security code
/// can be one of ours.
fn concealed(field: &FormField) -> bool {
    if field.html_tag.eq_ignore_ascii_case("input") {
        return field.attr("type").eq_ignore_ascii_case("password");
    }
    let (class, variation) = (field.input_type & TYPE_CLASS_MASK, field.input_type & TYPE_VARIATION_MASK);
    (class == TYPE_CLASS_TEXT && matches!(variation, 0x80 | 0x90 | 0xe0)) || (class == TYPE_CLASS_NUMBER && variation == 0x10)
}

fn card_part(w: &Words) -> Option<Part> {
    let card = w.word(&["card", "cartao", "tarjeta", "cc", "credit", "credito", "debit", "debito"]);
    let expiry = w.word(&["exp"]) || w.prefix(&["expir", "venc", "valid", "cadu"]);
    if w.word(&["cvv", "cvc", "csc", "cvn", "cvv2", "cvc2"])
        || w.has(&["securitycode", "cardcode", "codigodeseguranca", "codigoseguranca", "codseguranca", "codseg", "codigodeseguridad", "codigoseguridad", "cardverification"])
    {
        return Some(CardCode);
    }
    if w.has(&["cardholder", "holdername", "nameoncard", "ccname", "cardname", "nomedotitular", "nometitular", "nomenocartao", "nomeimpresso", "nombredeltitular", "nombretitular", "nombreenlatarjeta"])
        || w.word(&["titular"])
        || (card && w.word(&["name", "nome", "nombre", "holder"]))
    {
        return Some(CardHolder);
    }
    // "MM/YY" asks for both: one field for the whole expiry.
    let month = w.word(&["month", "mes", "mm"]) || w.has(&["expmonth", "expirymonth", "expirationmonth", "ccmonth", "cardmonth", "mesvalidade", "mesvencimento", "mesdevencimiento"]);
    let year = w.word(&["year", "ano", "anio", "yy", "yyyy", "aa", "aaaa"]) || w.has(&["expyear", "expiryyear", "expirationyear", "ccyear", "cardyear", "anovalidade", "anovencimento", "anodevencimiento"]);
    if (expiry || card || w.has(&["expmonth", "ccmonth", "cardmonth"])) && month && !year {
        return Some(CardExpMonth);
    }
    if (expiry || card || w.has(&["expyear", "ccyear", "cardyear"])) && year && !month {
        return Some(CardExpYear);
    }
    if expiry || w.has(&["mmyy", "mmaa"]) || (card && month && year) {
        return Some(CardExpiry);
    }
    if w.has(&["cardnumber", "ccnumber", "ccnum", "cardnum", "numerocartao", "numerodocartao", "numerotarjeta", "numerodetarjeta", "numerodelatarjeta", "creditcard", "debitcard", "cardno"])
        || (card && w.word(&["number", "numero", "num", "no", "nr"]))
    {
        return Some(CardNumber);
    }
    None
}

/// Words next to "name" that make it another name than a person's.
const OTHER_NAMES: &[&str] = &[
    "user", "login", "account", "conta", "cuenta", "nick", "screen", "display", "company", "empresa", "business", "file", "arquivo", "host", "bank", "banco",
    "card", "cartao", "tarjeta", "pet", "middle", "domain", "app", "device", "wifi", "network", "rede", "server", "project", "product", "event", "group", "team",
    "store", "shop", "loja", "tienda", "street", "rua", "city", "cidade", "mother", "mae", "father", "pai",
];

fn identity_part(w: &Words) -> Option<Part> {
    if w.word(&["email", "mail", "correo"]) || w.has(&["emailaddress"]) {
        return Some(Email);
    }
    if w.has(&["addressline2", "address2", "line2", "complemento", "apartment", "apartamento"]) || w.word(&["apto", "apt", "suite"]) {
        return Some(Line2);
    }
    if w.word(&["zip", "zipcode", "postcode", "postal", "cep", "postalcode"]) || w.has(&["codigopostal", "postalcode", "zipcode"]) {
        return Some(Zip);
    }
    if w.word(&["city", "cidade", "ciudad", "town", "municipio", "localidad", "locality"]) {
        return Some(City);
    }
    if w.word(&["state", "province", "estado", "provincia", "uf", "region", "county"]) && !w.word(&["civil"]) {
        return Some(State);
    }
    if w.word(&["country", "pais"]) {
        return Some(Country);
    }
    if w.word(&["phone", "telephone", "tel", "telefone", "telefono", "celular", "mobile", "cell", "cellphone", "fone", "whatsapp"]) || w.has(&["phonenumber", "mobilenumber"]) {
        return Some(Phone);
    }
    if w.word(&["company", "empresa", "organization", "organisation", "organizacao", "organizacion"]) {
        return Some(Company);
    }
    if w.has(&["fullname", "nomecompleto", "nombrecompleto", "yourname"]) {
        return Some(Name);
    }
    if w.has(&["firstname", "givenname", "primeironome", "prenome", "forename"]) || w.word(&["fname"]) {
        return Some(FirstName);
    }
    if w.has(&["lastname", "surname", "familyname", "sobrenome", "apellido"]) || w.word(&["lname"]) {
        return Some(LastName);
    }
    if w.word(&["name", "nome", "nombre"]) && !w.word(OTHER_NAMES) {
        return Some(Name);
    }
    if w.has(&["streetaddress", "addressline1", "address1", "line1"])
        || (w.word(&["address", "street", "endereco", "logradouro", "rua", "direccion", "calle", "avenida"]) && !w.word(&["ip", "wallet", "web", "mac", "url", "bitcoin"]))
    {
        return Some(Street);
    }
    None
}

/// What one field asks for, and whether a hint said so.
fn part_of(field: &FormField) -> (Option<Part>, bool) {
    if let Some(found) = explicit(field) {
        return (found, true);
    }
    let tag = field.html_tag.to_lowercase();
    let html_type = field.attr("type").to_lowercase();
    if !tag.is_empty() {
        if !matches!(tag.as_str(), "input" | "select" | "textarea") {
            return (None, false);
        }
        if tag == "input" && !matches!(html_type.as_str(), "" | "text" | "tel" | "number" | "month" | "email" | "password") {
            return (None, false);
        }
    }
    let strong = Words::new(
        &[field.id_entry.as_str(), field.attr("name"), field.attr("id"), field.attr("placeholder"), field.attr("aria-label"), field.attr("label"), field.hint.as_str()].join(" "),
    );
    let near = Words::new(&field.label);
    if concealed(field) {
        let code = [&strong, &near].into_iter().any(|w| card_part(w) == Some(CardCode));
        return (code.then_some(CardCode), false);
    }
    for words in [&strong, &near] {
        if words.is_empty() {
            continue;
        }
        if let Some(part) = card_part(words).or_else(|| identity_part(words)) {
            return (Some(part), false);
        }
    }
    // By the kind of text it takes.
    let (class, variation) = (field.input_type & TYPE_CLASS_MASK, field.input_type & TYPE_VARIATION_MASK);
    let part = match html_type.as_str() {
        "email" => Some(Email),
        "tel" => Some(Phone),
        _ if class == TYPE_CLASS_PHONE => Some(Phone),
        _ if class == TYPE_CLASS_TEXT && matches!(variation, 0x20 | 0xd0) => Some(Email),
        _ if class == TYPE_CLASS_TEXT && variation == 0x70 => Some(Street),
        _ if class == TYPE_CLASS_TEXT && variation == 0x60 => Some(Name),
        _ => None,
    };
    (part, false)
}

/// A form's fields, with what each asks for once the form as a whole is
/// known to ask for a card or an identity.
pub(crate) struct Classified {
    parts: Vec<Option<Part>>,
    cards: bool,
    identities: bool,
}

pub(crate) fn classify(fields: &[FormField]) -> Classified {
    let found: Vec<(Option<Part>, bool)> = fields.iter().map(part_of).collect();
    let present: BTreeSet<Part> = found.iter().filter_map(|(p, _)| *p).collect();
    let card_parts = present.iter().filter(|p| p.is_card()).count();
    let explicit_card = found.iter().any(|(p, e)| *e && p.is_some_and(Part::is_card));
    let person_parts = present.iter().filter(|p| !p.is_card() && **p != Email).count();
    let explicit_person = found.iter().any(|(p, e)| *e && p.is_some_and(|p| !p.is_card() && p != Email));
    let cards = card_parts >= 2 || explicit_card;
    let identities = person_parts >= 2 || (person_parts == 1 && (present.contains(&Email) || explicit_person));
    // "Name" next to a last name is the first name.
    let first_from_name = present.contains(&LastName) && !present.contains(&FirstName);
    let parts = found
        .into_iter()
        .map(|(part, _)| match part {
            Some(p) if p.is_card() && !cards => None,
            Some(p) if !p.is_card() && !identities => None,
            Some(Name) if first_from_name => Some(FirstName),
            other => other,
        })
        .collect();
    Classified { parts, cards, identities }
}

impl Classified {
    fn to_json(&self) -> Value {
        json!({
            "parts": self.parts.iter().map(|p| p.map(Part::name)).collect::<Vec<_>>(),
            "cards": self.cards,
            "identities": self.identities,
        })
    }
}

// ----- the items' values ------------------------------------------------------------------

fn label_has(field: &Field, words: &[&str]) -> bool {
    let label = field.label.to_lowercase();
    words.iter().any(|word| label.contains(word))
}

fn find(details: &ItemDetails, test: impl Fn(&Field) -> bool) -> Option<&str> {
    details.all_fields().find(|f| !f.value.trim().is_empty() && test(f)).map(|f| f.value.trim())
}

#[derive(Default, Debug, PartialEq)]
struct Card {
    holder: String,
    number: String,
    expiry: Option<(u32, u32)>,
    code: String,
}

/// "MM/YYYY", "MM/YY", "YYYY-MM" or "MMYY" -> (month, four-digit year).
fn parse_expiry(text: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = text.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).collect();
    let (month, year): (u32, u32) = match parts.as_slice() {
        [a, b] if a.len() == 4 => (b.parse().ok()?, a.parse().ok()?),
        [a, b] => (a.parse().ok()?, b.parse().ok()?),
        [ab] if ab.len() == 4 || ab.len() == 6 => (ab[..2].parse().ok()?, ab[2..].parse().ok()?),
        _ => return None,
    };
    let year = if year < 100 { 2000 + year } else { year };
    ((1..=12).contains(&month) && (2000..=2100).contains(&year)).then_some((month, year))
}

fn card(details: &ItemDetails) -> Option<Card> {
    let raw = find(details, |f| f.kind == FieldKind::CardNumber).or_else(|| find(details, |f| label_has(f, &["number", "número", "numero"])))?;
    let number: String = raw.chars().filter(char::is_ascii_digit).collect();
    if !(12..=19).contains(&number.len()) {
        return None;
    }
    Some(Card {
        holder: find(details, |f| f.kind == FieldKind::Text && label_has(f, &["holder", "name", "titular", "nome", "nombre"])).unwrap_or("").to_string(),
        number,
        expiry: find(details, |f| f.kind == FieldKind::MonthYear)
            .or_else(|| find(details, |f| label_has(f, &["expir", "valid", "venc", "cadu"])))
            .and_then(parse_expiry),
        code: find(details, |f| label_has(f, &["verification", "cvv", "cvc", "csc", "security", "segurança", "seguranca", "seguridad"]) && !label_has(f, &["pin"]))
            .unwrap_or("")
            .to_string(),
    })
}

fn brand(number: &str) -> &'static str {
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| number.starts_with(p));
    if starts(&["4011", "4312", "4389", "4514", "4576", "5041", "5066", "5067", "509", "6277", "6362", "6363", "650", "6516", "6550"]) {
        "Elo"
    } else if number.starts_with('4') {
        "Visa"
    } else if starts(&["51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27"]) {
        "Mastercard"
    } else if starts(&["34", "37"]) {
        "Amex"
    } else if starts(&["6011", "65", "644", "645", "646", "647", "648", "649"]) {
        "Discover"
    } else if starts(&["606282", "3841"]) {
        "Hipercard"
    } else {
        ""
    }
}

#[derive(Default, Debug, PartialEq)]
struct Person {
    first: String,
    last: String,
    email: String,
    phone: String,
    company: String,
    street: String,
    line2: String,
    city: String,
    state: String,
    zip: String,
    country: String,
}

impl Person {
    fn name(&self) -> String {
        format!("{} {}", self.first, self.last).trim().to_string()
    }
}

fn looks_like_zip(line: &str) -> bool {
    let line = line.trim();
    (3..=10).contains(&line.len()) && line.chars().any(|c| c.is_ascii_digit()) && line.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ')
}

fn person(details: &ItemDetails) -> Person {
    let plain = |f: &Field| !matches!(f.kind, FieldKind::Multiline | FieldKind::Email | FieldKind::Address);
    let but = |words: &[&str], not: &[&str]| find(details, |f| plain(f) && label_has(f, words) && !label_has(f, not)).unwrap_or("").to_string();
    let text = |words: &[&str]| but(words, &[]);
    const LAST: &[&str] = &["last name", "surname", "family name", "sobrenome", "apellido"];
    let mut first = text(&["first name", "given name", "primeiro nome", "prenome"]);
    if first.is_empty() {
        first = but(&["nome", "nombre", "name"], &[LAST, &["user", "company", "empresa", "bank", "banco", "member", "account", "conta", "cuenta"]].concat());
    }
    let last = text(LAST);
    // One name field: its first word is the first name.
    let (first, last) = if last.is_empty() || first.ends_with(&last) {
        let mut words = first.split_whitespace();
        let head = words.next().unwrap_or("").to_string();
        let rest: Vec<&str> = words.collect();
        if last.is_empty() && !rest.is_empty() { (head, rest.join(" ")) } else { (first.clone(), last) }
    } else {
        (first, last)
    };
    let mut p = Person {
        first,
        last,
        email: find(details, |f| f.kind == FieldKind::Email).map(str::to_string).unwrap_or_else(|| text(&["email", "e-mail", "correo"])),
        phone: find(details, |f| f.kind == FieldKind::Phone).map(str::to_string).unwrap_or_else(|| text(&["phone", "telefone", "teléfono", "telefono", "celular", "mobile"])),
        company: text(&["company", "empresa", "organization", "organização"]),
        street: but(&["street", "address", "rua", "logradouro", "endereço", "endereco", "calle", "dirección", "direccion"], &["mail", "line 2"]),
        line2: text(&["line 2", "complemento", "apartment", "apto"]),
        city: text(&["city", "cidade", "ciudad", "town"]),
        state: but(&["state", "estado", "province", "provincia", "region", "uf"], &["civil"]),
        zip: text(&["zip", "postal", "cep", "código postal"]),
        country: text(&["country", "país", "pais"]),
    };
    // An address field with its parts.
    if let Some(parts) = details.all_fields().filter(|f| f.kind == FieldKind::Address).find_map(|f| f.extra.address.as_ref()) {
        let take = |mine: &mut String, theirs: &str| {
            if mine.is_empty() {
                *mine = theirs.trim().to_string();
            }
        };
        take(&mut p.street, &parts.street);
        take(&mut p.line2, &parts.line2);
        take(&mut p.city, &parts.city);
        take(&mut p.state, &parts.state);
        take(&mut p.zip, &parts.zip);
        take(&mut p.country, &parts.country);
    }
    // One multiline address: street, city, state, zip, country (as imported).
    if p.street.is_empty()
        && let Some(text) = find(details, |f| matches!(f.kind, FieldKind::Multiline | FieldKind::Address) && label_has(f, &["address", "endereço", "endereco", "dirección", "direccion"]))
    {
        let mut lines: Vec<String> = text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        if let Some(zip) = lines.iter().position(|l| looks_like_zip(l)) {
            let found = lines.remove(zip);
            if p.zip.is_empty() {
                p.zip = found;
            }
            if zip < lines.len() && p.country.is_empty() {
                p.country = lines.split_off(zip).join(", ");
            }
        }
        let mut lines = lines.into_iter();
        p.street = lines.next().unwrap_or_default();
        if p.city.is_empty() {
            p.city = lines.next().unwrap_or_default();
        }
        if p.state.is_empty() {
            p.state = lines.collect::<Vec<_>>().join(", ");
        }
    }
    p
}

const MONTHS: [&[&str]; 12] = [
    &["january", "janeiro", "enero", "jan", "ene"],
    &["february", "fevereiro", "febrero", "feb", "fev"],
    &["march", "marco", "marzo", "mar"],
    &["april", "abril", "apr", "abr"],
    &["may", "maio", "mayo", "mai"],
    &["june", "junho", "junio", "jun"],
    &["july", "julho", "julio", "jul"],
    &["august", "agosto", "aug", "ago"],
    &["september", "setembro", "septiembre", "sep", "set"],
    &["october", "outubro", "octubre", "oct", "out"],
    &["november", "novembro", "noviembre", "nov"],
    &["december", "dezembro", "diciembre", "dec", "dez", "dic"],
];

fn normalized(text: &str) -> String {
    text.trim().to_lowercase().chars().map(fold).collect()
}

/// The choice in a list for any of `wanted` (best first): the same text,
/// else one starting with it.
fn pick(options: &[String], wanted: &[String]) -> Option<usize> {
    let options: Vec<String> = options.iter().map(|o| normalized(o)).collect();
    let wanted: Vec<String> = wanted.iter().map(|w| normalized(w)).filter(|w| !w.is_empty()).collect();
    for w in &wanted {
        if let Some(i) = options.iter().position(|o| o == w) {
            return Some(i);
        }
    }
    for w in &wanted {
        // "07 - July" for "07", "Brasil (BR)" for "Brasil".
        if let Some(i) = options.iter().position(|o| o.starts_with(w.as_str()) && !o[w.len()..].starts_with(|c: char| c.is_ascii_digit())) {
            return Some(i);
        }
    }
    None
}

/// Days since 1970-01-01 of a date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A value for the host: text, `{"index": n}` for a list or `{"date": ms}`.
fn value_for(field: &FormField, text: String, choices: Vec<String>) -> Value {
    match field.autofill_type.as_str() {
        "list" => pick(&field.options, &if choices.is_empty() { vec![text] } else { choices }).map_or(Value::Null, |i| json!({ "index": i })),
        "date" => Value::Null,
        _ if text.is_empty() => Value::Null,
        _ => json!(text),
    }
}

fn card_value(field: &FormField, part: Part, card: &Card) -> Value {
    let hint = field.format_hint();
    let (month, year) = card.expiry.unwrap_or((0, 0));
    let short_year = format!("{:02}", year % 100);
    match part {
        CardNumber => value_for(field, card.number.clone(), Vec::new()),
        CardHolder => value_for(field, card.holder.clone(), Vec::new()),
        CardCode => value_for(field, card.code.clone(), Vec::new()),
        _ if card.expiry.is_none() => Value::Null,
        CardExpiry if field.autofill_type == "date" => json!({ "date": days_from_civil(year.into(), month.into(), 1) * 86_400_000 }),
        CardExpiry => {
            let long = hint.contains("yyyy") || hint.contains("aaaa") || field.max_length().is_some_and(|n| n >= 7);
            let text = if field.attr("type").eq_ignore_ascii_case("month") {
                format!("{year}-{month:02}")
            } else if field.max_length() == Some(4) {
                format!("{month:02}{short_year}")
            } else if long {
                format!("{month:02}/{year}")
            } else {
                format!("{month:02}/{short_year}")
            };
            value_for(field, text, Vec::new())
        }
        CardExpMonth => {
            let mut choices = vec![format!("{month:02}"), month.to_string()];
            choices.extend(MONTHS[month as usize - 1].iter().map(|m| m.to_string()));
            value_for(field, format!("{month:02}"), choices)
        }
        CardExpYear => {
            let short = field.max_length() == Some(2) || ((hint.contains("yy") || hint.contains("aa")) && !hint.contains("yyyy") && !hint.contains("aaaa"));
            let text = if short { short_year.clone() } else { year.to_string() };
            value_for(field, text, vec![year.to_string(), short_year])
        }
        _ => Value::Null,
    }
}

fn person_value(field: &FormField, part: Part, p: &Person) -> Value {
    let text = match part {
        Name => p.name(),
        FirstName => p.first.clone(),
        LastName => p.last.clone(),
        Email => p.email.clone(),
        Phone => p.phone.clone(),
        Street => p.street.clone(),
        Line2 => p.line2.clone(),
        City => p.city.clone(),
        State => p.state.clone(),
        Zip => p.zip.clone(),
        Country => p.country.clone(),
        Company => p.company.clone(),
        _ => String::new(),
    };
    value_for(field, text, Vec::new())
}

/// One card or identity for a form: its values, aligned with the fields.
fn entry(id: &str, overview: &ItemOverview, details: &ItemDetails, fields: &[FormField], form: &Classified) -> Option<Value> {
    let (values, subtitle): (Vec<Value>, String) = match overview.category {
        Category::CreditCard if form.cards => {
            let card = card(details)?;
            let values = form.parts.iter().zip(fields).map(|(part, field)| part.filter(|p| p.is_card()).map_or(Value::Null, |p| card_value(field, p, &card))).collect();
            let last4 = &card.number[card.number.len() - 4..];
            (values, format!("{} •••• {last4}", brand(&card.number)).trim().to_string())
        }
        Category::Identity if form.identities => {
            let person = person(details);
            let values = form.parts.iter().zip(fields).map(|(part, field)| part.filter(|p| !p.is_card()).map_or(Value::Null, |p| person_value(field, p, &person))).collect();
            let subtitle = [person.name(), person.email.clone(), person.city.clone()].into_iter().find(|s| !s.is_empty()).unwrap_or_default();
            (values, subtitle)
        }
        _ => return None,
    };
    if values.iter().all(Value::is_null) {
        return None;
    }
    let category = if overview.category == Category::CreditCard { "credit_card" } else { "identity" };
    Some(json!({ "id": id, "category": category, "title": overview.title, "subtitle": subtitle, "favorite": overview.favorite, "values": values }))
}

impl Client {
    /// What a form's fields ask for (works while locked): `{"parts":
    /// [part | null], "cards": bool, "identities": bool}`.
    pub(crate) fn autofill_fields(&self, json: &str) -> Outcome<Value> {
        let form: Form = args(json)?;
        Ok(classify(&form.fields).to_json())
    }

    /// The same, with the cards and identities that fit the form and their
    /// value for each field: `{..., "items": [{"id", "category", "title",
    /// "subtitle", "values": [text | {"index"} | {"date"} | null]}]}`,
    /// favorites first, then by title.
    pub(crate) fn autofill_items(&self, json: &str) -> Outcome<Value> {
        let form: Form = args(json)?;
        let classified = classify(&form.fields);
        let unlocked = self.unlocked()?;
        let mut items = Vec::new();
        if classified.cards || classified.identities {
            for (id, row) in &self.store.items {
                if row.deleted {
                    continue;
                }
                let (Some(vault), Some(enc)) = (unlocked.vaults.get(&row.vault_id), row.enc_overview.as_deref()) else { continue };
                let Ok(overview) = vault.key.open_overview(&row.vault_id, id, enc) else { continue };
                if overview.trashed_at.is_some() || overview.archived || !matches!(overview.category, Category::CreditCard | Category::Identity) {
                    continue;
                }
                let Ok((_, overview, details)) = self.open_item(id) else { continue };
                if let Some(found) = entry(id, &overview, &details, &form.fields, &classified) {
                    items.push(found);
                }
            }
        }
        items.sort_by(|a, b| {
            b["favorite"].as_bool().cmp(&a["favorite"].as_bool()).then_with(|| a["title"].as_str().unwrap_or("").to_lowercase().cmp(&b["title"].as_str().unwrap_or("").to_lowercase()))
        });
        let mut answer = classified.to_json();
        answer["items"] = Value::Array(items);
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use keyless_core::{
        account::create_account,
        item::{Address, FieldExtra, new_field_id, stamp_version},
        keys::{KdfParams, SecretKey, derive_account_keys},
        vault::{VaultKey, VaultMeta},
    };

    use super::*;

    fn field(value: Value) -> FormField {
        serde_json::from_value(value).unwrap()
    }

    fn parts(fields: Vec<Value>) -> Vec<Option<&'static str>> {
        let fields: Vec<FormField> = fields.into_iter().map(field).collect();
        classify(&fields).parts.into_iter().map(|p| p.map(Part::name)).collect()
    }

    #[test]
    fn reads_android_hints() {
        let form = parts(vec![
            json!({ "hints": ["creditCardNumber"] }),
            json!({ "hints": ["creditCardExpirationDate"] }),
            json!({ "hints": ["creditCardSecurityCode"], "inputType": 0x12 }),
            json!({ "hints": ["username"] }),
        ]);
        assert_eq!(form, vec![Some("cardNumber"), Some("cardExpiry"), Some("cardCode"), None]);
        // androidx's names, and one marked field is enough.
        assert_eq!(parts(vec![json!({ "hints": ["personGivenName"] })]), vec![Some("firstName")]);
        assert_eq!(parts(vec![json!({ "hints": ["creditCardNumber"] })]), vec![Some("cardNumber")]);
    }

    #[test]
    fn reads_web_pages() {
        let input = |attrs: Value| json!({ "htmlTag": "input", "html": attrs });
        let form = parts(vec![
            input(json!({ "type": "text", "autocomplete": "billing cc-name" })),
            input(json!({ "type": "tel", "autocomplete": "cc-number" })),
            json!({ "htmlTag": "select", "html": { "autocomplete": "cc-exp-month" }, "autofillType": "list" }),
            input(json!({ "type": "text", "name": "exp_year" })),
            input(json!({ "type": "password", "name": "cvv" })),
            input(json!({ "type": "hidden", "name": "card_token" })),
            input(json!({ "type": "submit", "name": "pay" })),
        ]);
        assert_eq!(form, vec![Some("cardHolder"), Some("cardNumber"), Some("cardExpMonth"), Some("cardExpYear"), Some("cardCode"), None, None]);

        // Chrome's predicted types, and an address form's email.
        let form = parts(vec![
            input(json!({ "name": "f1", "computed-autofill-hints": "NAME_FIRST" })),
            input(json!({ "name": "f2", "crowdsourcing-autofill-hints": "NAME_LAST,UNKNOWN_TYPE" })),
            input(json!({ "type": "email", "name": "f3" })),
            input(json!({ "name": "f4", "ua-autofill-hints": "ADDRESS_HOME_ZIP" })),
        ]);
        assert_eq!(form, vec![Some("firstName"), Some("lastName"), Some("email"), Some("zip")]);
    }

    #[test]
    fn reads_names_in_three_languages() {
        let id = |name: &str| json!({ "idEntry": name, "inputType": 1 });
        let hint = |text: &str| json!({ "hint": text, "inputType": 1 });
        assert_eq!(
            parts(vec![id("etCardNumber"), id("card_expiry"), id("cvc"), id("cardHolderName")]),
            vec![Some("cardNumber"), Some("cardExpiry"), Some("cardCode"), Some("cardHolder")]
        );
        assert_eq!(
            parts(vec![hint("Número do cartão"), hint("Validade (MM/AA)"), hint("Código de segurança"), hint("Nome impresso no cartão")]),
            vec![Some("cardNumber"), Some("cardExpiry"), Some("cardCode"), Some("cardHolder")]
        );
        assert_eq!(
            parts(vec![hint("Número de tarjeta"), hint("Mes de vencimiento"), hint("Año de vencimiento"), hint("CVV")]),
            vec![Some("cardNumber"), Some("cardExpMonth"), Some("cardExpYear"), Some("cardCode")]
        );
        assert_eq!(
            parts(vec![hint("Nome"), hint("Sobrenome"), hint("E-mail"), hint("Telefone"), hint("Endereço"), hint("Complemento"), hint("Cidade"), hint("Estado"), hint("CEP"), hint("País")]),
            vec![Some("firstName"), Some("lastName"), Some("email"), Some("phone"), Some("street"), Some("line2"), Some("city"), Some("state"), Some("zip"), Some("country")]
        );
        assert_eq!(
            parts(vec![hint("Nombre completo"), hint("Correo electrónico"), hint("Dirección"), hint("Ciudad"), hint("Código postal")]),
            vec![Some("name"), Some("email"), Some("street"), Some("city"), Some("zip")]
        );
        // A label next to the field counts when the field says nothing.
        assert_eq!(parts(vec![json!({ "label": "City", "inputType": 1 }), json!({ "label": "ZIP code", "inputType": 2 })]), vec![Some("city"), Some("zip")]);
    }

    #[test]
    fn leaves_logins_and_lone_fields_alone() {
        // A sign-in form: no identity in its email field, no card.
        assert_eq!(parts(vec![json!({ "hints": ["emailAddress"] }), json!({ "hints": ["password"] })]), vec![None, None]);
        assert_eq!(parts(vec![json!({ "idEntry": "username" }), json!({ "idEntry": "password", "inputType": 0x81 })]), vec![None, None]);
        // One field named like a card's or an address's is not a form.
        assert_eq!(parts(vec![json!({ "idEntry": "cvv" })]), vec![None]);
        assert_eq!(parts(vec![json!({ "idEntry": "city" })]), vec![None]);
        // Names that are not a person's.
        assert_eq!(parts(vec![json!({ "idEntry": "user_name" }), json!({ "idEntry": "company_name" }), json!({ "hint": "Estado civil" })]), vec![None, None, None]);
        assert_eq!(parts(vec![json!({ "idEntry": "user_name" }), json!({ "hint": "Company" }), json!({ "hint": "Phone" })]), vec![None, Some("company"), Some("phone")]);
        // A password field is never an address's, and a login's is not a card's.
        assert_eq!(parts(vec![json!({ "idEntry": "street", "inputType": 0x81 }), json!({ "idEntry": "city" })]), vec![None, None]);
        // "Email address" is an email.
        assert_eq!(parts(vec![json!({ "hint": "Email address" }), json!({ "hint": "Full name" })]), vec![Some("email"), Some("name")]);
    }

    #[test]
    fn writes_values_for_each_field() {
        let card = Card { holder: "ANA SOUZA".into(), number: "4111111111111111".into(), expiry: Some((7, 2029)), code: "123".into() };
        let at = |value: Value, part| card_value(&field(value), part, &card);
        assert_eq!(at(json!({}), CardNumber), "4111111111111111");
        assert_eq!(at(json!({}), CardExpiry), "07/29");
        assert_eq!(at(json!({ "hint": "MM/YYYY" }), CardExpiry), "07/2029");
        // EditText's default limit says nothing.
        assert_eq!(at(json!({ "hints": ["creditCardExpirationDate"], "hint": "Expiry (MM/YY)", "inputType": 1, "maxLength": 5000 }), CardExpiry), "07/29");
        assert_eq!(at(json!({ "maxLength": 4 }), CardExpiry), "0729");
        assert_eq!(at(json!({ "htmlTag": "input", "html": { "type": "month" } }), CardExpiry), "2029-07");
        assert_eq!(at(json!({ "autofillType": "date" }), CardExpiry), json!({ "date": 1_877_558_400_000_i64 }));
        assert_eq!(at(json!({ "maxLength": 2 }), CardExpYear), "29");
        assert_eq!(at(json!({}), CardExpYear), "2029");
        assert_eq!(at(json!({}), CardExpMonth), "07");
        assert_eq!(at(json!({ "autofillType": "list", "options": ["Month", "1", "2", "3", "4", "5", "6", "7", "8"] }), CardExpMonth), json!({ "index": 7 }));
        assert_eq!(at(json!({ "autofillType": "list", "options": ["Mês", "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho"] }), CardExpMonth), json!({ "index": 7 }));
        assert_eq!(at(json!({ "autofillType": "list", "options": ["2027", "2028", "2029"] }), CardExpYear), json!({ "index": 2 }));
        assert_eq!(at(json!({ "autofillType": "list", "options": ["27", "28"] }), CardExpYear), Value::Null);

        let person = Person { country: "Brasil".into(), state: "SP".into(), ..Default::default() };
        let options = json!({ "autofillType": "list", "options": ["Argentina", "Brasil (BR)", "Chile"] });
        assert_eq!(person_value(&field(options), Country, &person), json!({ "index": 1 }));
        assert_eq!(person_value(&field(json!({})), City, &person), Value::Null);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    fn details(fields: &[(&str, FieldKind, &str)]) -> ItemDetails {
        let mut details = ItemDetails::default();
        details.fields = fields
            .iter()
            .map(|(label, kind, value)| Field { id: new_field_id(), label: (*label).into(), kind: *kind, value: (*value).into(), purpose: None, extra: Default::default() })
            .collect();
        details
    }

    #[test]
    fn reads_cards_and_identities_from_items() {
        let found = card(&details(&[
            ("cardholder name", FieldKind::Text, "ANA SOUZA"),
            ("number", FieldKind::CardNumber, "4111 1111 1111 1111"),
            ("expiry date", FieldKind::MonthYear, "07/2029"),
            ("verification number", FieldKind::Pin, "123"),
            ("PIN", FieldKind::Pin, "9999"),
        ]))
        .unwrap();
        assert_eq!(found, Card { holder: "ANA SOUZA".into(), number: "4111111111111111".into(), expiry: Some((7, 2029)), code: "123".into() });
        // Labels typed in Portuguese.
        let found = card(&details(&[("nome do titular", FieldKind::Text, "BIA"), ("número", FieldKind::Text, "5555555555554444"), ("data de validade", FieldKind::Text, "1/31"), ("código de segurança", FieldKind::Text, "999")])).unwrap();
        assert_eq!((found.holder.as_str(), found.expiry, found.code.as_str()), ("BIA", Some((1, 2031)), "999"));
        assert_eq!(card(&details(&[("number", FieldKind::CardNumber, "1234")])), None);

        let p = person(&details(&[
            ("first name", FieldKind::Text, "Ana"),
            ("last name", FieldKind::Text, "Souza"),
            ("email", FieldKind::Email, "ana@example.test"),
            ("phone", FieldKind::Phone, "+55 11 99999-0000"),
            ("address", FieldKind::Text, "Rua das Flores, 123"),
            ("city", FieldKind::Text, "São Paulo"),
            ("state", FieldKind::Text, "SP"),
            ("zip code", FieldKind::Text, "01234-567"),
            ("country", FieldKind::Text, "Brasil"),
        ]));
        assert_eq!(p.name(), "Ana Souza");
        assert_eq!((p.street.as_str(), p.city.as_str(), p.state.as_str(), p.zip.as_str(), p.country.as_str()), ("Rua das Flores, 123", "São Paulo", "SP", "01234-567", "Brasil"));
        // An imported address, in one field.
        let p = person(&details(&[("name", FieldKind::Text, "Bia Maria Lima"), ("address", FieldKind::Multiline, "Av. Paulista, 1000\nSão Paulo\nSP\n01310-100\nBrasil")]));
        assert_eq!((p.first.as_str(), p.last.as_str(), p.street.as_str(), p.zip.as_str(), p.country.as_str()), ("Bia", "Maria Lima", "Av. Paulista, 1000", "01310-100", "Brasil"));
        // An address field with its parts.
        let mut with_parts = details(&[("first name", FieldKind::Text, "Caio")]);
        with_parts.fields.push(Field {
            id: new_field_id(),
            label: "address".into(),
            kind: FieldKind::Address,
            value: "Calle 1, Madrid".into(),
            purpose: None,
            extra: FieldExtra { address: Some(Address { street: "Calle 1".into(), city: "Madrid".into(), country: "España".into(), ..Default::default() }), ..Default::default() },
        });
        let p = person(&with_parts);
        assert_eq!((p.street.as_str(), p.city.as_str(), p.country.as_str()), ("Calle 1", "Madrid", "España"));
    }

    #[test]
    fn lists_the_items_for_a_form() {
        const USER: &str = "11111111-1111-4111-8111-111111111111";
        const VAULT: &str = "22222222-2222-4222-8222-222222222222";
        let secret_key = SecretKey::generate().unwrap();
        let kdf = KdfParams::recommended();
        let keys = derive_account_keys("pw", &secret_key, &kdf).unwrap();
        let (bundle, account) = create_account(&keys.kek, kdf, USER).unwrap();
        let vault_key = VaultKey::generate().unwrap();
        let meta = VaultMeta { name: "Personal".into(), ..Default::default() };
        let membership = json!([{
            "vault_id": VAULT, "role": "owner", "enc_vault_key": vault_key.wrap(account.user_key(), VAULT).unwrap(),
            "vaults": { "owner_id": USER, "enc_meta": vault_key.seal_meta(VAULT, &meta).unwrap(), "seq": 1, "deleted_at": null, "enc_tombstone": null },
        }]);
        let mut client = Client::new();
        let call = |client: &mut Client, method: &str, args: Value| {
            let answer: Value = serde_json::from_str(&client.call(method, &args.to_string())).unwrap();
            assert!(answer.get("error").is_none(), "{answer}");
            answer["ok"].clone()
        };
        call(&mut client, "derive", json!({ "email": "me@example.com", "masterPassword": "pw", "secretKey": secret_key.to_display().as_str() }));
        call(&mut client, "signedIn", json!({ "userId": USER, "profile": bundle }));
        call(&mut client, "applyMemberships", membership);
        let item = |id: &str, title: &str, category: Category, fields: &[(&str, FieldKind, &str)], seq: i64| {
            let mut overview = ItemOverview { title: title.into(), category, ..Default::default() };
            let mut details = details(fields);
            stamp_version(&mut overview, &mut details, 1);
            json!({ "id": id, "vault_id": VAULT, "enc_overview": vault_key.seal_overview(VAULT, id, &overview).unwrap(), "enc_details": vault_key.seal_details(VAULT, id, &details).unwrap(), "revision": 1, "seq": seq, "deleted_at": null, "enc_tombstone": null })
        };
        let rows = json!([
            item("c1", "Visa", Category::CreditCard, &[("cardholder name", FieldKind::Text, "ANA"), ("number", FieldKind::CardNumber, "4111111111111111"), ("expiry date", FieldKind::MonthYear, "07/2029"), ("verification number", FieldKind::Pin, "123")], 1),
            item("i1", "Me", Category::Identity, &[("first name", FieldKind::Text, "Ana"), ("last name", FieldKind::Text, "Souza"), ("email", FieldKind::Email, "ana@example.test"), ("city", FieldKind::Text, "Recife")], 2),
            item("l1", "Login", Category::Login, &[("username", FieldKind::Text, "ana")], 3),
        ]);
        call(&mut client, "applyItems", json!({ "vaultId": VAULT, "items": rows }));

        let card_form = json!({ "fields": [{ "hints": ["creditCardNumber"] }, { "hints": ["creditCardExpirationDate"] }, { "hints": ["creditCardSecurityCode"] }, { "idEntry": "city" }] });
        let found = call(&mut client, "autofillItems", card_form.clone());
        assert_eq!(found["cards"], true);
        assert_eq!(found["identities"], false);
        assert_eq!(found["items"].as_array().unwrap().len(), 1);
        assert_eq!(found["items"][0]["subtitle"], "Visa •••• 1111");
        assert_eq!(found["items"][0]["values"], json!(["4111111111111111", "07/29", "123", null]));

        let address_form = json!({ "fields": [{ "hint": "First name" }, { "hint": "Last name" }, { "hint": "Email" }, { "hint": "City" }, { "hint": "ZIP" }] });
        let found = call(&mut client, "autofillItems", address_form.clone());
        assert_eq!(found["items"].as_array().unwrap().len(), 1);
        assert_eq!(found["items"][0]["category"], "identity");
        assert_eq!(found["items"][0]["subtitle"], "Ana Souza");
        assert_eq!(found["items"][0]["values"], json!(["Ana", "Souza", "ana@example.test", "Recife", null]));

        // Locked: what the fields are, not the items.
        call(&mut client, "lock", json!({}));
        assert_eq!(call(&mut client, "autofillFields", card_form)["parts"], json!(["cardNumber", "cardExpiry", "cardCode", null]));
        let answer: Value = serde_json::from_str(&client.call("autofillItems", &address_form.to_string())).unwrap();
        assert_eq!(answer["error"]["key"], "locked");
    }
}
